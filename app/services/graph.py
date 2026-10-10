from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.models.telemetry import TelemetryEventDB
from backend.app.models.session import InvestigationSessionDB
from backend.app.models.mitre import TechniqueMappingDB
from backend.app.models.alert import AlertDB
from backend.app.services.mitre_catalog import get_technique_from_catalog

def build_investigation_graph(
    db: Session,
    session_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    technique_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100
) -> Dict[str, Any]:
    """
    Constructs a fully interactive, evidence-backed investigation graph
    formatted for Cytoscape.js.
    Nodes: Telemetry Events, Correlated Sessions, MITRE ATT&CK Techniques, Security Alerts, Attacker IPs.
    Edges: Evidence-backed relationships:
      - Event BELONGS_TO Session
      - Event SUPPORTS_TECHNIQUE MITRE Technique
      - Session CONTAINS_TECHNIQUE MITRE Technique
      - Alert ALERTS_ON_SESSION Session / ALERTS_ON_TECHNIQUE
      - Session ORIGINATES_FROM Attacker IP
      - Chronological PRECEDES sequence within session
    Strictly avoids unsupported or fabricated connections.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: Set[str] = set()
    seen_edges: Set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, metadata: Dict[str, Any]):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "data": {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    **metadata
                }
            })

    def add_edge(edge_id: str, source: str, target: str, relationship: str, rel_type: str, evidence: str, extra: Dict[str, Any] = None):
        # Only add edge if both source and target nodes exist
        if edge_id not in seen_edges and source in seen_nodes and target in seen_nodes:
            seen_edges.add(edge_id)
            edges.append({
                "data": {
                    "id": edge_id,
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "relationship_type": rel_type,
                    "evidence": evidence,
                    **(extra or {})
                }
            })

    # 1. Query Telemetry Events with applied filters
    ev_query = db.query(TelemetryEventDB)
    if session_id:
        ev_query = ev_query.filter(TelemetryEventDB.session_id == session_id.strip())
    if source_ip:
        ev_query = ev_query.filter(TelemetryEventDB.source_ip == source_ip.strip())
    if technique_id:
        ev_query = ev_query.filter(TelemetryEventDB.mitre_technique_id == technique_id.strip())
    if start_time:
        ev_query = ev_query.filter(TelemetryEventDB.timestamp >= start_time)
    if end_time:
        ev_query = ev_query.filter(TelemetryEventDB.timestamp <= end_time)

    events: List[TelemetryEventDB] = ev_query.order_by(TelemetryEventDB.timestamp.asc()).limit(limit).all()

    # Collect session IDs, IPs, and event IDs from retrieved events
    matched_session_ids = set()
    matched_ips = set()
    for e in events:
        if e.session_id:
            matched_session_ids.add(e.session_id)
        if e.source_ip:
            matched_ips.add(e.source_ip)

    if session_id:
        matched_session_ids.add(session_id.strip())
    if source_ip:
        matched_ips.add(source_ip.strip())

    # 2. Query Associated Sessions
    sessions: List[InvestigationSessionDB] = []
    if matched_session_ids:
        sessions = db.query(InvestigationSessionDB).filter(
            InvestigationSessionDB.session_id.in_(list(matched_session_ids))
        ).all()
    elif not events and session_id:
        single_sess = db.query(InvestigationSessionDB).filter(
            InvestigationSessionDB.session_id == session_id.strip()
        ).first()
        if single_sess:
            sessions = [single_sess]

    # If filtering by source_ip and no events, check sessions by IP
    if not sessions and source_ip:
        sessions = db.query(InvestigationSessionDB).filter(
            InvestigationSessionDB.source_ip == source_ip.strip()
        ).limit(10).all()

    # 3. Add Session Nodes
    for sess in sessions:
        sess_node_id = f"sess_{sess.session_id}"
        sess_label = f"Session: {sess.session_id[:16]}... ({sess.event_count} evts)"
        dur_sec = (sess.last_seen - sess.first_seen).total_seconds() if (sess.last_seen and sess.first_seen) else 0.0
        add_node(
            sess_node_id,
            sess_label,
            "session",
            {
                "session_id": sess.session_id,
                "first_seen": sess.first_seen.isoformat() if sess.first_seen else None,
                "last_seen": sess.last_seen.isoformat() if sess.last_seen else None,
                "duration_seconds": dur_sec,
                "event_count": sess.event_count,
                "source_ip": sess.source_ip,
                "honeypot_id": sess.honeypot_id,
                "username": sess.username,
                "status": sess.status,
                "correlation_method": sess.correlation_method,
                "observed_event_types": sess.observed_event_types or [],
                "flagged_sequences_count": len(sess.flagged_sequences or []),
                "color": "#06b6d4" if sess.status == "active" else "#f43f5e"
            }
        )

        # Attacker IP node & Session -> Attacker IP edge
        if sess.source_ip:
            ip_node_id = f"ip_{sess.source_ip}"
            add_node(
                ip_node_id,
                f"Adversary: {sess.source_ip}",
                "attacker",
                {
                    "source_ip": sess.source_ip,
                    "ip": sess.source_ip,
                    "color": "#e11d48"
                }
            )
            add_edge(
                f"edge_orig_{sess.session_id}_{sess.source_ip}",
                sess_node_id,
                ip_node_id,
                "ORIGINATES_FROM",
                "observed",
                f"Session '{sess.session_id}' originated from remote IP {sess.source_ip}."
            )

    # 4. Add Event Nodes
    events_by_session: Dict[str, List[TelemetryEventDB]] = {}
    for event in events:
        evt_node_id = f"evt_{event.event_id}"
        short_payload = (event.payload[:30] + "...") if (event.payload and len(event.payload) > 30) else (event.payload or event.event_type)
        evt_label = f"[{event.event_type}] {short_payload}"
        
        # Color based on severity
        sev_color = "#10b981"
        if event.severity in ["high", "critical"]:
            sev_color = "#f43f5e"
        elif event.severity == "medium":
            sev_color = "#f59e0b"

        add_node(
            evt_node_id,
            evt_label,
            "event",
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "honeypot_id": event.honeypot_id,
                "honeypot_type": event.honeypot_type,
                "username": event.username,
                "payload": event.payload,
                "severity": event.severity,
                "confidence_score": event.confidence_score,
                "data_origin": event.data_origin or "real",
                "session_id": event.session_id,
                "mitre_technique_id": event.mitre_technique_id,
                "color": sev_color
            }
        )

        # Attacker IP node if not already added
        if event.source_ip:
            ip_node_id = f"ip_{event.source_ip}"
            add_node(
                ip_node_id,
                f"Adversary: {event.source_ip}",
                "attacker",
                {"source_ip": event.source_ip, "ip": event.source_ip, "color": "#e11d48"}
            )

        # Edge 1: Event belongs to session
        if event.session_id:
            sess_node_id = f"sess_{event.session_id}"
            if sess_node_id in seen_nodes:
                add_edge(
                    f"edge_belongs_{event.event_id}_{event.session_id}",
                    evt_node_id,
                    sess_node_id,
                    "BELONGS_TO",
                    "observed",
                    f"Event '{event.event_id}' belongs to correlated session '{event.session_id}'."
                )

            # Group for sequential edge generation
            if event.session_id not in events_by_session:
                events_by_session[event.session_id] = []
            events_by_session[event.session_id].append(event)

    # 5. Add Sequential (PRECEDES) Edges within Sessions
    for s_id, s_events in events_by_session.items():
        sorted_s_events = sorted(s_events, key=lambda x: x.timestamp or datetime.min)
        for i in range(len(sorted_s_events) - 1):
            e_curr = sorted_s_events[i]
            e_next = sorted_s_events[i + 1]
            dt = 0
            if e_curr.timestamp and e_next.timestamp:
                dt = round((e_next.timestamp - e_curr.timestamp).total_seconds(), 1)
            add_edge(
                f"seq_{e_curr.event_id}_{e_next.event_id}",
                f"evt_{e_curr.event_id}",
                f"evt_{e_next.event_id}",
                "PRECEDES",
                "temporal_sequence",
                f"Observed temporal progression in session '{s_id}'. Event {e_curr.event_id} occurred {dt}s prior to {e_next.event_id}."
            )

    # 6. Add MITRE Technique Nodes and Evidence Edges
    # Retrieve all technique mappings relevant to the current events and sessions
    event_ids_list = [e.event_id for e in events]
    session_ids_list = [s.session_id for s in sessions]

    mappings_query = db.query(TechniqueMappingDB)
    conds = []
    if event_ids_list:
        conds.append(TechniqueMappingDB.event_id.in_(event_ids_list))
    if session_ids_list:
        conds.append(TechniqueMappingDB.session_id.in_(session_ids_list))
    if technique_id:
        conds.append(TechniqueMappingDB.technique_id == technique_id.strip())

    relevant_mappings: List[TechniqueMappingDB] = []
    if conds:
        relevant_mappings = mappings_query.filter(or_(*conds)).all()

    # Set of technique IDs observed
    referenced_technique_ids = set()
    for m in relevant_mappings:
        referenced_technique_ids.add(m.technique_id)
    for e in events:
        if e.mitre_technique_id:
            referenced_technique_ids.add(e.mitre_technique_id)
    for s in sessions:
        for t in (s.associated_mitre_techniques or []):
            if t.get("technique_id"):
                referenced_technique_ids.add(t["technique_id"])

    # Create technique nodes
    for tid in referenced_technique_ids:
        cat_item = get_technique_from_catalog(tid)
        t_name = cat_item.name if cat_item else tid
        t_tactic = (cat_item.tactics[0] if cat_item and cat_item.tactics else "Discovery")
        t_node_id = f"mitre_{tid}"
        add_node(
            t_node_id,
            f"{tid}: {t_name}",
            "technique",
            {
                "technique_id": tid,
                "name": t_name,
                "tactic": t_tactic,
                "description": cat_item.description if cat_item else "",
                "mapping_rule_id": cat_item.mapping_rule_id if cat_item else "RULE_EVIDENCE",
                "color": "#a855f7"
            }
        )

    # Edge 2: Event SUPPORTS_TECHNIQUE MITRE Technique
    for event in events:
        if event.mitre_technique_id:
            t_node_id = f"mitre_{event.mitre_technique_id}"
            if t_node_id in seen_nodes:
                add_edge(
                    f"edge_evt_tech_{event.event_id}_{event.mitre_technique_id}",
                    f"evt_{event.event_id}",
                    t_node_id,
                    "SUPPORTS_TECHNIQUE",
                    "evidence_backed",
                    f"Event '{event.event_id}' provides concrete telemetry evidence supporting technique {event.mitre_technique_id}."
                )

    # Edge 3: Session CONTAINS_TECHNIQUE MITRE Technique
    for sess in sessions:
        sess_node_id = f"sess_{sess.session_id}"
        for t in (sess.associated_mitre_techniques or []):
            tid = t.get("technique_id")
            if tid:
                t_node_id = f"mitre_{tid}"
                if t_node_id in seen_nodes:
                    sup_count = len(t.get("supporting_event_ids") or [])
                    strength = t.get("evidence_strength", "medium")
                    add_edge(
                        f"edge_sess_tech_{sess.session_id}_{tid}",
                        sess_node_id,
                        t_node_id,
                        "CONTAINS_TECHNIQUE",
                        "session_aggregated",
                        f"Session '{sess.session_id}' contains evidence-backed mapping for {tid} ({sup_count} supporting events, strength={strength})."
                    )

    # 7. Add Security Alert Nodes & Edges
    # Find alerts linked to current sessions or events
    alert_query = db.query(AlertDB)
    alert_conds = []
    if session_ids_list:
        alert_conds.append(AlertDB.session_id.in_(session_ids_list))
    if matched_ips:
        alert_conds.append(AlertDB.source_ip.in_(list(matched_ips)))

    alerts: List[AlertDB] = []
    if alert_conds:
        alerts = alert_query.filter(or_(*alert_conds)).limit(20).all()

    for alert in alerts:
        alert_node_id = f"alert_{alert.alert_id}"
        add_node(
            alert_node_id,
            f"Alert: {alert.title[:25]}...",
            "alert",
            {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "session_id": alert.session_id,
                "primary_technique_id": alert.primary_technique_id,
                "is_resolved": alert.is_resolved,
                "color": "#dc2626"
            }
        )

        # Edge 4: Alert ALERTS_ON_SESSION
        if alert.session_id:
            sess_node_id = f"sess_{alert.session_id}"
            if sess_node_id in seen_nodes:
                add_edge(
                    f"edge_alert_sess_{alert.alert_id}_{alert.session_id}",
                    alert_node_id,
                    sess_node_id,
                    "ALERTS_ON_SESSION",
                    "alert_association",
                    f"High-severity security alert '{alert.title}' raised for session '{alert.session_id}'."
                )

        # Edge 5: Alert ALERTS_ON_TECHNIQUE
        if alert.primary_technique_id:
            t_node_id = f"mitre_{alert.primary_technique_id}"
            if t_node_id in seen_nodes:
                add_edge(
                    f"edge_alert_tech_{alert.alert_id}_{alert.primary_technique_id}",
                    alert_node_id,
                    t_node_id,
                    "ALERTS_ON_TECHNIQUE",
                    "alert_attribution",
                    f"Alert '{alert.title}' attributes threat activity to {alert.primary_technique_id}."
                )

    story = generate_investigation_story(
        events=events,
        sessions=sessions,
        alerts=alerts,
        mappings=relevant_mappings,
        source_ip=source_ip,
        session_id=session_id
    )

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "investigation_story": story,
        "filters_applied": {
            "session_id": session_id,
            "source_ip": source_ip,
            "technique_id": technique_id,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "limit": limit
        }
    }

def generate_investigation_story(
    events: List[TelemetryEventDB],
    sessions: List[InvestigationSessionDB],
    alerts: List[AlertDB],
    mappings: List[TechniqueMappingDB],
    source_ip: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Synthesizes an explainable investigation story from actual telemetry and graph relationships.
    Explicitly addresses the 8 core analytical questions:
    1. What was observed first?
    2. What happened next?
    3. Which events appear related?
    4. What suspicious behaviors were identified?
    5. Which ATT&CK techniques were considered?
    6. Which mappings were supported or rejected?
    7. Why were alerts generated?
    8. What remains uncertain?
    """
    if not events:
        return {
            "what_was_observed_first": "No telemetry records observed matching the specified investigation criteria.",
            "what_happened_next": "No subsequent activity recorded in this investigation window.",
            "which_events_appear_related": "No correlated sessions or linked events found.",
            "what_suspicious_behaviors_were_identified": "None identified.",
            "which_attack_techniques_were_considered": [],
            "which_mappings_were_supported_or_rejected": {
                "supported": [],
                "needs_more_evidence": [],
                "rejected": []
            },
            "why_were_alerts_generated": "No security alerts associated with this scope.",
            "what_remains_uncertain": "Baseline network state without observable telemetry."
        }

    # 1. First observation
    first_ev = events[0]
    first_time_str = first_ev.timestamp.isoformat() if first_ev.timestamp else "unknown time"
    first_desc = (
        f"Initial activity was recorded at {first_time_str} from IP {first_ev.source_ip} "
        f"targeting sensor '{first_ev.honeypot_id}' via {first_ev.event_type} "
        f"(port {first_ev.destination_port or 'default'})."
    )

    # 2. What happened next
    if len(events) > 1:
        last_ev = events[-1]
        delta_sec = (last_ev.timestamp - first_ev.timestamp).total_seconds() if (first_ev.timestamp and last_ev.timestamp) else 0.0
        unique_types = list(set(e.event_type for e in events[1:]))
        next_desc = (
            f"Over the subsequent {delta_sec:.1f} seconds, {len(events) - 1} further events were recorded, "
            f"exhibiting activities: {', '.join(unique_types[:5])}."
        )
    else:
        next_desc = "No subsequent activity observed within the current filter window."

    # 3. Which events appear related
    session_count = len(sessions)
    if sessions:
        sess_methods = list(set(s.correlation_method for s in sessions if s.correlation_method))
        sess_ids = [s.session_id for s in sessions[:3]]
        related_desc = (
            f"Events were correlated into {session_count} session(s) ({', '.join(sess_ids)}) "
            f"using methods: {', '.join(sess_methods)}. Grouping is based on shared source IP ({first_ev.source_ip}) "
            f"and contiguous temporal proximity."
        )
    else:
        related_desc = "Events share common endpoint attributes (source IP or target honeypot) but have not been formally grouped into a session."

    # 4. Suspicious behaviors identified
    behaviors = set()
    for e in events:
        if e.event_type in ["auth_failure", "login_failed"]:
            behaviors.add("Authentication Failures")
        elif e.event_type in ["auth_success", "login_success"]:
            behaviors.add("Successful Authentication")
        elif e.event_type in ["port_scan", "network_scan"]:
            behaviors.add("Network Scanning")
        elif e.payload:
            p_lower = e.payload.lower()
            if any(k in p_lower for k in ["whoami", "uname", "id", "systeminfo"]):
                behaviors.add("Host/User Discovery")
            if any(k in p_lower for k in ["curl", "wget", "tftp"]):
                behaviors.add("Ingress Tool Transfer")
            if any(k in p_lower for k in ["crontab", "/etc/cron"]):
                behaviors.add("Persistence Manipulation")
            if any(k in p_lower for k in ["history -c", "rm -rf"]):
                behaviors.add("Defense Evasion")

    behavior_list = list(behaviors) or ["Routine network traffic"]
    behaviors_desc = f"Identified behaviors include: {', '.join(behavior_list)}."

    # 5. ATT&CK techniques considered
    considered_techniques = list(set(
        [e.mitre_technique_id for e in events if e.mitre_technique_id] +
        [m.technique_id for m in mappings if m.technique_id]
    ))

    # 6. Mappings supported vs rejected
    supported = []
    insufficient = []
    rejected = []
    for m in mappings:
        item = {"technique_id": m.technique_id, "name": m.technique_name, "rule": m.mapping_rule}
        if m.mapping_status == "supported":
            supported.append(item)
        elif m.mapping_status in ["insufficient_evidence", "suggested"]:
            insufficient.append(item)
        else:
            rejected.append(item)

    # 7. Why alerts were generated
    if alerts:
        alert_reasons = [
            f"Alert '{a.title}' ({a.severity}) triggered by rule {a.detection_rule_id}: {a.severity_rationale or a.description[:80]}"
            for a in alerts[:5]
        ]
        alerts_desc = "; ".join(alert_reasons)
    else:
        alerts_desc = "No security alerts triggered; activity did not exceed defined severity or multi-sequence correlation thresholds."

    # 8. What remains uncertain
    uncertain_desc = (
        "Honeynet decoy telemetry captures observed terminal strings and network packets. "
        "It does not verify whether commands produced intended adversary outcomes on genuine production OS environments. "
        "Source IP identifies network routing origin; proxy, VPN, or spoofing factors mean true attacker identity cannot be proven from IP alone. "
        "Temporal correlation indicates observed co-occurrence, not verified causal sequence."
    )

    return {
        "what_was_observed_first": first_desc,
        "what_happened_next": next_desc,
        "which_events_appear_related": related_desc,
        "what_suspicious_behaviors_were_identified": behaviors_desc,
        "which_attack_techniques_were_considered": considered_techniques,
        "which_mappings_were_supported_or_rejected": {
            "supported": supported,
            "needs_more_evidence": insufficient,
            "rejected": rejected
        },
        "why_were_alerts_generated": alerts_desc,
        "what_remains_uncertain": uncertain_desc
    }

def generate_causal_graph(
    db: Session,
    session_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Backwards-compatible wrapper that invokes build_investigation_graph.
    """
    return build_investigation_graph(
        db=db,
        session_id=session_id,
        source_ip=source_ip,
        limit=limit
    )
