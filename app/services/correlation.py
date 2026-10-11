import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.telemetry import TelemetryEventDB
from app.models.session import InvestigationSessionDB, FlaggedSequenceLead

logger = logging.getLogger("honeynet.correlation")

# Configurable correlation time window (default 30 minutes)
CORRELATION_WINDOW_MINUTES = 30

def detect_activity_sequences(events: List[TelemetryEventDB]) -> List[Dict[str, Any]]:
    """
    Evaluates transparent heuristics to flag meaningful activity sequences within a session.
    These sequences represent investigation leads for analysts, not automatic proof of attacks.
    """
    flagged: List[Dict[str, Any]] = []
    
    if not events:
        return flagged

    # Sort events chronologically
    sorted_events = sorted(events, key=lambda e: e.timestamp or datetime.min)

    # 1. Rule: Repeated authentication failures
    failed_auths = [
        e for e in sorted_events 
        if e.event_type == "auth_attempt" and 
        ("fail" in (e.payload or "").lower() or "invalid" in (e.payload or "").lower() or "login failed" in (e.payload or "").lower())
    ]
    if len(failed_auths) >= 2:
        flagged.append({
            "rule_id": "RULE_AUTH_BRUTE_FORCE",
            "title": "Repeated Authentication Failures",
            "explanation": "Multiple consecutive failed authentication attempts observed in session window. Investigation lead for credential guessing or dictionary attack.",
            "supporting_event_ids": [e.event_id for e in failed_auths],
            "timestamps": [(e.timestamp.isoformat() if e.timestamp else "") for e in failed_auths],
            "evidence": {
                "failed_count": len(failed_auths),
                "attempted_users": list(set([e.username for e in failed_auths if e.username])),
                "target_sensor": failed_auths[0].honeypot_id
            }
        })

    # 2. Rule: Authentication failures followed by successful login
    successful_auths = [
        e for e in sorted_events
        if e.event_type == "auth_attempt" and
        ("succeed" in (e.payload or "").lower() or "success" in (e.payload or "").lower() or "login succeeded" in (e.payload or "").lower())
    ]
    if failed_auths and successful_auths:
        # Check if a failure precedes a success
        first_fail_time = min(e.timestamp for e in failed_auths if e.timestamp)
        first_success_time = min(e.timestamp for e in successful_auths if e.timestamp)
        if first_fail_time <= first_success_time:
            breach_event = successful_auths[0]
            flagged.append({
                "rule_id": "RULE_AUTH_BREACH",
                "title": "Authentication Failure Followed by Successful Login",
                "explanation": "Failed authentication attempts were followed by an accepted login credential. Investigation lead for potential brute force breakthrough or credential compromise.",
                "supporting_event_ids": [failed_auths[0].event_id, breach_event.event_id],
                "timestamps": [
                    first_fail_time.isoformat() if first_fail_time else "",
                    first_success_time.isoformat() if first_success_time else ""
                ],
                "evidence": {
                    "prior_failures_count": len(failed_auths),
                    "successful_user": breach_event.username,
                    "target_sensor": breach_event.honeypot_id
                }
            })

    # 3. Rule: Authentication followed by command execution activity
    auth_events = [e for e in sorted_events if e.event_type == "auth_attempt"]
    command_events = [e for e in sorted_events if e.event_type == "command_execution"]
    if auth_events and command_events:
        first_auth_time = min(e.timestamp for e in auth_events if e.timestamp)
        post_auth_commands = [c for c in command_events if c.timestamp and c.timestamp >= first_auth_time]
        if post_auth_commands:
            flagged.append({
                "rule_id": "RULE_POST_AUTH_EXECUTION",
                "title": "Authentication Followed by Command Execution Activity",
                "explanation": "Terminal command execution observed following an authentication event. Investigation lead for post-compromise reconnaissance or payload staging.",
                "supporting_event_ids": [auth_events[0].event_id] + [c.event_id for c in post_auth_commands[:3]],
                "timestamps": [
                    first_auth_time.isoformat(),
                    post_auth_commands[0].timestamp.isoformat()
                ],
                "evidence": {
                    "first_command": post_auth_commands[0].payload,
                    "commands_count": len(post_auth_commands),
                    "user": post_auth_commands[0].username or auth_events[0].username
                }
            })

    # 4. Rule: Multiple discovery-related events in correlated session
    discovery_events = [
        e for e in sorted_events
        if (e.mitre_tactic and "Discovery" in e.mitre_tactic) or
        e.event_type in ["port_scan", "network_probe"] or
        any(k in (e.payload or "").lower() for k in ["whoami", "uname", "id", "ifconfig", "ip a", "cat /etc/issue"])
    ]
    if len(discovery_events) >= 2:
        flagged.append({
            "rule_id": "RULE_DISCOVERY_CONCENTRATION",
            "title": "Concentrated Environmental Discovery Sequence",
            "explanation": "Multiple distinct reconnaissance and discovery actions observed in session. Investigation lead for environmental enumeration.",
            "supporting_event_ids": [e.event_id for e in discovery_events[:5]],
            "timestamps": [(e.timestamp.isoformat() if e.timestamp else "") for e in discovery_events[:5]],
            "evidence": {
                "discovery_events_count": len(discovery_events),
                "techniques": list(set([e.mitre_technique_id for e in discovery_events if e.mitre_technique_id]))
            }
        })

    # 5. Rule: Tool Transfer / Ingress Staging
    transfer_events = [
        e for e in sorted_events
        if e.mitre_technique_id == "T1105" or
        any(k in (e.payload or "").lower() for k in ["curl ", "wget ", "tftp ", "certutil", "bitsadmin"])
    ]
    if transfer_events:
        flagged.append({
            "rule_id": "RULE_TOOL_TRANSFER_STAGING",
            "title": "Ingress Tool Transfer Activity",
            "explanation": "External download or transfer utility invocation observed in session. Investigation lead for staging remote malware or toolkits.",
            "supporting_event_ids": [e.event_id for e in transfer_events],
            "timestamps": [(e.timestamp.isoformat() if e.timestamp else "") for e in transfer_events],
            "evidence": {
                "transfer_events_count": len(transfer_events),
                "payload_samples": [e.payload[:80] for e in transfer_events if e.payload]
            }
        })

    # 6. Rule: Scheduled Task / Cron Persistence
    persist_events = [
        e for e in sorted_events
        if e.mitre_technique_id == "T1053.003" or
        any(k in (e.payload or "").lower() for k in ["crontab", "/etc/cron", "systemctl enable"])
    ]
    if persist_events:
        flagged.append({
            "rule_id": "RULE_PERSISTENCE_INSTALLATION",
            "title": "Persistence Mechanism Configuration",
            "explanation": "Scheduled task, systemd unit, or crontab manipulation observed. Investigation lead for recurring execution persistence.",
            "supporting_event_ids": [e.event_id for e in persist_events],
            "timestamps": [(e.timestamp.isoformat() if e.timestamp else "") for e in persist_events],
            "evidence": {
                "persist_events_count": len(persist_events),
                "payload_samples": [e.payload[:80] for e in persist_events if e.payload]
            }
        })

    # 7. Rule: Defense Evasion / Indicator Removal
    evasion_events = [
        e for e in sorted_events
        if e.mitre_technique_id == "T1070.004" or
        any(k in (e.payload or "").lower() for k in ["history -c", "rm -rf", "unset histfile", "truncate -s 0", "shred"])
    ]
    if evasion_events:
        flagged.append({
            "rule_id": "RULE_DEFENSE_EVASION_CLEANUP",
            "title": "Defense Evasion Trace Erasure",
            "explanation": "Shell history clearing or recursive file removal observed. Investigation lead for anti-forensic activity.",
            "supporting_event_ids": [e.event_id for e in evasion_events],
            "timestamps": [(e.timestamp.isoformat() if e.timestamp else "") for e in evasion_events],
            "evidence": {
                "evasion_events_count": len(evasion_events),
                "payload_samples": [e.payload[:80] for e in evasion_events if e.payload]
            }
        })

    # 8. Rule: Multi-Stage Intrusion Progression
    observed_stages = []
    if failed_auths:
        observed_stages.append("Credential Access (Failures)")
    if successful_auths:
        observed_stages.append("Initial Access (Valid Login)")
    if discovery_events:
        observed_stages.append("Discovery")
    if transfer_events:
        observed_stages.append("Ingress Tool Transfer")
    if persist_events:
        observed_stages.append("Persistence")
    if evasion_events:
        observed_stages.append("Defense Evasion")

    if len(observed_stages) >= 3:
        all_stage_event_ids = list(dict.fromkeys(
            [e.event_id for e in failed_auths + successful_auths + discovery_events + transfer_events + persist_events + evasion_events]
        ))
        flagged.append({
            "rule_id": "RULE_MULTI_STAGE_CHAIN",
            "title": "Multi-Stage Attack Progression Observed",
            "explanation": (
                f"Session exhibited {len(observed_stages)} progressive stages: "
                f"{' -> '.join(observed_stages)}. Investigation lead for cohesive adversary campaign."
            ),
            "supporting_event_ids": all_stage_event_ids[:10],
            "timestamps": [(sorted_events[0].timestamp.isoformat() if sorted_events[0].timestamp else "")],
            "evidence": {
                "observed_stages_count": len(observed_stages),
                "stages": observed_stages
            }
        })

    return flagged

def correlate_events(db: Session, window_minutes: int = CORRELATION_WINDOW_MINUTES) -> Dict[str, Any]:
    """
    Executes the event correlation engine across all stored telemetry events.
    Groups events into persistent investigation sessions using explicit session IDs
    or documented fallback rules (IP + sensor + temporal window).
    """
    all_events = db.query(TelemetryEventDB).order_by(TelemetryEventDB.timestamp.asc()).all()
    if not all_events:
        return {
            "status": "completed",
            "events_processed": 0,
            "correlated_sessions": 0,
            "flagged_sequences_detected": 0
        }

    # Grouping structure: session_id -> list of events
    session_groups: Dict[str, Tuple[List[TelemetryEventDB], str]] = {}

    # Step 1: Explicit Trustworthy Session Identifiers
    unassigned_events: List[TelemetryEventDB] = []

    for event in all_events:
        if event.session_id and event.session_id.strip():
            sess_id = event.session_id.strip()
            corr_m = "fallback_ip_sensor_window" if sess_id.startswith("fallback-") else "explicit_session_id"
            if sess_id not in session_groups:
                session_groups[sess_id] = ([], corr_m)
            session_groups[sess_id][0].append(event)
        else:
            unassigned_events.append(event)

    # Step 2: Fallback Correlation for unassigned events
    # Rule: Group by (source_ip, honeypot_id) where consecutive event timestamps <= window_minutes
    # Do NOT assume IP alone is sufficient; combine IP + targeted sensor to represent cohesive interaction.
    grouped_by_ip_sensor: Dict[Tuple[str, str], List[TelemetryEventDB]] = {}
    for event in unassigned_events:
        key = (event.source_ip, event.honeypot_id or "sensor-default")
        if key not in grouped_by_ip_sensor:
            grouped_by_ip_sensor[key] = []
        grouped_by_ip_sensor[key].append(event)

    for (ip, sensor), ev_list in grouped_by_ip_sensor.items():
        # Sort chronologically
        ev_list.sort(key=lambda e: e.timestamp or datetime.min)
        
        current_cluster: List[TelemetryEventDB] = []
        last_time: Optional[datetime] = None

        for ev in ev_list:
            ev_time = ev.timestamp or datetime.now(timezone.utc)
            if last_time is None or (ev_time - last_time) <= timedelta(minutes=window_minutes):
                current_cluster.append(ev)
                last_time = ev_time
            else:
                # Window exceeded: close cluster and start new one
                if current_cluster:
                    cluster_start_ts = int(current_cluster[0].timestamp.timestamp()) if current_cluster[0].timestamp else 0
                    fallback_id = f"fallback-{ip.replace('.', '-')}-{sensor[:12]}-{cluster_start_ts}"
                    session_groups[fallback_id] = (list(current_cluster), "fallback_ip_sensor_window")
                current_cluster = [ev]
                last_time = ev_time

        if current_cluster:
            cluster_start_ts = int(current_cluster[0].timestamp.timestamp()) if current_cluster[0].timestamp else 0
            fallback_id = f"fallback-{ip.replace('.', '-')}-{sensor[:12]}-{cluster_start_ts}"
            session_groups[fallback_id] = (list(current_cluster), "fallback_ip_sensor_window")

    # Step 3: Persist or Update Sessions in Database
    total_flagged_sequences = 0

    for sess_id, (ev_list, corr_method) in session_groups.items():
        if not ev_list:
            continue

        sorted_ev = sorted(ev_list, key=lambda e: e.timestamp or datetime.min)
        first_seen = sorted_ev[0].timestamp or datetime.now(timezone.utc)
        last_seen = sorted_ev[-1].timestamp or datetime.now(timezone.utc)
        source_ip = sorted_ev[0].source_ip
        honeypot_id = sorted_ev[0].honeypot_id
        
        # Determine username if present
        usernames = [e.username for e in sorted_ev if e.username]
        primary_username = usernames[0] if usernames else None

        observed_types = list(set([e.event_type for e in sorted_ev if e.event_type]))
        
        # MITRE techniques summary
        mitre_map: Dict[str, Dict[str, Any]] = {}
        for e in sorted_ev:
            if e.mitre_technique_id:
                mitre_map[e.mitre_technique_id] = {
                    "technique_id": e.mitre_technique_id,
                    "name": e.mitre_technique_name,
                    "tactic": e.mitre_tactic
                }
        associated_mitre = list(mitre_map.values())

        # Evaluate activity sequence rules
        sequences = detect_activity_sequences(sorted_ev)
        total_flagged_sequences += len(sequences)

        status = "flagged" if len(sequences) > 0 else "active"

        # Check if session already exists
        session_record = db.query(InvestigationSessionDB).filter(
            InvestigationSessionDB.session_id == sess_id
        ).first()

        event_ids = [e.event_id for e in sorted_ev]

        if session_record:
            # Update existing session safely
            session_record.first_seen = first_seen
            session_record.last_seen = last_seen
            session_record.source_ip = source_ip
            session_record.honeypot_id = honeypot_id
            session_record.username = primary_username
            session_record.event_count = len(sorted_ev)
            session_record.observed_event_types = observed_types
            session_record.associated_mitre_techniques = associated_mitre
            session_record.correlation_method = corr_method
            session_record.status = status
            session_record.flagged_sequences = sequences
            session_record.associated_event_ids = event_ids
        else:
            # Insert new session
            session_record = InvestigationSessionDB(
                session_id=sess_id,
                first_seen=first_seen,
                last_seen=last_seen,
                source_ip=source_ip,
                honeypot_id=honeypot_id,
                username=primary_username,
                event_count=len(sorted_ev),
                observed_event_types=observed_types,
                associated_mitre_techniques=associated_mitre,
                correlation_method=corr_method,
                status=status,
                flagged_sequences=sequences,
                associated_event_ids=event_ids
            )
            db.add(session_record)

        # Update event.session_id for fallback events to preserve persistent linkage
        if corr_method.startswith("fallback"):
            for e in sorted_ev:
                if not e.session_id:
                    e.session_id = sess_id

    db.commit()

    # Recompute and persist session-level MITRE technique mappings
    try:
        from app.services.mitre import analyze_session_techniques
        for s_id in session_groups.keys():
            s_obj = db.query(InvestigationSessionDB).filter(InvestigationSessionDB.session_id == s_id).first()
            if s_obj:
                analyze_session_techniques(s_obj, db)
    except Exception:
        pass

    return {
        "status": "completed",
        "events_processed": len(all_events),
        "correlated_sessions": len(session_groups),
        "flagged_sequences_detected": total_flagged_sequences
    }

def correlate_single_event(event: TelemetryEventDB, db: Session, window_minutes: int = CORRELATION_WINDOW_MINUTES) -> str:
    """
    Incrementally correlates a single newly ingested telemetry event into an investigation session.
    Returns the assigned session_id.
    """
    ev_time = event.timestamp or datetime.now(timezone.utc)
    assigned_session_id = event.session_id

    corr_method = "explicit_session_id"

    # If no explicit session_id, check for active temporal fallback match (IP + sensor + window)
    if not assigned_session_id:
        corr_method = "fallback_ip_sensor_window"
        sensor_id = event.honeypot_id or "sensor-default"
        cutoff = ev_time - timedelta(minutes=window_minutes)

        candidate = db.query(InvestigationSessionDB).filter(
            InvestigationSessionDB.source_ip == event.source_ip,
            InvestigationSessionDB.honeypot_id == sensor_id,
            InvestigationSessionDB.last_seen >= cutoff
        ).order_by(InvestigationSessionDB.last_seen.desc()).first()

        if candidate:
            assigned_session_id = candidate.session_id
        else:
            ts_epoch = int(ev_time.timestamp())
            assigned_session_id = f"fallback-{event.source_ip.replace('.', '-')}-{sensor_id[:12]}-{ts_epoch}"

        event.session_id = assigned_session_id

    # Fetch all events currently linked to this session
    session_events = db.query(TelemetryEventDB).filter(
        (TelemetryEventDB.session_id == assigned_session_id) |
        (TelemetryEventDB.id == event.id)
    ).order_by(TelemetryEventDB.timestamp.asc()).all()

    if not session_events:
        session_events = [event]

    first_seen = session_events[0].timestamp or ev_time
    last_seen = session_events[-1].timestamp or ev_time
    observed_types = list(set([e.event_type for e in session_events if e.event_type]))
    
    mitre_map: Dict[str, Dict[str, Any]] = {}
    for e in session_events:
        if e.mitre_technique_id:
            mitre_map[e.mitre_technique_id] = {
                "technique_id": e.mitre_technique_id,
                "name": e.mitre_technique_name,
                "tactic": e.mitre_tactic
            }
    associated_mitre = list(mitre_map.values())
    event_ids = [e.event_id for e in session_events]
    primary_username = next((e.username for e in session_events if e.username), event.username)

    # Detect activity sequences
    sequences = detect_activity_sequences(session_events)
    status = "flagged" if len(sequences) > 0 else "active"

    # Check for existing session record
    session_record = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.session_id == assigned_session_id
    ).first()

    if session_record:
        session_record.first_seen = first_seen
        session_record.last_seen = last_seen
        session_record.event_count = len(session_events)
        session_record.observed_event_types = observed_types
        session_record.associated_mitre_techniques = associated_mitre
        session_record.associated_event_ids = event_ids
        session_record.flagged_sequences = sequences
        session_record.status = status
        if primary_username:
            session_record.username = primary_username
    else:
        session_record = InvestigationSessionDB(
            session_id=assigned_session_id,
            first_seen=first_seen,
            last_seen=last_seen,
            source_ip=event.source_ip,
            honeypot_id=event.honeypot_id or "sensor-default",
            username=primary_username,
            event_count=len(session_events),
            observed_event_types=observed_types,
            associated_mitre_techniques=associated_mitre,
            correlation_method=corr_method,
            status=status,
            flagged_sequences=sequences,
            associated_event_ids=event_ids
        )
        db.add(session_record)

    db.commit()

    try:
        from app.services.mitre import analyze_session_techniques
        analyze_session_techniques(session_record, db)
    except Exception:
        pass

    return assigned_session_id

def analyze_session_attack_sequence(session_id: str, db: Session) -> Optional[Dict[str, Any]]:
    """
    Analyzes correlated events in a session chronologically to evaluate multi-stage attack behavior.
    - Preserves references to original event IDs.
    - Evaluates chronological order and relative offsets.
    - Maps individual behaviors to verified ATT&CK techniques using the verification engine.
    - Identifies observed stages vs. missing stages.
    - Distinguishes temporal correlation from causal proof.
    - Produces a structured attack timeline and investigation narrative.
    """
    session = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.session_id == session_id
    ).first()

    if not session:
        return None

    events = db.query(TelemetryEventDB).filter(
        (TelemetryEventDB.session_id == session_id) |
        (TelemetryEventDB.event_id.in_(session.associated_event_ids or []))
    ).order_by(TelemetryEventDB.timestamp.asc()).all()

    if not events:
        return {
            "session_id": session.session_id,
            "status": session.status,
            "first_seen": session.first_seen.isoformat() if session.first_seen else None,
            "last_seen": session.last_seen.isoformat() if session.last_seen else None,
            "duration_seconds": 0.0,
            "total_events": 0,
            "chronological_timeline": [],
            "identified_stages": [],
            "missing_stages": ["Initial Access", "Discovery", "Execution", "Persistence", "Defense Evasion"],
            "correlation_explanation": "No telemetry events currently associated with this session.",
            "investigation_summary": "Session record exists without linked telemetry events."
        }

    first_time = events[0].timestamp or datetime.now(timezone.utc)
    last_time = events[-1].timestamp or first_time
    duration = max(0.0, (last_time - first_time).total_seconds())

    from app.services.event_analysis import analyze_telemetry_event
    from app.services.mitre_verification import verify_technique_mapping

    timeline_items = []
    observed_stages_set = set()
    stage_evidence_map = {}

    for idx, ev in enumerate(events):
        ev_time = ev.timestamp or first_time
        offset = max(0.0, (ev_time - first_time).total_seconds())
        analysis = analyze_telemetry_event(ev)

        # Verification result if technique present
        verified_tech = None
        if analysis.candidate_mitre_technique_ids:
            cand_id = analysis.candidate_mitre_technique_ids[0]
            v_res = verify_technique_mapping(
                candidate_technique_id=cand_id,
                event_type=ev.event_type,
                payload=ev.payload,
                username=ev.username,
                supporting_event_ids=[ev.event_id],
                event_count=1
            )
            verified_tech = {
                "technique_id": v_res.candidate_technique_id,
                "name": v_res.official_technique_name,
                "status": v_res.verification_status,
                "rationale": v_res.mapping_rationale
            }

        cat = analysis.observed_behavior_category
        # Stage categorization
        stage_name = None
        if cat == "AUTH_FAILURE":
            stage_name = "Stage 1: Credential Access Probing"
        elif cat == "AUTH_SUCCESS":
            stage_name = "Stage 2: Initial Access (Valid Account)"
        elif cat in ["USER_DISCOVERY", "SYSTEM_INFO_DISCOVERY", "NETWORK_DISCOVERY"]:
            stage_name = f"Stage 3: Environmental Discovery ({cat})"
        elif cat == "FILE_RETRIEVAL_TRANSFER":
            stage_name = "Stage 4: Ingress Tool Staging"
        elif cat == "PERSISTENCE_MECHANISM":
            stage_name = "Stage 5: Persistence Establishment"
        elif cat == "INDICATOR_REMOVAL":
            stage_name = "Stage 6: Defense Evasion (Cleanup)"

        if stage_name:
            observed_stages_set.add(stage_name)
            if stage_name not in stage_evidence_map:
                stage_evidence_map[stage_name] = []
            stage_evidence_map[stage_name].append(ev.event_id)

        timeline_items.append({
            "sequence_index": idx + 1,
            "event_id": ev.event_id,
            "timestamp": ev_time.isoformat(),
            "offset_seconds": offset,
            "source_ip": ev.source_ip,
            "event_type": ev.event_type,
            "observed_behavior_category": cat,
            "matched_rule_id": analysis.matched_rule_id,
            "payload_snippet": (ev.payload[:100] if ev.payload else None),
            "verified_technique": verified_tech,
            "explanation": analysis.concise_explanation
        })

    # Standard attack lifecycle stages
    all_lifecycle_stages = [
        "Stage 1: Credential Access Probing",
        "Stage 2: Initial Access (Valid Account)",
        "Stage 3: Environmental Discovery",
        "Stage 4: Ingress Tool Staging",
        "Stage 5: Persistence Establishment",
        "Stage 6: Defense Evasion (Cleanup)"
    ]

    identified_stages = [
        {"stage": s, "supporting_event_ids": stage_evidence_map.get(s, [])}
        for s in all_lifecycle_stages if any(s.startswith(base) for base in [s.split(" (")[0], s]) and s in stage_evidence_map
    ]

    # Compute missing stages
    identified_names = [item["stage"] for item in identified_stages]
    missing_stages = [s for s in all_lifecycle_stages if not any(s.split(" (")[0] in name for name in identified_names)]

    corr_expl = (
        f"Events were grouped using correlation method '{session.correlation_method}' "
        f"under a {CORRELATION_WINDOW_MINUTES}-minute time window. "
        "Chronological ordering reflects observed event arrival times on the decoy listener. "
        "Correlation establishes temporal co-occurrence across common endpoints, not definitive causal execution."
    )

    stage_summary_str = f"Observed {len(identified_stages)} intrusion stages ({', '.join(identified_names)})" if identified_stages else "Observed baseline telemetry without distinct attack stages"
    inv_summary = (
        f"Session '{session.session_id}' spanning {duration:.1f} seconds with {len(events)} events from {session.source_ip}. "
        f"{stage_summary_str}. "
        f"Missing stages: {', '.join(missing_stages) if missing_stages else 'None'}."
    )

    return {
        "session_id": session.session_id,
        "status": session.status,
        "first_seen": first_time.isoformat(),
        "last_seen": last_time.isoformat(),
        "duration_seconds": duration,
        "source_ip": session.source_ip,
        "honeypot_id": session.honeypot_id,
        "username": session.username,
        "total_events": len(events),
        "chronological_timeline": timeline_items,
        "identified_stages": identified_stages,
        "missing_stages": missing_stages,
        "correlation_explanation": corr_expl,
        "investigation_summary": inv_summary,
        "flagged_sequences": session.flagged_sequences or []
    }
