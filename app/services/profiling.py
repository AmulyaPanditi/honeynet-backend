"""
Attacker Behavior Profiling Service
Project: Autonomous Honeynet Telemetry & Threat Actor MITRE ATT&CK Causal Graph Profiler.

Builds evidence-based threat actor profiles from correlated telemetry, verified ATT&CK mappings,
and security alerts. Strictly preserves uncertainty and avoids fabricating real-world person identities.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models.telemetry import TelemetryEventDB
from backend.app.models.session import InvestigationSessionDB
from backend.app.models.alert import AlertDB
from backend.app.models.mitre import TechniqueMappingDB
from backend.app.services.alerts import cluster_threat_actor
from backend.app.services.event_analysis import analyze_telemetry_event
from backend.app.services.mitre_verification import verify_technique_mapping

def build_attacker_profile(source_ip: str, db: Session) -> Optional[Dict[str, Any]]:
    """
    Constructs an evidence-backed behavioral profile for a specific adversary source IP.
    Adheres strictly to cybersecurity evidentiary boundaries:
    - Never equates an IP address to a physical individual.
    - Never claims threat group attribution without definitive IOC evidence.
    - Distinguishes observed TTPs from unverified inferences.
    """
    ip_clean = (source_ip or "").strip()
    if not ip_clean:
        return None

    events = db.query(TelemetryEventDB).filter(
        TelemetryEventDB.source_ip == ip_clean
    ).order_by(TelemetryEventDB.timestamp.asc()).all()

    if not events:
        return None

    first_time = events[0].timestamp or datetime.now(timezone.utc)
    last_time = events[-1].timestamp or first_time
    duration = max(0.0, (last_time - first_time).total_seconds())

    sessions = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.source_ip == ip_clean
    ).all()

    alerts = db.query(AlertDB).filter(
        AlertDB.source_ip == ip_clean
    ).all()

    # Determine behavioral cluster
    cluster_label = cluster_threat_actor(events, ip_clean)

    # Behavior frequency breakdown
    behavior_counts: Dict[str, int] = {}
    for ev in events:
        res = analyze_telemetry_event(ev)
        cat = res.observed_behavior_category
        behavior_counts[cat] = behavior_counts.get(cat, 0) + 1

    # Extract distinct targeted endpoints
    honeypots = list(set(e.honeypot_id for e in events if e.honeypot_id))
    usernames = list(set(e.username for e in events if e.username))

    # Compile candidate and verified MITRE techniques
    raw_techniques = list(set(e.mitre_technique_id for e in events if e.mitre_technique_id))
    verified_techniques = []
    for tid in raw_techniques:
        supporting_for_tid = [e for e in events if e.mitre_technique_id == tid]
        first_supp = supporting_for_tid[0]
        v_res = verify_technique_mapping(
            candidate_technique_id=tid,
            event_type=first_supp.event_type,
            payload=first_supp.payload,
            username=first_supp.username,
            supporting_event_ids=[e.event_id for e in supporting_for_tid],
            event_count=len(supporting_for_tid)
        )
        verified_techniques.append({
            "technique_id": v_res.candidate_technique_id,
            "name": v_res.official_technique_name,
            "status": v_res.verification_status,
            "event_count": len(supporting_for_tid),
            "rationale": v_res.mapping_rationale
        })

    # Alert summaries
    alert_summaries = [
        {
            "alert_id": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "detection_rule_id": a.detection_rule_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None
        }
        for a in alerts
    ]

    # Chronological sample activity
    timeline_sample = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "payload_snippet": (e.payload[:80] if e.payload else None),
            "mitre_technique_id": e.mitre_technique_id
        }
        for e in events[:15]
    ]

    # Synthesize evidence-backed narrative
    top_behaviors = sorted(behavior_counts.items(), key=lambda x: x[1], reverse=True)
    behaviors_str = ", ".join([f"{k} ({v})" for k, v in top_behaviors[:4]]) if top_behaviors else "None"
    
    evidence_summary = (
        f"Observed {len(events)} telemetry events across {len(sessions)} session(s) spanning {duration:.1f} seconds. "
        f"Activity targeted sensor(s): {', '.join(honeypots) or 'default'}. "
        f"Primary behavioral indicators: {behaviors_str}. "
        f"Correlated cluster classification: '{cluster_label}' with {len(alerts)} security alert(s) raised."
    )

    uncertainty_disclaimer = (
        "Adversary profiling is derived exclusively from telemetry observations. "
        "The source IP reflects the originating or relay network address and does not prove the legal identity "
        "of a human operator or confirm threat group attribution without external cross-sensor intelligence. "
        "Event frequency alone does not establish attacker sophistication."
    )

    return {
        "source_ip": ip_clean,
        "cluster_label": cluster_label,
        "first_seen": first_time.isoformat(),
        "last_seen": last_time.isoformat(),
        "duration_seconds": duration,
        "total_events": len(events),
        "total_sessions": len(sessions),
        "targeted_honeypots": honeypots,
        "targeted_usernames": usernames,
        "observed_behaviors": behavior_counts,
        "candidate_techniques": raw_techniques,
        "verified_techniques": verified_techniques,
        "related_alerts": alert_summaries,
        "chronological_activity": timeline_sample,
        "evidence_backed_summary": evidence_summary,
        "missing_evidence_and_uncertainty": uncertainty_disclaimer
    }

def list_attacker_profiles(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Returns aggregated behavioral profile summaries across top active adversary source IPs.
    """
    top_ips_q = db.query(
        TelemetryEventDB.source_ip,
        func.count(TelemetryEventDB.id).label("cnt")
    ).group_by(TelemetryEventDB.source_ip)\
     .order_by(func.count(TelemetryEventDB.id).desc())\
     .limit(limit).all()

    summaries = []
    for row in top_ips_q:
        ip = row[0]
        profile = build_attacker_profile(ip, db)
        if profile:
            summaries.append({
                "source_ip": profile["source_ip"],
                "cluster_label": profile["cluster_label"],
                "first_seen": profile["first_seen"],
                "last_seen": profile["last_seen"],
                "total_events": profile["total_events"],
                "total_sessions": profile["total_sessions"],
                "targeted_honeypots": profile["targeted_honeypots"],
                "alert_count": len(profile["related_alerts"]),
                "evidence_backed_summary": profile["evidence_backed_summary"]
            })

    return summaries
