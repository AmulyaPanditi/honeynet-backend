from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.models.telemetry import TelemetryEventDB
from backend.app.models.alert import AlertDB
from backend.app.models.session import InvestigationSessionDB
from backend.app.services.mitre import MITRE_TECHNIQUES
from backend.app.database import is_sqlite

def get_telemetry_stats(db: Session) -> Dict[str, Any]:
    """
    Computes comprehensive statistics directly from stored telemetry events.
    Strictly calculates real aggregations; never fabricates numbers.
    """
    total_events = db.query(func.count(TelemetryEventDB.id)).scalar() or 0
    real_events_count = db.query(func.count(TelemetryEventDB.id)).filter(
        (TelemetryEventDB.data_origin == "real") | (TelemetryEventDB.data_origin.is_(None))
    ).scalar() or 0
    synthetic_events_count = db.query(func.count(TelemetryEventDB.id)).filter(
        TelemetryEventDB.data_origin == "synthetic"
    ).scalar() or 0

    total_sessions = db.query(func.count(InvestigationSessionDB.id)).scalar() or 0
    flagged_sessions = db.query(func.count(InvestigationSessionDB.id)).filter(
        InvestigationSessionDB.status == "flagged"
    ).scalar() or 0

    unique_source_ips = db.query(func.count(func.distinct(TelemetryEventDB.source_ip))).scalar() or 0
    unique_honeypots = db.query(func.count(func.distinct(TelemetryEventDB.honeypot_id))).scalar() or 0

    # Event types breakdown
    event_types_q = db.query(
        TelemetryEventDB.event_type, func.count(TelemetryEventDB.id)
    ).group_by(TelemetryEventDB.event_type).all()
    event_types_breakdown = {row[0]: row[1] for row in event_types_q if row[0]}

    # Severity breakdown
    severity_q = db.query(
        TelemetryEventDB.severity, func.count(TelemetryEventDB.id)
    ).group_by(TelemetryEventDB.severity).all()
    severity_breakdown = {row[0]: row[1] for row in severity_q if row[0]}

    # Data origin breakdown
    data_origin_q = db.query(
        TelemetryEventDB.data_origin, func.count(TelemetryEventDB.id)
    ).group_by(TelemetryEventDB.data_origin).all()
    data_origin_breakdown = {
        (row[0] or "real"): row[1] for row in data_origin_q
    }

    # Top Source IPs
    top_ips_q = db.query(
        TelemetryEventDB.source_ip, func.count(TelemetryEventDB.id).label("count")
    ).group_by(TelemetryEventDB.source_ip).order_by(func.count(TelemetryEventDB.id).desc()).limit(10).all()
    top_source_ips = [{"source_ip": r[0], "count": r[1]} for r in top_ips_q]

    # Top MITRE Techniques
    top_mitre_q = db.query(
        TelemetryEventDB.mitre_technique_id,
        TelemetryEventDB.mitre_technique_name,
        func.count(TelemetryEventDB.id).label("count")
    ).filter(TelemetryEventDB.mitre_technique_id.isnot(None))\
     .group_by(TelemetryEventDB.mitre_technique_id, TelemetryEventDB.mitre_technique_name)\
     .order_by(func.count(TelemetryEventDB.id).desc()).limit(10).all()
    top_mitre_techniques = [
        {"technique_id": r[0], "name": r[1], "count": r[2]} for r in top_mitre_q
    ]

    return {
        "total_events": total_events,
        "real_events_count": real_events_count,
        "synthetic_events_count": synthetic_events_count,
        "total_sessions": total_sessions,
        "flagged_sessions": flagged_sessions,
        "unique_source_ips": unique_source_ips,
        "unique_honeypots": unique_honeypots,
        "event_types_breakdown": event_types_breakdown,
        "severity_breakdown": severity_breakdown,
        "data_origin_breakdown": data_origin_breakdown,
        "top_source_ips": top_source_ips,
        "top_mitre_techniques": top_mitre_techniques,
        "database_engine": "SQLite (Local Fallback)" if is_sqlite else "PostgreSQL (Hosted)"
    }

def get_dashboard_summary(db: Session) -> Dict[str, Any]:
    """
    Computes dashboard metrics derived directly from telemetry and alert persistence.
    """
    stats = get_telemetry_stats(db)
    total_alerts = db.query(func.count(AlertDB.id)).scalar() or 0
    new_alerts = db.query(func.count(AlertDB.id)).filter(AlertDB.status == "NEW").scalar() or 0
    resolved_alerts = db.query(func.count(AlertDB.id)).filter(
        (AlertDB.status == "RESOLVED") | (AlertDB.is_resolved == True)
    ).scalar() or 0
    unresolved_alerts = db.query(func.count(AlertDB.id)).filter(AlertDB.is_resolved == False).scalar() or 0

    sev_alerts_q = db.query(AlertDB.severity, func.count(AlertDB.id)).group_by(AlertDB.severity).all()
    alerts_by_severity = {row[0]: row[1] for row in sev_alerts_q if row[0]}

    return {
        "total_events": stats["total_events"],
        "real_events_count": stats["real_events_count"],
        "synthetic_events_count": stats["synthetic_events_count"],
        "total_sessions": stats["total_sessions"],
        "flagged_sessions": stats["flagged_sessions"],
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "resolved_alerts": resolved_alerts,
        "unresolved_alerts": unresolved_alerts,
        "alerts_by_severity": alerts_by_severity,
        "unique_attackers": stats["unique_source_ips"],
        "active_honeypots": stats["unique_honeypots"],
        "severity_distribution": stats["severity_breakdown"],
        "top_mitre_techniques": stats["top_mitre_techniques"][:5],
        "top_attackers": stats["top_source_ips"][:5]
    }

def get_mitre_matrix_status(db: Session) -> List[Dict[str, Any]]:
    """
    Returns the MITRE ATT&CK coverage matrix populated with real detection event counts.
    """
    counts_query = db.query(
        TelemetryEventDB.mitre_technique_id,
        func.count(TelemetryEventDB.id)
    ).filter(TelemetryEventDB.mitre_technique_id.isnot(None))\
     .group_by(TelemetryEventDB.mitre_technique_id).all()
    
    count_map = {row[0]: row[1] for row in counts_query}

    matrix = []
    for tech_id, info in MITRE_TECHNIQUES.items():
        matrix.append({
            "technique_id": tech_id,
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "detections_count": count_map.get(tech_id, 0)
        })

    return matrix
