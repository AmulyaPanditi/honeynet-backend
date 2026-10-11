from datetime import datetime, timezone
import uuid
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.telemetry import TelemetryEventDB, TelemetryEventCreate
from app.services.mitre import map_telemetry_to_mitre
from app.services.alerts import check_and_create_alert

def ingest_telemetry_event(data: TelemetryEventCreate, db: Session) -> Tuple[TelemetryEventDB, bool]:
    """
    Ingests a raw telemetry event.
    Safely checks for duplicate event_id:
    - If event_id exists, returns (existing_record, True) without throwing database constraint errors.
    - If new, enriches with MITRE ATT&CK heuristics, evaluates alerts, persists, and returns (new_record, False).
    """
    assigned_event_id = data.event_id or str(uuid.uuid4())

    # Check for existing event_id
    existing = db.query(TelemetryEventDB).filter(TelemetryEventDB.event_id == assigned_event_id).first()
    if existing:
        return existing, True

    mitre_data = map_telemetry_to_mitre(
        event_type=data.event_type,
        payload=data.payload,
        destination_port=data.destination_port or 0,
        honeypot_type=data.honeypot_type or "generic",
        username=data.username
    )

    db_event = TelemetryEventDB(
        event_id=assigned_event_id,
        timestamp=data.timestamp or datetime.now(timezone.utc),
        session_id=data.session_id,
        honeypot_id=data.honeypot_id or "sensor-default",
        honeypot_type=data.honeypot_type or "generic",
        source_ip=data.source_ip,
        source_port=data.source_port or 0,
        destination_ip=data.destination_ip or "10.0.0.1",
        destination_port=data.destination_port or 0,
        protocol=data.protocol or "TCP",
        event_type=data.event_type,
        username=data.username,
        payload=data.payload,
        data_origin=data.data_origin or "real",
        mitre_technique_id=mitre_data.get("technique_id"),
        mitre_technique_name=mitre_data.get("name"),
        mitre_tactic=mitre_data.get("tactic"),
        confidence_score=mitre_data.get("confidence", 0.0),
        severity=mitre_data.get("severity", "medium")
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # Persist evidence mapping record if supported
    try:
        from app.services.mitre import persist_event_technique_mapping
        persist_event_technique_mapping(db_event, db)
    except Exception:
        pass

    # Check for alerts only on real or high-severity activity
    try:
        check_and_create_alert(db_event, db)
    except Exception:
        pass

    # Real-time incremental session correlation & session-level technique analysis
    try:
        from app.services.correlation import correlate_single_event
        from app.models.session import InvestigationSessionDB
        from app.services.mitre import analyze_session_techniques
        assigned_session_id = correlate_single_event(db_event, db)
        if assigned_session_id:
            sess_obj = db.query(InvestigationSessionDB).filter(
                InvestigationSessionDB.session_id == assigned_session_id
            ).first()
            if sess_obj:
                analyze_session_techniques(sess_obj, db)
    except Exception:
        pass

    return db_event, False

def ingest_bulk_telemetry(events_list: List[TelemetryEventCreate], db: Session) -> Dict[str, Any]:
    """
    Safely ingests a batch of telemetry events, handling duplicate event IDs without failing the transaction.
    """
    ingested_events = []
    duplicates_count = 0

    for item in events_list:
        event_obj, is_duplicate = ingest_telemetry_event(item, db)
        if is_duplicate:
            duplicates_count += 1
        else:
            ingested_events.append(event_obj)

    return {
        "ingested": len(ingested_events),
        "duplicates_skipped": duplicates_count,
        "total": len(events_list),
        "events": ingested_events
    }
