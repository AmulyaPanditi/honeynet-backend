from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime

from backend.app.database import get_db
from backend.app.models.session import (
    InvestigationSessionDB,
    SessionResponse,
    SessionTimelineResponse,
    SessionTimelineItem
)
from backend.app.models.telemetry import TelemetryEventDB, TelemetryEventResponse
from backend.app.services.correlation import correlate_events

router = APIRouter(tags=["Attack Sessions"])

def format_session_response(sess: InvestigationSessionDB) -> SessionResponse:
    duration = 0.0
    if sess.first_seen and sess.last_seen:
        duration = max(0.0, (sess.last_seen - sess.first_seen).total_seconds())

    return SessionResponse(
        id=sess.id,
        session_id=sess.session_id,
        first_seen=sess.first_seen,
        last_seen=sess.last_seen,
        duration_seconds=duration,
        source_ip=sess.source_ip,
        honeypot_id=sess.honeypot_id,
        username=sess.username,
        event_count=sess.event_count or 0,
        observed_event_types=sess.observed_event_types or [],
        associated_mitre_techniques=sess.associated_mitre_techniques or [],
        correlation_method=sess.correlation_method or "explicit_session_id",
        status=sess.status or "active",
        flagged_sequences=sess.flagged_sequences or [],
        associated_event_ids=sess.associated_event_ids or []
    )

@router.get("/sessions", response_model=List[SessionResponse])
def list_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    source_ip: Optional[str] = Query(None, description="Filter by adversary source IP"),
    status: Optional[str] = Query(None, description="Filter by status (active, flagged, closed)"),
    min_events: Optional[int] = Query(None, description="Minimum number of events in session"),
    flagged_only: bool = Query(False, description="Filter only sessions with flagged investigation leads"),
    db: Session = Depends(get_db)
):
    """
    List correlated attack/investigation sessions with filtering and pagination.
    """
    query = db.query(InvestigationSessionDB)

    if source_ip:
        query = query.filter(InvestigationSessionDB.source_ip == source_ip.strip())
    if status:
        query = query.filter(InvestigationSessionDB.status == status.strip())
    if min_events is not None:
        query = query.filter(InvestigationSessionDB.event_count >= min_events)
    if flagged_only:
        query = query.filter(InvestigationSessionDB.status == "flagged")

    sessions = query.order_by(InvestigationSessionDB.last_seen.desc()).offset(skip).limit(limit).all()
    return [format_session_response(s) for s in sessions]

@router.get("/sessions/{session_id}", response_model=SessionResponse)
def get_session(session_id: str, db: Session = Depends(get_db)):
    """
    Retrieve details of a single correlated investigation session.
    """
    session = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.session_id == session_id
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation session '{session_id}' not found."
        )

    return format_session_response(session)

@router.get("/sessions/{session_id}/events", response_model=List[TelemetryEventResponse])
def get_session_events(session_id: str, db: Session = Depends(get_db)):
    """
    Retrieve all associated telemetry events for a specific session ordered chronologically.
    """
    session = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.session_id == session_id
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation session '{session_id}' not found."
        )

    # Fetch events either by session_id column or by associated_event_ids list
    query = db.query(TelemetryEventDB).filter(
        (TelemetryEventDB.session_id == session_id) |
        (TelemetryEventDB.event_id.in_(session.associated_event_ids or []))
    )

    return query.order_by(TelemetryEventDB.timestamp.asc()).all()

@router.get("/sessions/{session_id}/timeline", response_model=SessionTimelineResponse)
def get_session_timeline(session_id: str, db: Session = Depends(get_db)):
    """
    Retrieve structured chronological timeline of events for an investigation session.
    """
    session = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.session_id == session_id
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation session '{session_id}' not found."
        )

    events = db.query(TelemetryEventDB).filter(
        (TelemetryEventDB.session_id == session_id) |
        (TelemetryEventDB.event_id.in_(session.associated_event_ids or []))
    ).order_by(TelemetryEventDB.timestamp.asc()).all()

    first_time = session.first_seen or (events[0].timestamp if events else datetime.utcnow())
    last_time = session.last_seen or (events[-1].timestamp if events else datetime.utcnow())
    duration = max(0.0, (last_time - first_time).total_seconds())

    # Map flagged sequence events to markers
    event_markers: Dict[str, List[str]] = {}
    for seq in (session.flagged_sequences or []):
        for eid in seq.get("supporting_event_ids", []):
            if eid not in event_markers:
                event_markers[eid] = []
            event_markers[eid].append(seq.get("title", seq.get("rule_id", "Flagged Lead")))

    timeline_items: List[SessionTimelineItem] = []
    for ev in events:
        ev_time = ev.timestamp or first_time
        offset = max(0.0, (ev_time - first_time).total_seconds())
        timeline_items.append(SessionTimelineItem(
            event_id=ev.event_id,
            timestamp=ev_time,
            offset_seconds=round(offset, 2),
            event_type=ev.event_type,
            source_ip=ev.source_ip,
            destination_ip=ev.destination_ip,
            destination_port=ev.destination_port,
            protocol=ev.protocol,
            honeypot_id=ev.honeypot_id,
            username=ev.username,
            payload=ev.payload,
            data_origin=ev.data_origin or "real",
            mitre_technique_id=ev.mitre_technique_id,
            mitre_technique_name=ev.mitre_technique_name,
            mitre_tactic=ev.mitre_tactic,
            severity=ev.severity or "medium",
            sequence_markers=event_markers.get(ev.event_id, [])
        ))

    return SessionTimelineResponse(
        session_id=session.session_id,
        first_seen=first_time,
        last_seen=last_time,
        duration_seconds=round(duration, 2),
        total_events=len(timeline_items),
        source_ip=session.source_ip,
        honeypot_id=session.honeypot_id,
        timeline=timeline_items,
        flagged_sequences=session.flagged_sequences or []
    )

@router.post("/correlation/run")
def run_correlation(
    window_minutes: int = Query(30, ge=1, le=1440, description="Correlation window in minutes"),
    db: Session = Depends(get_db)
):
    """
    Triggers the correlation engine across stored telemetry events and updates investigation sessions.
    """
    try:
        result = correlate_events(db, window_minutes=window_minutes)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation engine error: {str(e)}"
        )

from backend.app.services.correlation import analyze_session_attack_sequence

@router.get("/sessions/{session_id}/attack-sequence", response_model=Dict[str, Any])
def get_session_attack_sequence(session_id: str, db: Session = Depends(get_db)):
    """
    Returns structured multi-stage attack sequence analysis for a correlated session.
    Explains event ordering, identified lifecycle stages, missing stages, and correlation rationale.
    """
    result = analyze_session_attack_sequence(session_id, db)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation session '{session_id}' not found."
        )
    return result
