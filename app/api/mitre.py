from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional

from backend.app.database import get_db
from backend.app.models.telemetry import TelemetryEventDB
from backend.app.models.session import InvestigationSessionDB
from backend.app.models.mitre import (
    TechniqueMappingDB,
    TechniqueMappingResponse,
    TechniqueSummaryItem,
    TechniqueDetailResponse,
    MitreRunResponse
)
from backend.app.services.mitre_catalog import (
    load_mitre_catalog,
    get_technique_from_catalog,
    list_all_catalog_techniques
)
from backend.app.services.mitre import (
    run_mitre_analysis,
    evaluate_event_evidence,
    persist_event_technique_mapping,
    analyze_session_techniques
)
from backend.app.services.analysis import get_mitre_matrix_status

router = APIRouter(tags=["MITRE ATT&CK Engine"])

@router.get("/techniques", response_model=List[TechniqueSummaryItem])
def list_techniques(
    tactic: Optional[str] = Query(None, description="Filter techniques by tactic"),
    search: Optional[str] = Query(None, description="Search by ID, name, or description"),
    has_evidence: Optional[bool] = Query(None, description="Filter techniques with supporting evidence"),
    db: Session = Depends(get_db)
):
    """
    Returns the authoritative MITRE ATT&CK technique catalog enriched with
    real database evidence counts (supporting events, associated sessions, evidence strength).
    """
    catalog_items = list_all_catalog_techniques()

    # Query event counts grouped by technique
    event_counts_q = db.query(
        TelemetryEventDB.mitre_technique_id,
        func.count(TelemetryEventDB.id)
    ).filter(TelemetryEventDB.mitre_technique_id.isnot(None))\
     .group_by(TelemetryEventDB.mitre_technique_id).all()
    event_counts = {r[0]: r[1] for r in event_counts_q}

    # Query session mappings count grouped by technique
    session_counts_q = db.query(
        TechniqueMappingDB.technique_id,
        func.count(func.distinct(TechniqueMappingDB.session_id))
    ).filter(TechniqueMappingDB.scope == "session")\
     .group_by(TechniqueMappingDB.technique_id).all()
    session_counts = {r[0]: r[1] for r in session_counts_q}

    results = []
    for item in catalog_items:
        # Filtering
        if tactic and tactic.lower() != "all" and not any(t.lower() == tactic.lower() for t in item.tactics):
            continue

        if search:
            s = search.lower()
            if not (s in item.technique_id.lower() or s in item.name.lower() or s in item.description.lower()):
                continue

        ev_count = event_counts.get(item.technique_id, 0)
        sess_count = session_counts.get(item.technique_id, 0)

        # Fallback check from technique_mappings if event not direct
        if ev_count == 0:
            map_ev = db.query(func.count(TechniqueMappingDB.id)).filter(
                TechniqueMappingDB.technique_id == item.technique_id,
                TechniqueMappingDB.scope == "event"
            ).scalar() or 0
            ev_count = map_ev

        if has_evidence is True and ev_count == 0 and sess_count == 0:
            continue
        if has_evidence is False and (ev_count > 0 or sess_count > 0):
            continue

        evidence_strength = "none"
        mapping_status = "unobserved"
        if ev_count > 0 or sess_count > 0:
            mapping_status = "supported"
            evidence_strength = "high" if ev_count >= 2 else "medium"

        results.append(TechniqueSummaryItem(
            technique_id=item.technique_id,
            name=item.name,
            tactics=item.tactics,
            tactic=item.tactics[0] if item.tactics else "Discovery",
            description=item.description,
            applicable_event_evidence=item.applicable_event_evidence,
            data_source_requirements=item.data_source_requirements,
            mapping_rule_id=item.mapping_rule_id,
            supporting_events_count=ev_count,
            associated_sessions_count=sess_count,
            evidence_strength=evidence_strength,
            mapping_status=mapping_status
        ))

    return results

@router.get("/techniques/{technique_id}", response_model=TechniqueDetailResponse)
def get_technique_detail(technique_id: str, db: Session = Depends(get_db)):
    """
    Returns comprehensive details for a specific MITRE ATT&CK technique:
    official catalog definition, supporting event IDs, associated session IDs, and evidence records.
    """
    cat_item = get_technique_from_catalog(technique_id)
    if not cat_item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique '{technique_id}' is not in the MITRE ATT&CK catalog."
        )

    # Fetch supporting events
    events = db.query(TelemetryEventDB).filter(
        TelemetryEventDB.mitre_technique_id == technique_id
    ).order_by(TelemetryEventDB.timestamp.desc()).all()
    supporting_event_ids = [e.event_id for e in events]

    # Fetch mappings
    mappings = db.query(TechniqueMappingDB).filter(
        TechniqueMappingDB.technique_id == technique_id
    ).order_by(TechniqueMappingDB.created_at.desc()).all()

    # Complement supporting event IDs from mappings
    for m in mappings:
        for eid in (m.supporting_event_ids or []):
            if eid not in supporting_event_ids:
                supporting_event_ids.append(eid)

    # Associated sessions
    sessions_q = db.query(TechniqueMappingDB.session_id).filter(
        TechniqueMappingDB.technique_id == technique_id,
        TechniqueMappingDB.session_id.isnot(None)
    ).distinct().all()
    associated_sessions = [s[0] for s in sessions_q if s[0]]

    # If sessions not in mappings yet, check sessions table
    all_sessions = db.query(InvestigationSessionDB).all()
    for s in all_sessions:
        for t in (s.associated_mitre_techniques or []):
            if t.get("technique_id") == technique_id and s.session_id not in associated_sessions:
                associated_sessions.append(s.session_id)

    return TechniqueDetailResponse(
        technique_id=cat_item.technique_id,
        name=cat_item.name,
        tactics=cat_item.tactics,
        tactic=cat_item.tactics[0] if cat_item.tactics else "Discovery",
        description=cat_item.description,
        applicable_event_evidence=cat_item.applicable_event_evidence,
        data_source_requirements=cat_item.data_source_requirements,
        mapping_rule_id=cat_item.mapping_rule_id,
        supporting_events_count=len(supporting_event_ids),
        associated_sessions_count=len(associated_sessions),
        supporting_event_ids=supporting_event_ids,
        associated_sessions=associated_sessions,
        mappings=[TechniqueMappingResponse.model_validate(m) for m in mappings]
    )

@router.get("/events/{event_id}/techniques", response_model=List[TechniqueMappingResponse])
def get_event_techniques(event_id: str, db: Session = Depends(get_db)):
    """
    Returns all MITRE ATT&CK technique mappings supporting a specific telemetry event.
    Returns 404 if the event does not exist in the database.
    """
    event = db.query(TelemetryEventDB).filter(TelemetryEventDB.event_id == event_id).first()
    if not event and event_id.isdigit():
        event = db.query(TelemetryEventDB).filter(TelemetryEventDB.id == int(event_id)).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Telemetry event '{event_id}' not found."
        )

    mappings = db.query(TechniqueMappingDB).filter(
        TechniqueMappingDB.event_id == event.event_id,
        TechniqueMappingDB.scope == "event"
    ).all()

    if not mappings:
        # Attempt real-time evaluation and persistence
        m = persist_event_technique_mapping(event, db)
        if m:
            mappings = [m]

    return [TechniqueMappingResponse.model_validate(m) for m in mappings]

@router.get("/sessions/{session_id}/techniques", response_model=List[TechniqueMappingResponse])
def get_session_techniques(session_id: str, db: Session = Depends(get_db)):
    """
    Returns all aggregated MITRE ATT&CK technique mappings associated with a specific investigation session.
    Returns 404 if the session does not exist.
    """
    session = db.query(InvestigationSessionDB).filter(
        InvestigationSessionDB.session_id == session_id
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation session '{session_id}' not found."
        )

    mappings = db.query(TechniqueMappingDB).filter(
        TechniqueMappingDB.session_id == session_id,
        TechniqueMappingDB.scope == "session"
    ).all()

    if not mappings:
        # Attempt on-the-fly analysis and reload
        analyze_session_techniques(session, db)
        mappings = db.query(TechniqueMappingDB).filter(
            TechniqueMappingDB.session_id == session_id,
            TechniqueMappingDB.scope == "session"
        ).all()

    return [TechniqueMappingResponse.model_validate(m) for m in mappings]

@router.post("/analysis/mitre/run", response_model=MitreRunResponse)
def run_analysis(db: Session = Depends(get_db)):
    """
    Executes an evidence-based MITRE ATT&CK re-analysis pass across all
    events and investigation sessions in the database.
    """
    res = run_mitre_analysis(db)
    return MitreRunResponse(**res)

@router.post("/mitre/run", response_model=MitreRunResponse)
def run_analysis_alias(db: Session = Depends(get_db)):
    """Alias for POST /api/analysis/mitre/run."""
    res = run_mitre_analysis(db)
    return MitreRunResponse(**res)

@router.get("/mitre/matrix", response_model=List[Dict[str, Any]])
@router.get("/matrix", response_model=List[Dict[str, Any]])
def get_mitre_matrix(db: Session = Depends(get_db)):
    """
    Legacy endpoint returning ATT&CK technique matrix populated with detection counts.
    """
    return get_mitre_matrix_status(db)

from pydantic import BaseModel, Field
from backend.app.services.mitre_verification import (
    TechniqueVerificationResult,
    verify_technique_mapping
)

class MitreVerifyRequest(BaseModel):
    candidate_technique_id: str = Field(..., description="Proposed MITRE ATT&CK technique identifier")
    event_type: str = Field(..., description="Observed telemetry event type")
    payload: Optional[str] = Field(None, description="Observed event payload")
    username: Optional[str] = Field(None, description="Targeted or authenticated username")
    supporting_event_ids: Optional[List[str]] = Field(None, description="Event IDs supporting this mapping")
    event_count: int = Field(1, description="Number of observed occurrences in session")
    claimed_tactic: Optional[str] = Field(None, description="Optional claimed tactic to validate")

@router.post("/mitre/verify", response_model=TechniqueVerificationResult)
def verify_candidate_mapping(request: MitreVerifyRequest):
    """
    Evaluates whether a candidate MITRE ATT&CK mapping is supported by concrete telemetry evidence.
    Returns structured verification result with status: SUPPORTED, NEEDS_MORE_EVIDENCE, or REJECTED.
    """
    return verify_technique_mapping(
        candidate_technique_id=request.candidate_technique_id,
        event_type=request.event_type,
        payload=request.payload,
        username=request.username,
        supporting_event_ids=request.supporting_event_ids,
        event_count=request.event_count,
        claimed_tactic=request.claimed_tactic
    )

@router.get("/events/{event_id}/verify", response_model=TechniqueVerificationResult)
def verify_stored_event_technique(event_id: str, db: Session = Depends(get_db)):
    """
    Performs evidence-based verification of the MITRE ATT&CK technique associated with a stored event.
    """
    event = db.query(TelemetryEventDB).filter(TelemetryEventDB.event_id == event_id).first()
    if not event and event_id.isdigit():
        event = db.query(TelemetryEventDB).filter(TelemetryEventDB.id == int(event_id)).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Telemetry event '{event_id}' not found."
        )

    cand_tech = event.mitre_technique_id or "UNMAPPED"
    return verify_technique_mapping(
        candidate_technique_id=cand_tech,
        event_type=event.event_type,
        payload=event.payload,
        username=event.username,
        supporting_event_ids=[event.event_id],
        event_count=1
    )
