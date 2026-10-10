from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from backend.app.database import get_db
from backend.app.models.telemetry import (
    TelemetryEventCreate,
    TelemetryEventResponse,
    TelemetryEventDB
)
from backend.app.services.ingestion import ingest_telemetry_event
from backend.seed_demo_telemetry import seed_synthetic_telemetry

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])

@router.post("/", response_model=TelemetryEventResponse, status_code=status.HTTP_201_CREATED)
def create_telemetry_event(payload: TelemetryEventCreate, db: Session = Depends(get_db)):
    """
    Ingest a new honeynet telemetry event with duplicate handling.
    """
    try:
        event, _ = ingest_telemetry_event(payload, db)
        return event
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to ingest event: {str(e)}")

@router.get("/", response_model=List[TelemetryEventResponse])
def get_telemetry_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    session_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    data_origin: Optional[str] = None,
    honeypot_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Query ingested honeynet events with filters, search, and pagination.
    """
    query = db.query(TelemetryEventDB)
    if session_id:
        query = query.filter(TelemetryEventDB.session_id == session_id.strip())
    if source_ip:
        query = query.filter(TelemetryEventDB.source_ip == source_ip.strip())
    if event_type:
        query = query.filter(TelemetryEventDB.event_type == event_type.strip())
    if data_origin:
        query = query.filter(TelemetryEventDB.data_origin == data_origin.strip())
    if honeypot_id:
        query = query.filter(TelemetryEventDB.honeypot_id == honeypot_id.strip())
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                TelemetryEventDB.source_ip.ilike(search_term),
                TelemetryEventDB.event_type.ilike(search_term),
                TelemetryEventDB.username.ilike(search_term),
                TelemetryEventDB.payload.ilike(search_term),
                TelemetryEventDB.mitre_technique_id.ilike(search_term)
            )
        )

    return query.order_by(TelemetryEventDB.timestamp.desc()).offset(skip).limit(limit).all()

@router.post("/seed")
def seed_telemetry():
    """
    Seed reproducible synthetic honeynet observations for demonstration.
    """
    seed_synthetic_telemetry()
    return {"message": "Synthetic demo telemetry successfully verified/seeded."}
