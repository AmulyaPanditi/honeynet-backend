from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional, Union
from app.database import get_db
from app.models.telemetry import (
    TelemetryEventCreate,
    TelemetryEventResponse,
    TelemetryEventDB,
    BulkTelemetryCreate,
    BulkTelemetryResponse,
    TelemetryStatsResponse
)
from app.services.ingestion import ingest_telemetry_event, ingest_bulk_telemetry
from app.services.analysis import get_telemetry_stats
from app.services.event_analysis import (
    EventAnalysisResult,
    analyze_telemetry_event,
    analyze_events_batch
)

router = APIRouter(tags=["Telemetry Events"])

@router.post("/events/analyze", response_model=Union[EventAnalysisResult, List[EventAnalysisResult]])
def analyze_telemetry_endpoint(payload: Union[TelemetryEventCreate, List[TelemetryEventCreate]]):
    """
    Interprets telemetry using explicit, explainable behavioral rules without inserting duplicate database records.
    """
    if isinstance(payload, list):
        return analyze_events_batch(payload)
    return analyze_telemetry_event(payload)

@router.get("/events/{event_id}/analysis", response_model=EventAnalysisResult)
def get_event_analysis(event_id: str, db: Session = Depends(get_db)):
    """
    Retrieve explainable behavioral analysis for an existing stored telemetry event.
    """
    event = db.query(TelemetryEventDB).filter(TelemetryEventDB.event_id == event_id).first()
    if not event and event_id.isdigit():
        event = db.query(TelemetryEventDB).filter(TelemetryEventDB.id == int(event_id)).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Telemetry event '{event_id}' not found."
        )

    return analyze_telemetry_event(event)

@router.get("/events", response_model=List[TelemetryEventResponse])
def list_events(
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    data_origin: Optional[str] = Query(None, description="Filter by origin: real or synthetic"),
    honeypot_id: Optional[str] = Query(None, description="Filter by sensor ID"),
    search: Optional[str] = Query(None, description="Search keyword across IP, payload, username"),
    db: Session = Depends(get_db)
):
    """
    Retrieve stored telemetry events with pagination and filtering.
    """
    query = db.query(TelemetryEventDB)

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
                TelemetryEventDB.mitre_technique_id.ilike(search_term),
                TelemetryEventDB.honeypot_id.ilike(search_term)
            )
        )

    return query.order_by(TelemetryEventDB.timestamp.desc()).offset(skip).limit(limit).all()

@router.get("/events/{event_id}", response_model=TelemetryEventResponse)
def get_single_event(event_id: str, db: Session = Depends(get_db)):
    """
    Retrieve a specific telemetry event by its unique event_id or numeric ID.
    """
    # Check by event_id string first
    event = db.query(TelemetryEventDB).filter(TelemetryEventDB.event_id == event_id).first()
    
    # If not found and identifier is numeric, check by primary key id
    if not event and event_id.isdigit():
        event = db.query(TelemetryEventDB).filter(TelemetryEventDB.id == int(event_id)).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Telemetry event '{event_id}' not found."
        )

    return event

import secrets
from fastapi import Header
from app.config import settings

def verify_sensor_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """
    Optional authentication for sensor telemetry ingestion.
    - If API_KEY is configured in settings/environment, strictly requires and validates matching X-API-Key header.
    - Missing key -> HTTP 401 Unauthorized
    - Invalid key -> HTTP 403 Forbidden
    - Uses constant-time comparison (secrets.compare_digest).
    - If API_KEY is unset or empty, allows unauthenticated ingestion for local development mode.
    """
    configured_key = (settings.API_KEY or "").strip()
    if not configured_key:
        return True  # Dev mode: open

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: missing X-API-Key header."
        )

    if not secrets.compare_digest(x_api_key.strip(), configured_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: invalid API key."
        )

    return True

@router.post("/events", response_model=TelemetryEventResponse, status_code=status.HTTP_201_CREATED)
def create_single_event(
    payload: TelemetryEventCreate,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_sensor_api_key)
):
    """
    Validates and stores a telemetry event. Safely handles duplicate event IDs.
    """
    try:
        event_obj, is_duplicate = ingest_telemetry_event(payload, db)
        return event_obj
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to ingest event: {str(e)}"
        )

@router.post("/events/bulk", response_model=BulkTelemetryResponse, status_code=status.HTTP_201_CREATED)
def create_bulk_events(
    payload: Union[BulkTelemetryCreate, List[TelemetryEventCreate]],
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_sensor_api_key)
):
    """
    Safely ingests multiple telemetry events in bulk, gracefully skipping duplicates.
    """
    events_list = payload.events if isinstance(payload, BulkTelemetryCreate) else payload
    if not events_list:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No events provided for ingestion.")

    try:
        result = ingest_bulk_telemetry(events_list, db)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk ingestion failed: {str(e)}"
        )

@router.get("/stats", response_model=TelemetryStatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """
    Calculate telemetry and honeynet statistics directly from stored database records.
    """
    return get_telemetry_stats(db)
