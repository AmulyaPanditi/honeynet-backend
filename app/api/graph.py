from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from datetime import datetime

from backend.app.database import get_db
from backend.app.services.graph import build_investigation_graph, generate_causal_graph

router = APIRouter(tags=["Investigation Graph"])

@router.get("/graph", response_model=Dict[str, Any])
def get_investigation_graph_data(
    session_id: Optional[str] = Query(None, description="Filter graph by correlated session ID"),
    source_ip: Optional[str] = Query(None, description="Filter graph by adversary IP address"),
    technique_id: Optional[str] = Query(None, description="Filter graph by MITRE ATT&CK technique ID"),
    start_time: Optional[datetime] = Query(None, description="Filter events after start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before end timestamp"),
    limit: int = Query(100, ge=1, le=500, description="Max telemetry events to include"),
    db: Session = Depends(get_db)
):
    """
    Returns an interactive Cytoscape.js investigation graph generated from real database records.
    Nodes: Telemetry Events, Correlated Sessions, MITRE Techniques, Security Alerts, Attacker IPs.
    Edges: Evidence-backed relationships (BELONGS_TO, SUPPORTS_TECHNIQUE, CONTAINS_TECHNIQUE, ALERTS_ON_SESSION, PRECEDES).
    """
    return build_investigation_graph(
        db=db,
        session_id=session_id,
        source_ip=source_ip,
        technique_id=technique_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit
    )

@router.get("/graph/causal", response_model=Dict[str, Any])
def get_causal_graph_data(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    technique_id: Optional[str] = Query(None, description="Filter by technique ID"),
    limit: int = Query(100, ge=1, le=500, description="Max events"),
    db: Session = Depends(get_db)
):
    """
    Backwards-compatible alias for /api/graph.
    """
    return build_investigation_graph(
        db=db,
        session_id=session_id,
        source_ip=source_ip,
        technique_id=technique_id,
        limit=limit
    )

@router.get("/graph/story", response_model=Dict[str, Any])
def get_graph_investigation_story(
    session_id: Optional[str] = Query(None, description="Filter story by session ID"),
    source_ip: Optional[str] = Query(None, description="Filter story by source IP"),
    limit: int = Query(100, ge=1, le=500, description="Max events"),
    db: Session = Depends(get_db)
):
    """
    Returns an explainable investigation story answering the 8 core analytical questions:
    1. First observed, 2. Next activity, 3. Related events, 4. Suspicious behaviors,
    5. ATT&CK techniques, 6. Supported/rejected mappings, 7. Alerts generated, 8. Uncertainties.
    """
    graph_data = build_investigation_graph(
        db=db,
        session_id=session_id,
        source_ip=source_ip,
        limit=limit
    )
    return graph_data.get("investigation_story", {})
