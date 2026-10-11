from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.models.alert import AlertDB, AlertResponse, AlertUpdate, AlertDetectResponse
from app.services.alerts import detect_explainable_alerts

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
@router.get("/", response_model=List[AlertResponse], include_in_schema=False)
def get_alerts(
    skip: int = Query(0, ge=0, description="Offset records"),
    limit: int = Query(50, ge=1, le=200, description="Max records to return"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, RESOLVED"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    unresolved_only: bool = Query(False, description="Filter only unresolved alerts (backward compatibility)"),
    db: Session = Depends(get_db)
):
    """
    List explainable security alerts with filtering, search, and pagination.
    """
    query = db.query(AlertDB)

    if unresolved_only:
        query = query.filter(AlertDB.is_resolved == False)
    if severity:
        query = query.filter(func.lower(AlertDB.severity) == severity.lower())
    if status:
        query = query.filter(AlertDB.status == status.upper())
    if source_ip:
        query = query.filter(AlertDB.source_ip == source_ip)
    if session_id:
        query = query.filter(AlertDB.session_id == session_id)

    alerts = query.order_by(desc(AlertDB.timestamp)).offset(skip).limit(limit).all()
    return alerts

@router.get("/metrics", response_model=Dict[str, Any])
def get_alert_metrics(db: Session = Depends(get_db)):
    """
    Get live statistical metrics of stored security alerts.
    """
    total = db.query(func.count(AlertDB.id)).scalar() or 0
    new_count = db.query(func.count(AlertDB.id)).filter(AlertDB.status == "NEW").scalar() or 0
    investigating_count = db.query(func.count(AlertDB.id)).filter(AlertDB.status == "INVESTIGATING").scalar() or 0
    resolved_count = db.query(func.count(AlertDB.id)).filter(
        or_(AlertDB.status == "RESOLVED", AlertDB.is_resolved == True)
    ).scalar() or 0

    # Severity distribution
    sev_q = db.query(AlertDB.severity, func.count(AlertDB.id)).group_by(AlertDB.severity).all()
    by_severity = {row[0]: row[1] for row in sev_q if row[0]}

    # Rule distribution
    rule_q = db.query(AlertDB.detection_rule_id, func.count(AlertDB.id)).group_by(AlertDB.detection_rule_id).all()
    by_rule = {row[0]: row[1] for row in rule_q if row[0]}

    # Recent activity
    recent = db.query(AlertDB).order_by(desc(AlertDB.timestamp)).limit(5).all()
    recent_activity = [
        {
            "alert_id": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "source_ip": a.source_ip
        }
        for a in recent
    ]

    return {
        "total_alerts": total,
        "new_alerts": new_count,
        "investigating_alerts": investigating_count,
        "resolved_alerts": resolved_count,
        "alerts_by_severity": by_severity,
        "alerts_by_rule": by_rule,
        "recent_alert_activity": recent_activity
    }

@router.post("/detect", response_model=AlertDetectResponse)
def trigger_alert_detection(db: Session = Depends(get_db)):
    """
    Run the explainable alert detection engine across all sessions and events.
    Applies deduplication and updates existing alerts if evidence changed.
    """
    return detect_explainable_alerts(db)

def _find_alert(db: Session, alert_id: str) -> Optional[AlertDB]:
    if alert_id.isdigit():
        return db.query(AlertDB).filter(or_(AlertDB.alert_id == alert_id, AlertDB.id == int(alert_id))).first()
    return db.query(AlertDB).filter(AlertDB.alert_id == alert_id).first()

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """
    Get detailed evidence and explainability report for a specific alert.
    """
    alert = _find_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(alert_id: str, update_data: AlertUpdate, db: Session = Depends(get_db)):
    """
    Update alert status (NEW, INVESTIGATING, RESOLVED).
    Synchronizes is_resolved flag accordingly.
    """
    alert = _find_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    if update_data.status is not None:
        status_upper = update_data.status.upper()
        if status_upper not in ["NEW", "INVESTIGATING", "RESOLVED"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid status. Must be 'NEW', 'INVESTIGATING', or 'RESOLVED'"
            )
        alert.status = status_upper
        alert.is_resolved = (status_upper == "RESOLVED")

    if update_data.is_resolved is not None:
        alert.is_resolved = update_data.is_resolved
        if update_data.is_resolved:
            alert.status = "RESOLVED"
        elif alert.status == "RESOLVED":
            alert.status = "INVESTIGATING"

    db.commit()
    db.refresh(alert)
    return alert

@router.patch("/{alert_id}/resolve", response_model=AlertResponse, include_in_schema=False)
def resolve_alert_legacy(alert_id: str, db: Session = Depends(get_db)):
    """
    Backward-compatible resolve route.
    """
    alert = _find_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    alert.status = "RESOLVED"
    db.commit()
    db.refresh(alert)
    return alert
