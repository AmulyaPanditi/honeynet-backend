from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any
from backend.app.database import get_db
from backend.app.services.analysis import get_dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/summary", response_model=Dict[str, Any])
def get_summary(db: Session = Depends(get_db)):
    """
    Get honeynet telemetry analytics and metrics computed from database.
    """
    return get_dashboard_summary(db)
