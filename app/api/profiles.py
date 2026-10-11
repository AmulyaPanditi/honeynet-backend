from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from app.database import get_db
from app.services.profiling import build_attacker_profile, list_attacker_profiles

router = APIRouter(tags=["Attacker Profiling"])

@router.get("/profiles", response_model=List[Dict[str, Any]])
def get_attacker_profiles(
    limit: int = Query(50, ge=1, le=200, description="Max adversary profiles to return"),
    db: Session = Depends(get_db)
):
    """
    Returns aggregated behavioral profiles for active threat actor source IPs.
    Synthesizes observed behaviors, candidate ATT&CK techniques, and security alerts.
    """
    return list_attacker_profiles(db, limit=limit)

@router.get("/profiles/{source_ip}", response_model=Dict[str, Any])
def get_single_attacker_profile(
    source_ip: str,
    db: Session = Depends(get_db)
):
    """
    Returns a detailed evidence-based threat actor profile for a specific adversary IP.
    Adheres to evidentiary boundaries regarding identity and attribution uncertainty.
    """
    profile = build_attacker_profile(source_ip, db)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No telemetry activity found for source IP '{source_ip}'."
        )
    return profile
