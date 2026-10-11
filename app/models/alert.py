from datetime import datetime, timezone
import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON
from app.database import Base
from pydantic import BaseModel, Field

class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    session_id = Column(String(64), index=True, nullable=True)
    source_ip = Column(String(64), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    threat_actor_cluster = Column(String(64), index=True, nullable=True)
    primary_technique_id = Column(String(32), index=True, nullable=True)
    severity = Column(String(16), default="high", index=True) # critical, high, medium, low
    status = Column(String(32), default="NEW", index=True) # NEW, INVESTIGATING, RESOLVED
    is_resolved = Column(Boolean, default=False, index=True)
    
    # Explainable Evidence Fields
    detection_rule_id = Column(String(64), index=True, nullable=True)
    related_event_ids = Column(JSON, default=list)
    related_technique_ids = Column(JSON, default=list)
    supporting_evidence = Column(JSON, default=dict)
    explanation = Column(Text, nullable=True)
    severity_rationale = Column(Text, nullable=True)
    fingerprint = Column(String(128), index=True, nullable=True) # Prevents duplicate alerts on repeated detection
    data_origin = Column(String(16), default="real", index=True)

class AlertResponse(BaseModel):
    id: int
    alert_id: str
    timestamp: datetime
    session_id: Optional[str] = None
    source_ip: str
    title: str
    description: str
    threat_actor_cluster: Optional[str] = None
    primary_technique_id: Optional[str] = None
    severity: str = "high"
    status: str = "NEW"
    is_resolved: bool = False
    detection_rule_id: Optional[str] = None
    related_event_ids: List[str] = Field(default_factory=list)
    related_technique_ids: List[str] = Field(default_factory=list)
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    explanation: Optional[str] = None
    severity_rationale: Optional[str] = None
    data_origin: str = "real"

    class Config:
        from_attributes = True

class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, description="'NEW', 'INVESTIGATING', or 'RESOLVED'")
    is_resolved: Optional[bool] = Field(None, description="Direct resolution flag")
    resolution_notes: Optional[str] = Field(None, description="Optional investigative notes")

class AlertDetectResponse(BaseModel):
    evaluated_sessions: int
    evaluated_events: int
    new_alerts_created: int
    existing_alerts_updated: int
    total_active_alerts: int
    message: str
