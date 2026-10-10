from datetime import datetime, timezone
import json
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON
from backend.app.database import Base
from pydantic import BaseModel, Field

# SQLAlchemy Model for Correlated Investigation Sessions
class InvestigationSessionDB(Base):
    __tablename__ = "investigation_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(64), index=True, nullable=True)
    honeypot_id = Column(String(64), index=True, nullable=True)
    username = Column(String(64), index=True, nullable=True)
    event_count = Column(Integer, default=0)
    
    # JSON-serializable summaries
    observed_event_types = Column(JSON, default=list)
    associated_mitre_techniques = Column(JSON, default=list)
    correlation_method = Column(String(64), default="explicit_session_id")
    status = Column(String(32), default="active", index=True) # active, closed, flagged
    flagged_sequences = Column(JSON, default=list)
    associated_event_ids = Column(JSON, default=list)

# Pydantic Schemas
class FlaggedSequenceLead(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Brief human-readable sequence title")
    explanation: str = Field(..., description="Transparent reasoning regarding why this sequence is flagged as an investigation lead")
    supporting_event_ids: List[str] = Field(default_factory=list, description="IDs of events forming this sequence")
    timestamps: List[str] = Field(default_factory=list, description="Timestamps of the sequence events")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Concrete evidence fields used by the rule")

class SessionResponse(BaseModel):
    id: int
    session_id: str
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float = 0.0
    source_ip: Optional[str] = None
    honeypot_id: Optional[str] = None
    username: Optional[str] = None
    event_count: int = 0
    observed_event_types: List[str] = Field(default_factory=list)
    associated_mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_method: str = "explicit_session_id"
    status: str = "active"
    flagged_sequences: List[FlaggedSequenceLead] = Field(default_factory=list)
    associated_event_ids: List[str] = Field(default_factory=list)

    class Config:
        from_attributes = True

class SessionTimelineItem(BaseModel):
    event_id: str
    timestamp: datetime
    offset_seconds: float
    event_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    honeypot_id: Optional[str] = None
    username: Optional[str] = None
    payload: Optional[str] = None
    data_origin: str = "real"
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    severity: str = "medium"
    sequence_markers: List[str] = Field(default_factory=list)

class SessionTimelineResponse(BaseModel):
    session_id: str
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    total_events: int
    source_ip: Optional[str] = None
    honeypot_id: Optional[str] = None
    timeline: List[SessionTimelineItem]
    flagged_sequences: List[FlaggedSequenceLead]
