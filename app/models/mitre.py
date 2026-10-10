from datetime import datetime, timezone
import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.app.database import Base
from pydantic import BaseModel, Field
from backend.app.services.mitre_catalog import TechniqueCatalogItem

# SQLAlchemy Table for Stored Evidence-Based MITRE ATT&CK Mappings
class TechniqueMappingDB(Base):
    __tablename__ = "technique_mappings"

    id = Column(Integer, primary_key=True, index=True)
    mapping_id = Column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    technique_id = Column(String(32), index=True, nullable=False)
    technique_name = Column(String(128), nullable=False)
    tactic = Column(String(64), index=True, nullable=False)
    scope = Column(String(16), index=True, default="event") # "event" or "session"
    event_id = Column(String(64), index=True, nullable=True)
    session_id = Column(String(64), index=True, nullable=True)
    supporting_event_ids = Column(JSON, default=list)
    supporting_event_fields = Column(JSON, default=dict)
    mapping_rule = Column(String(64), nullable=False)
    explanation = Column(Text, nullable=False)
    mapping_status = Column(String(32), default="supported", index=True) # supported, suggested, insufficient_evidence, unmapped
    evidence_strength = Column(String(16), default="medium") # high, medium, low
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

# Pydantic Schemas
class TechniqueMappingResponse(BaseModel):
    id: int
    mapping_id: str
    technique_id: str
    technique_name: str
    tactic: str
    scope: str
    event_id: Optional[str] = None
    session_id: Optional[str] = None
    supporting_event_ids: List[str] = Field(default_factory=list)
    supporting_event_fields: Dict[str, Any] = Field(default_factory=dict)
    mapping_rule: str
    explanation: str
    mapping_status: str
    evidence_strength: str
    created_at: datetime

    class Config:
        from_attributes = True

class TechniqueSummaryItem(BaseModel):
    technique_id: str
    name: str
    tactics: List[str]
    tactic: str # Primary tactic for backward compatibility
    description: str
    applicable_event_evidence: str
    data_source_requirements: List[str]
    mapping_rule_id: str
    supporting_events_count: int = 0
    associated_sessions_count: int = 0
    evidence_strength: str = "none" # high, medium, low, none
    mapping_status: str = "unobserved" # supported, suggested, unobserved

class TechniqueDetailResponse(BaseModel):
    technique_id: str
    name: str
    tactics: List[str]
    tactic: str
    description: str
    applicable_event_evidence: str
    data_source_requirements: List[str]
    mapping_rule_id: str
    supporting_events_count: int
    associated_sessions_count: int
    supporting_event_ids: List[str]
    associated_sessions: List[str]
    mappings: List[TechniqueMappingResponse]

class MitreRunResponse(BaseModel):
    evaluated_events: int
    mapped_events: int
    unmapped_events: int
    evaluated_sessions: int
    session_techniques_mapped: int
    message: str
