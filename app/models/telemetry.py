from datetime import datetime, timezone
import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from backend.app.database import Base
from pydantic import BaseModel, Field, model_validator

# SQLAlchemy DB Model
class TelemetryEventDB(Base):
    __tablename__ = "telemetry_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    session_id = Column(String(64), index=True, nullable=True)
    honeypot_id = Column(String(64), index=True, nullable=True, default="sensor-default")
    honeypot_type = Column(String(32), index=True, nullable=True, default="generic")
    source_ip = Column(String(64), index=True, nullable=False)
    source_port = Column(Integer, nullable=True, default=0)
    destination_ip = Column(String(64), nullable=True, default="10.0.0.1")
    destination_port = Column(Integer, nullable=True, default=0)
    protocol = Column(String(16), nullable=True, default="TCP")
    event_type = Column(String(64), index=True, nullable=False)
    username = Column(String(64), index=True, nullable=True)
    payload = Column(Text, nullable=True)
    data_origin = Column(String(16), default="real", index=True, nullable=False)
    
    # MITRE ATT&CK Attribution
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(128), nullable=True)
    mitre_tactic = Column(String(64), nullable=True, index=True)
    confidence_score = Column(Float, default=0.0)
    severity = Column(String(16), default="medium")

# Pydantic Schemas
class TelemetryEventCreate(BaseModel):
    event_id: Optional[str] = Field(None, description="Unique event identifier (auto-generated if omitted)")
    timestamp: Optional[datetime] = Field(None, description="Timestamp in UTC")
    session_id: Optional[str] = Field(None, description="Session identifier for multi-step tracking")
    honeypot_id: Optional[str] = Field("sensor-default", description="Sensor or honeypot identifier")
    honeypot_type: Optional[str] = Field("generic", description="e.g. ssh, rdp, http, smb, scada, network")
    source_ip: str = Field(..., description="Source IP address of event or observer")
    source_port: Optional[int] = Field(0, ge=0, le=65535, description="Source port number")
    destination_ip: Optional[str] = Field("10.0.0.1", description="Destination IP address")
    destination_port: Optional[int] = Field(0, ge=0, le=65535, description="Destination port number")
    protocol: Optional[str] = Field("TCP", description="Network protocol: TCP, UDP, ICMP, HTTP, etc.")
    event_type: str = Field(..., description="auth_attempt, command_execution, port_scan, payload_drop, ping, etc.")
    username: Optional[str] = Field(None, description="Username associated with authentication or command")
    payload: Optional[str] = Field(None, description="Raw event details or command payload")
    raw_details: Optional[str] = Field(None, description="Alternative field for raw event details")
    data_origin: Optional[str] = Field("real", description="'real' or 'synthetic'")

    @model_validator(mode="before")
    @classmethod
    def reconcile_payload_fields(cls, values):
        if isinstance(values, dict):
            # Normalize source IP aliases
            if not values.get("source_ip") and values.get("src_ip"):
                values["source_ip"] = str(values.get("src_ip"))

            # Normalize destination IP aliases
            if not values.get("destination_ip") and values.get("dst_ip"):
                values["destination_ip"] = str(values.get("dst_ip"))

            # Normalize port aliases
            if values.get("source_port") is None and values.get("src_port") is not None:
                values["source_port"] = values.get("src_port")
            if values.get("destination_port") is None and values.get("dst_port") is not None:
                values["destination_port"] = values.get("dst_port")

            # Map raw_details, command, input, message to payload if payload is not provided
            if not values.get("payload"):
                for alt in ["command", "input", "raw_details", "message", "data"]:
                    if values.get(alt) is not None:
                        values["payload"] = str(values.get(alt))
                        break

            # Normalize data_origin
            origin = values.get("data_origin", "real")
            if origin not in ["real", "synthetic"]:
                values["data_origin"] = "real"
        return values

class TelemetryEventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: datetime
    session_id: Optional[str] = None
    honeypot_id: Optional[str] = None
    honeypot_type: Optional[str] = None
    source_ip: str
    source_port: Optional[int] = 0
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = 0
    protocol: Optional[str] = "TCP"
    event_type: str
    username: Optional[str] = None
    payload: Optional[str] = None
    data_origin: str = "real"
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    confidence_score: float = 0.0
    severity: str = "medium"

    class Config:
        from_attributes = True

class BulkTelemetryCreate(BaseModel):
    events: List[TelemetryEventCreate] = Field(..., description="List of telemetry events to ingest")

class BulkTelemetryResponse(BaseModel):
    ingested: int
    duplicates_skipped: int
    total: int
    events: List[TelemetryEventResponse]

class TelemetryStatsResponse(BaseModel):
    total_events: int
    real_events_count: int
    synthetic_events_count: int
    total_sessions: int = 0
    flagged_sessions: int = 0
    unique_source_ips: int
    unique_honeypots: int
    event_types_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]
    data_origin_breakdown: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_mitre_techniques: List[Dict[str, Any]]
    database_engine: str
