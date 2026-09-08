from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import uuid

class FlowID(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

class Evidence(BaseModel):
    features: Dict[str, Any]
    explanation: str
    window_start: Optional[float] = None
    window_end: Optional[float] = None

class AlertRecord(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float
    detector: str
    flow_id: FlowID
    threat_class: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score: float
    evidence: Evidence
    related_alert_ids: List[str] = Field(default_factory=list)
