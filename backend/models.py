from pydantic import BaseModel
from typing import Optional
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IOC(BaseModel):
    type: str        # "ip", "domain", "hash", "port"
    value: str
    context: str


class ThreatReport(BaseModel):
    incident_id: str
    severity: SeverityLevel
    summary: str
    affected_assets: list[str]
    iocs: list[IOC]
    recommended_actions: list[str]
    escalate_to_human: bool
    analyst_notes: str


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

class AgentResponse(BaseModel):
    answer: str                          # short answer for follow-up questions
    report: Optional[ThreatReport] = None  # only populated for new investigations
    is_new_investigation: bool = False