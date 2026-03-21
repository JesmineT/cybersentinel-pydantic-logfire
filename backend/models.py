from pydantic import BaseModel
from typing import Optional
from enum import Enum

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class IOC(BaseModel):
    type: str       # "ip", "domain", "hash", "port"
    value: str      # basically value of ip/domain/hash/port
    context: str    # source device/external c2 server - an attacker-controlled machine, located outside network

class ThreatReport(BaseModel):
    incident_id: str
    severity: SeverityLevel
    summary: str
    affected_assets: list[str]
    iocs: list[IOC]
    recommended_actions: list[str]
    escalate_to_human: bool
    analyst_notes: str

class ChatRequest(BaseModel): # shape of what frontend sends to backend.
    message: str                # what the user typed
    session_id: Optional[str] = None # which conversation this belongs to

class AgentResponse(BaseModel): # shape of what backend sents to frontend
    answer: str                          #  what the agent always says in plain English, short or long.
    report: Optional[ThreatReport] = None # the full structured incident report, only when a new investigation happened.
    is_new_investigation: bool = False # a flag telling the frontend which type of response this is.