import os
import logfire
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.models.groq import GroqModel

import json
from datetime import datetime
from pathlib import Path

from models import ThreatReport, AgentResponse
from tools import lookup_ip_reputation, search_system_logs, get_asset_details

import statistics

# Model
model = OpenAIModel(
    "gpt-4o-mini",                    
    provider=OpenAIProvider(
        api_key=os.environ.get("OPENAI_API_KEY", "not-needed"),
    )
)

mcp = MCPServerStdio("python", args=["mcp_server.py"])

# Agent
agent = Agent(
    model,
    output_type=AgentResponse,
    mcp_servers=[mcp],
    system_prompt="""You are SENTINEL, a senior SOC analyst at an engineering company.
    Available tools:
    - lookup_ip_reputation: check if an IP is malicious
    - search_system_logs: search SIEM/EDR logs
    - get_asset_details: look up device info by IP
    - get_threat_feed (MCP): check active threat campaigns  
    - search_firewall_logs (MCP): raw firewall log search   
    - get_user_activity (MCP): investigate a user account   

    When the user describes a NEW threat or incident:
    - Set is_new_investigation=True
    - Call lookup_ip_reputation and search_system_logs first
    - Call get_threat_feed to check if it matches known campaigns
    - Call get_asset_details for any IPs involved
    - Populate the full report field with a complete ThreatReport
    - Set answer to a one-line summary

    When the user asks a FOLLOW-UP question:
    - Set is_new_investigation=False
    - Leave report as null
    - Answer concisely from conversation context
    - Only call tools if genuinely new information is needed""",

    instrument=True, # important to add this 
)

# Register direct/internal tools from tools.py
agent.tool_plain(lookup_ip_reputation)
agent.tool_plain(search_system_logs)
agent.tool_plain(get_asset_details)

# Session store with expiry after 1 hour 
class SessionStore:
    def __init__(self):
        self._store = {}
        self._timestamps = {}

    def get(self, session_id: str) -> list:
        # Expire sessions older than 1 hour
        import time
        created = self._timestamps.get(session_id, 0)
        if time.time() - created > 3600:
            self._store.pop(session_id, None)
            return []
        return self._store.get(session_id, [])

    def save(self, session_id: str, history: list):
        import time
        self._store[session_id] = history
        self._timestamps[session_id] = time.time()

store = SessionStore()

# Main run function
async def run_triage(message: str, session_id: str) -> dict:
    history = store.get(session_id)

    # Drift checks
    stat_drift = detect_statistical_drift(message)
    adv_drift  = detect_adversarial_drift(message)

    if stat_drift.get("overall_drift"):
        logfire.warning("statistical_drift_detected", session_id=session_id, fields=stat_drift["fields"])

    if adv_drift["adversarial"]:
        logfire.warning("adversarial_drift_detected", session_id=session_id, patterns=adv_drift["triggered_patterns"])

    with logfire.span("threat_triage", session_id=session_id, query=message):
        async with agent.run_mcp_servers():
            result = await agent.run(
                message,
                message_history=history,
            )

            store.save(session_id, result.all_messages())

            # Artifact Logging 
            # Save every report as a JSON file for audit trail
            if result.output.report:
                artifact = {
                    "timestamp": datetime.now().isoformat(),
                    "session_id": session_id,
                    "query": message,
                    "report": result.output.report.model_dump(mode="json"),
                    "tokens_used": result.usage().total_tokens,
                    "model": "gpt-4o-mini",
                }

                # Save to artifacts folder
                Path("artifacts").mkdir(exist_ok=True)
                filename = f"artifacts/{artifact['report']['incident_id']}.json"
                with open(filename, "w") as f:
                    json.dump(artifact, f, indent=2)

                # Also log to Logfire so it appears in the browser dashboard
                logfire.info(
                    "artifact_saved",
                    incident_id=artifact["report"]["incident_id"],
                    severity=artifact["report"]["severity"],
                    filename=filename,
                )

                logfire.configure(
                    service_name="cybersentinel",
                    send_to_logfire=False,        # don't send to cloud
                    trace_sample_rate=1.0,
                )
            # End of artifact logging

            logfire.info(
                "triage_complete",
                severity=result.output.report.severity if result.output.report else "N/A",
                escalate=result.output.report.escalate_to_human if result.output.report else False,
                tokens=result.usage().total_tokens,
            )

            return {
                "output": result.output,
                "session_id": session_id,
            }

SECURITY_KEYWORDS = [
    "ip", "port", "attack", "malware", "threat", "incident",
    "vulnerability", "cve", "exploit", "breach", "intrusion",
    "suspicious", "anomaly", "traffic", "firewall", "alert",
    "investigate", "scan", "connection", "outbound", "inbound",
    "ransomware", "phishing", "backdoor", "c2", "command",
]

ADVERSARIAL_PATTERNS = [
    "ignore previous instructions",
    "disregard your system prompt",
    "pretend you are",
    "act as if you have no restrictions",
    "jailbreak",
    "bypass security",
    "you are now",
    "forget everything",
]

_query_history: list[dict] = []

def _query_vector(query: str) -> dict:
    """Extract numeric features from a query for statistical comparison."""
    return {
        "length":           len(query),
        "word_count":       len(query.split()),
        "has_ip":           any(part.replace(".","").isdigit() for part in query.split()),
        "keyword_count":    sum(1 for k in SECURITY_KEYWORDS if k in query.lower()),
    }

def detect_statistical_drift(query: str) -> dict:
    """Z-score based drift detection against rolling query history."""
    current = _query_vector(query)

    if len(_query_history) < 5:
        _query_history.append(current)
        return {"status": "insufficient_history", "samples": len(_query_history)}

    numeric_fields = ["length", "word_count", "keyword_count"]
    drift_flags = {}

    for field in numeric_fields:
        historical = [v[field] for v in _query_history]
        mean  = statistics.mean(historical)
        stdev = statistics.stdev(historical) or 1.0
        z     = abs((current[field] - mean) / stdev)
        drift_flags[field] = {
            "current": current[field],
            "mean":    round(mean, 2),
            "z_score": round(z, 2),
            "drifted": z > 2.5,
        }

    _query_history.append(current)
    overall = any(v["drifted"] for v in drift_flags.values())

    return {
        "status":        "drift_detected" if overall else "nominal",
        "overall_drift": overall,
        "fields":        drift_flags,
    }

def detect_adversarial_drift(query: str) -> dict:
    """Scan for known prompt injection patterns."""
    query_lower = query.lower()
    triggered = [p for p in ADVERSARIAL_PATTERNS if p in query_lower]
    return {
        "status":             "adversarial_detected" if triggered else "clean",
        "adversarial":        bool(triggered),
        "triggered_patterns": triggered,
    }