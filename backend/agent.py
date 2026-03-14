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

# ── Model ──────────────────────────────────
model = OpenAIModel(
    "gpt-4o-mini",                    
    provider=OpenAIProvider(
        api_key=os.environ.get("OPENAI_API_KEY", "not-needed"),
    )
)

# (vLLM)
# model = OpenAIModel(
#     "Qwen2.5-7B-Instruct",        # given
#     provider=OpenAIProvider(
#         base_url="http://localhost:8000/v1",  # given
#         api_key="not-needed",
#     )
# )

mcp = MCPServerStdio("python", args=["mcp_server.py"])

# ── Agent ──────────────────────────────────
agent = Agent(
    model,
    output_type=AgentResponse,
    mcp_servers=[mcp],
    system_prompt="""You are SENTINEL, a senior SOC analyst at an engineering company.
    Available tools:
    - lookup_ip_reputation: check if an IP is malicious
    - search_system_logs: search SIEM/EDR logs
    - get_asset_details: look up device info by IP
    - get_threat_feed (MCP): check active threat campaigns  ← new
    - search_firewall_logs (MCP): raw firewall log search   ← new
    - get_user_activity (MCP): investigate a user account   ← new

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

    instrument=True,
)

# Register tools
agent.tool_plain(lookup_ip_reputation)
agent.tool_plain(search_system_logs)
agent.tool_plain(get_asset_details)


# ── Session store with expiry after 1 hour ──────────────────────────
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


# ── Main run function ──────────────────────
async def run_triage(message: str, session_id: str) -> dict:
    history = store.get(session_id)

    # ── Drift check BEFORE running the agent ──
    drift_detected = _check_input_drift(message)
    if drift_detected:
        logfire.warn(
            "input_drift_detected",
            query=message,
            session_id=session_id,
        )
        print(f"[DRIFT] Out-of-distribution query detected: {message[:50]}")

    with logfire.span("threat_triage", session_id=session_id, query=message):
        async with agent.run_mcp_servers():
            result = await agent.run(
                message,
                message_history=history,
            )

            store.save(session_id, result.all_messages())

            # ── Artifact Logging ──────────────────
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

                # Also log to Logfire so it appears in the dashboard
                # logfire.info(
                #     "artifact_saved",
                #     incident_id=artifact["report"]["incident_id"],
                #     severity=artifact["report"]["severity"],
                #     filename=filename,
                # )

                logfire.configure(
                    service_name="cybersentinel",
                    send_to_logfire=False,        # don't send to cloud
                    trace_sample_rate=1.0,
                )
            # ── End Artifact Logging ──────────────

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

def _check_input_drift(query: str) -> bool:
    """
    Lightweight input distribution check.
    
    Returns True if the query looks OUT of distribution —
    meaning it doesn't look like a security-related question.
    
    In production: replace with embedding distance comparison
    against a reference dataset of normal security queries.
    
    Returns:
        True  = drift detected (query is suspicious / off-topic)
        False = query looks normal for this system
    """
    # Rule 1: too short to be a real security query
    if len(query.strip()) < 10:
        return True

    # Rule 2: no security keywords present
    query_lower = query.lower()
    has_security_context = any(
        keyword in query_lower 
        for keyword in SECURITY_KEYWORDS
    )
    if not has_security_context:
        return True

    # Rule 3: looks like a test or nonsense input
    nonsense_patterns = ["hello", "test", "hi ", "hey ", "what is", "who are"]
    is_nonsense = any(query_lower.startswith(p) for p in nonsense_patterns)
    if is_nonsense:
        return True

    return False  # looks like a legitimate security query