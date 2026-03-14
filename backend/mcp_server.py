from mcp.server.fastmcp import FastMCP
import json
from datetime import datetime, timedelta
import random

server = FastMCP("cybersentinel-tools")


@server.tool()
def get_threat_feed(days: int = 7) -> str:
    print(f"[MCP] get_threat_feed called -> {days} days")

    """
    Get active threat intelligence feed for the past N days.
    Use this to check if an incident matches known active campaigns.
    """
    feed = {
        "period_days": days,
        "active_campaigns": [
            {
                "name": "Operation SilverFox",
                "type": "APT",
                "targets": ["Defence", "Aerospace", "Government"],
                "indicators": ["10.0.0.99", "port 4444", "Cobalt Strike"],
                "confidence": "HIGH",
                "first_seen": "2026-02-28",
            }
        ],
        "trending_malware": ["Cobalt Strike", "AsyncRAT", "XLoader"],
        "top_attack_vectors": ["Phishing", "Exposed RDP", "Unpatched CVEs"],
        "generated_at": datetime.now().isoformat(),
    }
    return json.dumps(feed, indent=2)


@server.tool()
def search_firewall_logs(
    source_ip: str = "",
    dest_port: int = 0,
    hours: int = 24,
) -> str:
    
    print(f"[MCP] search_firewall_logs called -> {source_ip}:{dest_port}")

    """
    Search firewall logs filtered by source IP and/or destination port.
    Use when you need raw firewall evidence for a specific IP or port.
    """
    now = datetime.now()
    logs = []
    for i in range(random.randint(2, 5)):
        logs.append({
            "id": f"FW-{random.randint(10000, 99999)}",
            "timestamp": (now - timedelta(minutes=random.randint(5, hours * 60))).isoformat(),
            "source_ip": source_ip or f"192.168.1.{random.randint(100, 200)}",
            "dest_ip": f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "dest_port": dest_port or random.choice([4444, 8080, 443, 22]),
            "action": "BLOCKED",
            "rule": "Block-C2-Outbound",
            "bytes": random.randint(512, 65536),
        })
    return json.dumps(logs, indent=2)


@server.tool()
def get_user_activity(username: str) -> str:
    print(f"[MCP] get_user_activity called -> {username}")

    """
    Get recent activity for a specific user account.
    Use when you need to understand what a user has been doing.
    """
    activity = {
        "username": username,
        "last_login": "2026-03-20T07:45:00",
        "recent_commands": [
            "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "net user /domain",
            "whoami /priv",
        ],
        "failed_logins_24h": 3,
        "unusual_hours_access": True,
        "data_accessed_mb": 450,
        "note": "Encoded PowerShell and domain enumeration commands are suspicious"
    }
    return json.dumps(activity, indent=2)


if __name__ == "__main__":
    server.run()