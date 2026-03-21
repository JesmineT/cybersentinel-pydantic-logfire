import json

async def lookup_ip_reputation(ip_address: str) -> str:
    print(f"[TOOL] lookup_ip_reputation called → {ip_address}")

    """Check IP address against threat intelligence database."""
    is_malicious = ip_address.startswith("10.") or ip_address.endswith(".99")

    result = {
        "ip": ip_address,
        "malicious": is_malicious,
        "risk_level": "HIGH" if is_malicious else "LOW",
        "associated_malware": ["Cobalt Strike"] if is_malicious else [],
        "open_ports": [4444, 8080] if is_malicious else [443],
        "country": "CN" if is_malicious else "SG",
    }
    return json.dumps(result)

async def search_system_logs(query: str, hours: int = 24) -> str:
    print(f"[TOOL] search_system_logs called → {query}")

    """Search SIEM logs for events matching the query."""
    logs = [
        {
            "timestamp": "2026-03-20T09:15:00Z",
            "source": "Firewall",
            "event": f"Outbound connection blocked — {query}",
            "severity": "HIGH",
            "source_ip": "192.168.1.105",
            "dest_port": 4444,
        },
        {
            "timestamp": "2026-03-20T09:10:00Z",
            "source": "EDR",
            "event": f"Suspicious process matching {query}",
            "severity": "MEDIUM",
            "process": "powershell.exe",
        }
    ]
    return json.dumps(logs)

async def get_asset_details(ip_address: str) -> str:
    print(f"[TOOL] get_asset_details called → {ip_address}")
    
    """Look up asset details by IP address."""
    assets = {
        "192.168.1.105": {
            "hostname": "WORKSTATION-07",
            "owner": "john.doe@company.sg",
            "os": "Windows 11",
            "patch_status": "NON-COMPLIANT",
            "department": "Engineering",
        }
    }
    result = assets.get(ip_address, {
        "hostname": "UNKNOWN",
        "note": "Not in inventory — possible rogue device"
    })
    return json.dumps(result)