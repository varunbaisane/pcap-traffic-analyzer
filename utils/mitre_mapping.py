MITRE_MAPPING = {
    "Port Scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning"
    },
    "DNS Anomaly": {
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "DNS"
    },
    "ICMP Flood": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning"
    },
    "Brute Force Attempt": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force"
    },
    "HTTP Flood": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service"
    }
}


def enrich_with_mitre(alert):
    mapping = MITRE_MAPPING.get(alert.get("alert_type"))
    if mapping:
        alert["mitre_attack"] = mapping
    return alert