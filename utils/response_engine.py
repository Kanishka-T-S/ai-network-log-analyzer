RESPONSE_ACTIONS = {
    "Port Scan": [
        "Block source IP",
        "Close unused/unnecessary ports",
        "Enable IDS/IPS rule for port scan signatures",
        "Notify administrator",
    ],
    "DDoS": [
        "Rate limit traffic from source",
        "Block malicious IP range",
        "Enable firewall filtering / upstream scrubbing",
        "Notify administrator",
    ],
    "Brute Force Login": [
        "Block source IP",
        "Force password reset for targeted account",
        "Enable multi-factor authentication",
        "Monitor further login attempts",
    ],
    "Malware Communication": [
        "Isolate affected host from the network",
        "Block outbound traffic to the destination",
        "Run a full malware scan on the endpoint",
        "Notify administrator",
    ],
    "Data Exfiltration": [
        "Isolate affected device",
        "Disable the compromised account",
        "Inspect and audit transferred files",
        "Notify administrator and legal/compliance if needed",
    ],
    "Unknown Attack": [
        "Escalate to a security analyst",
        "Continue monitoring traffic from this source",
        "Collect additional logs for context",
        "Notify administrator",
    ],
    "Normal Activity": [
        "No immediate action required",
        "Log retained for security auditing",
    ],
}

DEFAULT_ACTIONS = ["Monitor incident", "Escalate if activity continues"]


def get_response_actions(threat_type):
    return RESPONSE_ACTIONS.get(threat_type, DEFAULT_ACTIONS)
