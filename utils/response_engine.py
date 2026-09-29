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

    "DDoS Attack": [
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

    "Web Attack": [
        "Block malicious IP at Web Application Firewall (WAF)",
        "Inspect web server logs for SQLi/XSS payloads",
        "Notify web application administrator",
    ],

    "RDP Attack": [
        "Block source IP at firewall",
        "Enforce NLA and strong password policies on RDP service",
        "Notify system administrator",
    ],

    "FTP Attack": [
        "Block source IP",
        "Disable anonymous FTP access and enforce strong credentials",
        "Notify system administrator",
    ],

    # ---------------------------------------------------------
    # UNSW-NB15 ATTACK TYPES
    # ---------------------------------------------------------

    "Exploit Attack": [
        "Block or isolate the suspicious source",
        "Inspect affected service and application logs",
        "Apply security patches to the targeted service",
        "Notify security administrator",
    ],

    "Fuzzing Attack": [
        "Block suspicious source IP if repeated",
        "Inspect application and service logs",
        "Check for crashes or abnormal service behavior",
        "Notify security administrator",
    ],

    "Reconnaissance Attack": [
        "Monitor the source IP for further activity",
        "Block repeated reconnaissance attempts if necessary",
        "Review exposed network services and ports",
        "Notify security administrator",
    ],

    "Backdoor Attack": [
        "Immediately isolate the affected host",
        "Block suspicious source and destination communication",
        "Run a full malware and integrity scan",
        "Notify security administrator",
    ],

    "Analysis Attack": [
        "Monitor the source for repeated suspicious activity",
        "Review affected system and application logs",
        "Inspect unusual network communication",
        "Notify security administrator",
    ],

    "Generic Attack": [
        "Block suspicious source if activity continues",
        "Review network and system logs",
        "Monitor related hosts for similar activity",
        "Notify security administrator",
    ],

    "Shellcode Attack": [
        "Isolate the affected host",
        "Inspect running processes and application logs",
        "Apply security patches",
        "Run endpoint security scans",
    ],

    "Worm Attack": [
        "Immediately isolate affected host",
        "Block suspicious network communication",
        "Scan connected systems for propagation",
        "Notify security administrator",
    ],

    # ---------------------------------------------------------
    # NORMAL
    # ---------------------------------------------------------

    "Normal Activity": [
        "No immediate action required",
        "Log retained for security auditing",
    ],

    # ---------------------------------------------------------
    # UNKNOWN
    # ---------------------------------------------------------

    "Unknown Attack": [
        "Escalate to a security analyst",
        "Continue monitoring traffic from this source",
        "Collect additional logs for context",
        "Notify administrator",
    ],
}


DEFAULT_ACTIONS = [
    "Monitor incident",
    "Escalate if activity continues",
]


def get_response_actions(threat_type):
    """
    Return recommended response actions for a detected threat.
    """

    return RESPONSE_ACTIONS.get(
        threat_type,
        DEFAULT_ACTIONS
    )