def classify_threat(
    row,
    port_scan_ip_counts=None,
    ddos_dest_counts=None,
    bruteforce_ip_counts=None
):
    """
    Rule-based threat classification for a single suspicious log row.

    Optional aggregate dictionaries improve detection when processing
    a complete batch of network logs.
    """

    packets = row.get("packets", 0) or 0
    bytes_sent = row.get("bytes_sent", 0) or 0
    dest_port = row.get("destination_port", 0) or 0

    event_type = str(row.get("event_type", "")).lower().strip()

    source_ip = row.get("source_ip")
    dest_ip = row.get("destination_ip")

    # ---------------------------------------------------------
    # 1. BRUTE FORCE
    # ---------------------------------------------------------
    login_failure = (
        "login failure" in event_type
        or ("login" in event_type and "fail" in event_type)
    )

    if login_failure:
        if (
            bruteforce_ip_counts
            and bruteforce_ip_counts.get(source_ip, 0) >= 3
        ):
            return "Brute Force Login"

        # SSH / Telnet / RDP login failures
        if dest_port in (22, 23, 3389):
            return "Brute Force Login"

    # ---------------------------------------------------------
    # 2. PORT SCAN
    # ---------------------------------------------------------
    if (
        port_scan_ip_counts
        and port_scan_ip_counts.get(source_ip, 0) >= 5
    ):
        return "Port Scan"

    if (
        dest_port > 1000
        and packets < 15
        and "connection" in event_type
    ):
        return "Port Scan"

    # ---------------------------------------------------------
    # 3. DDOS
    # ---------------------------------------------------------
    if packets >= 1000:
        return "DDoS"

    if (
        ddos_dest_counts
        and ddos_dest_counts.get(dest_ip, 0) >= 20
        and packets >= 100
    ):
        return "DDoS"

    # ---------------------------------------------------------
    # 4. DATA EXFILTRATION
    # ---------------------------------------------------------
    if bytes_sent >= 1_000_000:
        return "Data Exfiltration"

    # ---------------------------------------------------------
    # 5. MALWARE COMMUNICATION
    # ---------------------------------------------------------
    suspicious_ports = {
        4444,
        4445,
        4446,
        31337,
        6667
    }

    if dest_port in suspicious_ports:
        return "Malware Communication"

    if dest_port > 5000 and packets < 10:
        return "Malware Communication"

    # ---------------------------------------------------------
    # 6. UNKNOWN
    # ---------------------------------------------------------
    return "Unknown Attack"


def build_batch_aggregates(df):
    """
    Build aggregate statistics used by classify_threat().
    """

    # ---------------------------------------------------------
    # Port scan:
    # Number of unique destination ports contacted
    # by each source IP.
    # ---------------------------------------------------------
    port_scan_ip_counts = (
        df.groupby("source_ip")["destination_port"]
        .nunique()
        .to_dict()
    )

    # ---------------------------------------------------------
    # DDoS:
    # Number of connections targeting each destination IP.
    # ---------------------------------------------------------
    ddos_dest_counts = (
        df.groupby("destination_ip")["source_ip"]
        .count()
        .to_dict()
    )

    # ---------------------------------------------------------
    # Brute force:
    # Count ONLY login failures per source IP.
    # ---------------------------------------------------------
    event_text = df["event_type"].astype(str).str.lower()

    login_failure_mask = (
        event_text.str.contains("login failure", na=False)
        | (
            event_text.str.contains("login", na=False)
            & event_text.str.contains("fail", na=False)
        )
    )

    bruteforce_ip_counts = (
        df[login_failure_mask]
        .groupby("source_ip")
        .size()
        .to_dict()
    )

    return (
        port_scan_ip_counts,
        ddos_dest_counts,
        bruteforce_ip_counts
    )

def generate_description(threat_type, row):
    templates = {
        "Port Scan": f"Multiple destination ports probed from {row.get('source_ip')} in a short window, "
                     f"consistent with reconnaissance activity.",
        "DDoS": f"Abnormally high packet volume ({row.get('packets')} packets) directed at "
                f"{row.get('destination_ip')}, consistent with a denial-of-service pattern.",
        "Brute Force Login": f"Repeated login failures from {row.get('source_ip')} targeting "
                              f"{row.get('destination_ip')}:{row.get('destination_port')}.",
        "Malware Communication": f"Outbound connection from {row.get('source_ip')} to an uncommon port "
                                  f"({row.get('destination_port')}), consistent with C2 beaconing.",
        "Data Exfiltration": f"Unusually large outbound transfer ({row.get('bytes_sent')} bytes) from "
                              f"{row.get('source_ip')} to {row.get('destination_ip')}.",
        "Unknown Attack": f"Flagged as anomalous by the detection model but did not match a known rule "
                           f"pattern. Manual review recommended.",
    }
    return templates.get(threat_type, "Anomalous activity detected.")
