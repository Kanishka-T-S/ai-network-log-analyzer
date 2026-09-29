def _get_row_value(row, field_names):
    if row is None:
        return None
    if hasattr(row, "to_dict"):
        d = row.to_dict()
    elif isinstance(row, dict):
        d = row
    elif hasattr(row, "items"):
        d = dict(row.items())
    else:
        try:
            d = dict(row)
        except Exception:
            return None

    norm_map = {}
    for k, v in d.items():
        norm_k = str(k).strip().lower().replace(" ", "_")
        norm_map[norm_k] = v

    for field in field_names:
        norm_field = field.lower().strip().replace(" ", "_")
        if norm_field in norm_map:
            val = norm_map[norm_field]
            if val is not None:
                try:
                    import pandas as pd
                    if pd.isna(val):
                        continue
                except Exception:
                    pass
                s_val = str(val).strip()
                if s_val != "" and s_val.lower() not in {"nan", "none", "null", "n/a", "-", "undefined"}:
                    return s_val
    return None


def get_dataset_threat(row):
    """
    Safely inspect dataset attack fields (attack_cat, attack_category, attack_type, threat_type, event_type)
    case-insensitively and normalize into the project's threat names or preserve readable attack categories.
    """
    is_explicit_field = True
    raw_val = _get_row_value(row, ["attack_cat", "attack_category", "attack_type", "threat_type"])

    if raw_val is None:
        is_explicit_field = False
        raw_val = _get_row_value(row, ["event_type"])

    if raw_val is None:
        return None

    s = raw_val.strip().lower()

    # Generic event types / placeholders to ignore when from event_type or generic dataset column
    if s in {"connection", "file transfer", "dns query", "network traffic", "http request", "general", "log", "event", "login failure"}:
        if not is_explicit_field:
            return None

    # Explicit normal traffic handling
    if s in {"normal", "normal activity", "benign", "normal traffic", "clean"}:
        return "Normal Activity"

    # 1. DoS / DDoS
    if s in {"dos", "ddos", "denial of service", "denial-of-service", "dos/ddos"} or "denial of service" in s:
        return "DDoS"

    # 2. Brute Force Login
    if (
        s in {"brute force", "brute-force", "ssh-bruteforce", "ftp-bruteforce", "bruteforce", "brute force login"}
        or "brute force" in s
        or "bruteforce" in s
    ):
        return "Brute Force Login"

    # 3. Port Scan
    if s in {"port scan", "portscan", "reconnaissance", "scan", "port-scan"} or "port scan" in s or "portscan" in s:
        return "Port Scan"

    # 4. Data Exfiltration
    if s in {"data exfiltration", "exfiltration"} or "exfiltration" in s:
        return "Data Exfiltration"

    # 5. Malware Communication
    if (
        s in {"malware", "c2", "command and control", "command & control", "backdoor", "malware communication"}
        or "malware" in s
        or "command and control" in s
    ):
        return "Malware Communication"

    # 6. Web Attack
    if (
        s in {"web attack", "web attack - brute force", "web attack - xss", "web attack - sql injection"}
        or "web attack" in s
    ):
        return "Web Attack"

    # 7. RDP Attack
    if s in {"rdp", "rdp attack", "rdp-attack"} or "rdp attack" in s or s == "rdp":
        return "RDP Attack"

    # 8. FTP Attack
    if s in {"ftp", "ftp attack", "ftp-attack"} or "ftp attack" in s or s == "ftp":
        return "FTP Attack"

    # If from event_type and not a recognized attack mapping, return None so rule-based engine can evaluate
    if not is_explicit_field:
        return None

    # If the value is a meaningful attack category from an explicit column not in the mapping, preserve as readable category
    formatted = raw_val.replace("_", " ").replace("-", " ").strip()
    if formatted.islower() or formatted.isupper():
        formatted = formatted.title()
    return formatted


def classify_threat(
    row,
    port_scan_ip_counts=None,
    ddos_dest_counts=None,
    bruteforce_ip_counts=None
):
    """
    Rule-based and dataset-assisted threat classification for a single log row.

    Classification priority:
    1. Valid explicit dataset attack category (FIRST)
    2. Rule-based threat detection (SECOND)
    3. Fallback to 'Unknown Attack' (THIRD)
    """

    # FIRST: Use valid explicit dataset attack category if present
    dataset_threat = get_dataset_threat(row)
    if dataset_threat:
        return dataset_threat

    # SECOND: Rule-based detection
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
    # 6. UNKNOWN (THIRD)
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
        "Web Attack": "Network activity identified as a web attack based on the dataset-provided attack category.",
        "RDP Attack": "Network activity identified as an RDP attack based on the dataset-provided attack category.",
        "FTP Attack": "Network activity identified as an FTP attack based on the dataset-provided attack category.",
        "Normal Activity": "Traffic identified as normal or benign activity.",
        "Unknown Attack": f"Flagged as anomalous by the detection model but did not match a known rule "
                           f"pattern. Manual review recommended.",
    }
    return templates.get(threat_type, f"Network activity identified as {threat_type} based on security analysis.")

