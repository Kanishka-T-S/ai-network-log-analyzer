import pandas as pd
import re
import io


# ---------------------------------------------------------------------------
# Existing application log format
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "bytes_sent",
    "packets",
    "event_type",
    "severity",
]


# ---------------------------------------------------------------------------
# Official UNSW-NB15 format
# ---------------------------------------------------------------------------

UNSW_REQUIRED_COLUMNS = [
    "id",
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
    "attack_cat",
    "label",
]


# ---------------------------------------------------------------------------
# Regex fallback parser for freeform .log/.txt lines
# ---------------------------------------------------------------------------

LOG_LINE_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<protocol>TCP|UDP|ICMP)\s+"
    r"(?P<source_ip>[\d.]+):(?P<source_port>\d+)\s*->\s*"
    r"(?P<destination_ip>[\d.]+):(?P<destination_port>\d+)\s+"
    r"bytes=(?P<bytes_sent>\d+)\s+packets=(?P<packets>\d+)\s+"
    r"event=(?P<event_type>[\w\s]+?)\s+severity=(?P<severity>\w+)",
    re.IGNORECASE,
)


class LogParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# Column normalization
# ---------------------------------------------------------------------------

def _normalize_columns(df):
    df = df.copy()

    df.columns = [
        str(c).strip().lower().replace(" ", "_")
        for c in df.columns
    ]

    return df


# ---------------------------------------------------------------------------
# Detect UNSW-NB15 format
# ---------------------------------------------------------------------------

def is_unsw_dataset(df):
    """
    Determine whether the uploaded CSV follows the official UNSW-NB15 schema.

    We use several characteristic columns rather than relying only on
    attack_cat/label, because target columns should not be required for
    live inference.
    """

    columns = set(df.columns)

    unsw_markers = {
        "dur",
        "proto",
        "service",
        "state",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "sttl",
        "dttl",
    }

    return len(unsw_markers.intersection(columns)) >= 6


# ---------------------------------------------------------------------------
# Parse normal application CSV
# ---------------------------------------------------------------------------

def _parse_standard_csv(df):
    missing = [
        col for col in REQUIRED_COLUMNS
        if col not in df.columns
    ]

    if missing:
        raise LogParseError(
            f"Missing required columns: {missing}"
        )

    df = df.copy()

    # Preserve the original uploaded row.
    df["raw_log"] = df.apply(
        lambda r: ",".join(str(v) for v in r.values),
        axis=1
    )

    return df


# ---------------------------------------------------------------------------
# Parse UNSW-NB15 CSV
# ---------------------------------------------------------------------------

def _parse_unsw_csv(df):
    """
    Preserve the complete UNSW-NB15 feature set while adding the common
    application columns required by the existing dashboard/database layer.

    The ML preprocessor will use the original UNSW fields such as:
        dur, proto, service, spkts, dpkts, sbytes, dbytes, ...
    """

    df = df.copy()

    # ------------------------------------------------------------------
    # Common application fields
    #
    # UNSW-NB15 does not contain source_ip/destination_ip/timestamp.
    # Therefore these are represented safely as "UNSW-NB15" placeholders.
    #
    # The actual UNSW ML features remain untouched.
    # ------------------------------------------------------------------

    if "timestamp" not in df.columns:
        df["timestamp"] = None

    if "source_ip" not in df.columns:
        df["source_ip"] = None

    if "destination_ip" not in df.columns:
        df["destination_ip"] = None

    # Map protocol
    if "protocol" not in df.columns:
        df["protocol"] = df["proto"].astype(str).str.upper()

    # Map ports
    if "source_port" not in df.columns:
    	if "sport" in df.columns:
        	df["source_port"] = pd.to_numeric(
            		df["sport"],
            		errors="coerce"
        	).fillna(0)
    	else:
        	df["source_port"] = 0


    if "destination_port" not in df.columns:
    	if "dsport" in df.columns:
        	df["destination_port"] = pd.to_numeric(
            		df["dsport"],
            		errors="coerce"
        	).fillna(0)
    	else:
        	df["destination_port"] = 0


    if "bytes_sent" not in df.columns:
    	if "sbytes" in df.columns:
        	df["bytes_sent"] = pd.to_numeric(
            		df["sbytes"],
            		errors="coerce"
        	).fillna(0)
    	else:
        	df["bytes_sent"] = 0


    if "packets" not in df.columns:
    	if "spkts" in df.columns:
        	df["packets"] = pd.to_numeric(
            		df["spkts"],
            		errors="coerce"
        	).fillna(0)
    	else:
        	df["packets"] = 0

    # Use service / attack category as a readable event type.
    if "event_type" not in df.columns:
        if "attack_cat" in df.columns:
            df["event_type"] = (
                df["attack_cat"]
                .fillna("Network Traffic")
                .astype(str)
            )
        elif "service" in df.columns:
            df["event_type"] = df["service"].astype(str)
        else:
            df["event_type"] = "Network Traffic"

    # Derive a readable severity from UNSW label.
    if "severity" not in df.columns:
        if "label" in df.columns:
            df["severity"] = df["label"].apply(
                lambda x: "High" if str(x).strip() == "1" else "Low"
            )
        else:
            df["severity"] = "Low"

    # Preserve the complete original row as raw_log.
    df["raw_log"] = df.apply(
        lambda r: ",".join(str(v) for v in r.values),
        axis=1
    )

    return df


# ---------------------------------------------------------------------------
# Main CSV parser
# ---------------------------------------------------------------------------

def parse_csv(file_storage_or_path):
    """
    Parse either:

    1. Existing application network-log CSV
    2. Official UNSW-NB15 CSV

    Returns a DataFrame compatible with the existing application.
    """

    try:
        df = pd.read_csv(file_storage_or_path)
    except Exception as e:
        raise LogParseError(
            f"Unable to read CSV file: {e}"
        )

    df = _normalize_columns(df)

    # Remove completely empty rows.
    df = df.dropna(how="all").reset_index(drop=True)

    if df.empty:
        raise LogParseError("The uploaded CSV contains no data.")

    # ------------------------------------------------------------------
    # UNSW-NB15
    # ------------------------------------------------------------------

    if is_unsw_dataset(df):
        return _parse_unsw_csv(df)

    # ------------------------------------------------------------------
    # Existing application format
    # ------------------------------------------------------------------

    return _parse_standard_csv(df)


# ---------------------------------------------------------------------------
# Freeform LOG/TXT parser
# ---------------------------------------------------------------------------

def parse_freeform(file_storage_or_bytes):
    """Parse .log/.txt files using the regex line parser."""

    if hasattr(file_storage_or_bytes, "read"):
        content = file_storage_or_bytes.read()

        if isinstance(content, bytes):
            content = content.decode(
                "utf-8",
                errors="ignore"
            )
    else:
        content = file_storage_or_bytes

    rows = []

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        match = LOG_LINE_RE.search(line)

        if match:
            d = match.groupdict()

            rows.append({
                "timestamp": d["timestamp"].replace("T", " "),
                "source_ip": d["source_ip"],
                "destination_ip": d["destination_ip"],
                "protocol": d["protocol"].upper(),
                "source_port": int(d["source_port"]),
                "destination_port": int(d["destination_port"]),
                "bytes_sent": int(d["bytes_sent"]),
                "packets": int(d["packets"]),
                "event_type": d["event_type"].strip(),
                "severity": d["severity"].capitalize(),
                "raw_log": line,
            })

    if not rows:
        raise LogParseError(
            "No lines matched the expected log format. "
            "Try uploading a CSV with the required columns "
            "or an official UNSW-NB15 CSV."
        )

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Generic file parser
# ---------------------------------------------------------------------------

def parse_file(filepath, extension):
    extension = extension.lower()

    if extension == "csv":
        return parse_csv(filepath)

    elif extension in ("log", "txt"):
        with open(filepath, "r", errors="ignore") as f:
            return parse_freeform(f.read())

    else:
        raise LogParseError(
            f"Unsupported file extension: {extension}"
        )

