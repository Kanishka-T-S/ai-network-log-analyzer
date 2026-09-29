import sqlite3
import os
import pandas as pd
from config import Config

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    bytes_sent INTEGER,
    packets INTEGER,
    event_type TEXT,
    severity TEXT,
    status TEXT,
    anomaly_score REAL,
    threat_type TEXT,
    risk_score INTEGER,
    description TEXT,
    raw_log TEXT,
    batch_id TEXT
);

CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT,
    filename TEXT,
    filesize INTEGER,
    upload_time TEXT,
    rows_parsed INTEGER
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    log_id INTEGER,
    attack_type TEXT,
    severity TEXT,
    status TEXT,
    assigned_to TEXT,
    detected_time TEXT,
    recommendation TEXT,
    FOREIGN KEY (log_id) REFERENCES logs(id)
);
"""
UNSW_COLUMNS = [
    "unsw_id",
    "dur",
    "proto",
    "service",
    "state",
    "sport",
    "dsport",
    "sbytes",
    "dbytes",
    "spkts",
    "dpkts",
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
    "label",
    "attack_cat",
    "attack_category",
    "attack_type",
]

def get_connection():
    db_dir = os.path.dirname(Config.DATABASE_PATH)

    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(
        Config.DATABASE_PATH,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    # Improve SQLite concurrency for the Flask application.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    return conn

def init_db():
    conn = get_connection()

    # Create existing tables if they do not exist.
    conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Database migration for UNSW-NB15 fields
    #
    # Existing installations already have a "logs" table. SQLite's
    # CREATE TABLE IF NOT EXISTS will NOT add new columns to that table.
    # Therefore we explicitly add missing UNSW columns.
    # ------------------------------------------------------------------

    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(logs)").fetchall()
    }

    numeric_unsw_columns = {
        "unsw_id",
        "dur",
        "sport",
        "dsport",
        "sbytes",
        "dbytes",
        "spkts",
        "dpkts",
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
        "label",
    }

    for column in UNSW_COLUMNS:
        if column not in existing_columns:

            if column in numeric_unsw_columns:
                column_type = "REAL"
            else:
                column_type = "TEXT"

            conn.execute(
                f'ALTER TABLE logs ADD COLUMN "{column}" {column_type}'
            )

    conn.commit()
    conn.close()
def pd_is_missing(value):
    try:
        return pd.isna(value)
    except (TypeError, ValueError):
        return False

def insert_logs(df, batch_id):
    conn = get_connection()

    # Existing application columns.
    base_cols = [
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
        "status",
        "anomaly_score",
        "threat_type",
        "risk_score",
        "description",
        "raw_log",
        "batch_id",
    ]

    # Add UNSW fields when they are present in the uploaded dataframe.
    unsw_cols = [
        col for col in UNSW_COLUMNS
        if col in df.columns
    ]

    cols = base_cols + unsw_cols

    records = []

    for _, row in df.iterrows():
        values = []

        for col in cols:
            value = row.get(col, None)

            # Convert pandas NaN/NA to SQLite NULL.
            if pd_is_missing(value):
                value = None

            values.append(value)

        records.append(tuple(values))

    placeholders = ",".join(["?"] * len(cols))

    conn.executemany(
        f"""
        INSERT INTO logs ({','.join(cols)})
        VALUES ({placeholders})
        """,
        records
    )

    conn.commit()
    conn.close()

def record_upload(batch_id, filename, filesize, upload_time, rows_parsed):
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO uploads
        (batch_id, filename, filesize, upload_time, rows_parsed)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            batch_id,
            filename,
            filesize,
            upload_time,
            rows_parsed
        )
    )

    conn.commit()
    conn.close()


def fetch_logs(filters=None, limit=500):

    conn = get_connection()

    query = "SELECT * FROM logs"

    clauses = []
    params = []

    filters = filters or {}

    if filters.get("source_ip"):
        clauses.append("source_ip LIKE ?")
        params.append(f"%{filters['source_ip']}%")

    if filters.get("protocol"):
        clauses.append("protocol=?")
        params.append(filters["protocol"])

    if filters.get("severity"):
        clauses.append("severity=?")
        params.append(filters["severity"])

    if filters.get("status"):
        clauses.append("status=?")
        params.append(filters["status"])

    if filters.get("threat_type"):
        clauses.append("threat_type=?")
        params.append(filters["threat_type"])

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY id DESC LIMIT ?"

    params.append(limit)

    rows = conn.execute(query, params).fetchall()

    conn.close()

    return rows


def fetch_log_by_id(log_id):

    conn = get_connection()

    row = conn.execute(
        "SELECT * FROM logs WHERE id=?",
        (log_id,)
    ).fetchone()

    conn.close()

    return row


def fetch_unanalyzed_logs(batch_id=None):

    conn = get_connection()

    if batch_id:
        rows = conn.execute(
            """
            SELECT *
            FROM logs
            WHERE status IS NULL
              AND batch_id = ?
            """,
            (batch_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT *
            FROM logs
            WHERE status IS NULL
            """
        ).fetchall()

    conn.close()

    return rows

def update_log_analysis(
    log_id,
    status,
    anomaly_score,
    threat_type,
    risk_score,
    description
):

    conn = get_connection()

    conn.execute(
        """
        UPDATE logs
        SET
            status=?,
            anomaly_score=?,
            threat_type=?,
            risk_score=?,
            description=?
        WHERE id=?
        """,
        (
            status,
            anomaly_score,
            threat_type,
            risk_score,
            description,
            log_id
        )
    )

    conn.commit()
    conn.close()
def update_log_analysis_batch(results):
    """
    Update multiple analyzed logs in a single SQLite transaction.
    """

    if not results:
        return

    conn = get_connection()

    try:
        conn.executemany(
            """
            UPDATE logs
            SET
                status=?,
                anomaly_score=?,
                threat_type=?,
                risk_score=?,
                description=?
            WHERE id=?
            """,
            results
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def get_stats():
    conn = get_connection()

    # Basic counts
    total_logs = conn.execute(
        "SELECT COUNT(*) FROM logs"
    ).fetchone()[0]

    normal_logs = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE status='Normal'"
    ).fetchone()[0]

    suspicious_logs = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE status='Suspicious'"
    ).fetchone()[0]

    critical_incidents = conn.execute(
        """
        SELECT COUNT(*)
        FROM logs
        WHERE severity='Critical'
        AND status='Suspicious'
        """
    ).fetchone()[0]

    # Most active source IP
    most_active_row = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS c
        FROM logs
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY c DESC
        LIMIT 1
        """
    ).fetchone()

    most_active_ip = (
        most_active_row["source_ip"]
        if most_active_row
        else "N/A"
    )

    # Most used protocol
    most_protocol_row = conn.execute(
        """
        SELECT protocol, COUNT(*) AS c
        FROM logs
        WHERE protocol IS NOT NULL
        GROUP BY protocol
        ORDER BY c DESC
        LIMIT 1
        """
    ).fetchone()

    most_used_protocol = (
        most_protocol_row["protocol"]
        if most_protocol_row
        else "N/A"
    )

    # Logs over time
    timeline_rows = conn.execute(
        """
        SELECT
            substr(timestamp, 1, 10) AS date,
            COUNT(*) AS count
        FROM logs
        WHERE timestamp IS NOT NULL
        GROUP BY substr(timestamp, 1, 10)
        ORDER BY date
        """
    ).fetchall()

    logs_over_time = [
        {
            "date": row["date"],
            "count": row["count"]
        }
        for row in timeline_rows
    ]

    # Attack / threat types
    attack_rows = conn.execute(
        """
        SELECT
            threat_type,
            COUNT(*) AS count
        FROM logs
        WHERE threat_type IS NOT NULL
        GROUP BY threat_type
        ORDER BY count DESC
        """
    ).fetchall()

    attack_types = [
        {
            "threat_type": row["threat_type"],
            "count": row["count"]
        }
        for row in attack_rows
    ]

    # Protocol distribution
    protocol_rows = conn.execute(
        """
        SELECT
            protocol,
            COUNT(*) AS count
        FROM logs
        WHERE protocol IS NOT NULL
        GROUP BY protocol
        ORDER BY count DESC
        """
    ).fetchall()

    protocol_distribution = [
        {
            "protocol": row["protocol"],
            "count": row["count"]
        }
        for row in protocol_rows
    ]

    # Severity distribution
    severity_rows = conn.execute(
        """
        SELECT
            severity,
            COUNT(*) AS count
        FROM logs
        WHERE severity IS NOT NULL
        GROUP BY severity
        ORDER BY count DESC
        """
    ).fetchall()

    severity_distribution = [
        {
            "severity": row["severity"],
            "count": row["count"]
        }
        for row in severity_rows
    ]

    # Top attacking IPs
    attacking_rows = conn.execute(
        """
        SELECT
            source_ip,
            COUNT(*) AS c
        FROM logs
        WHERE status='Suspicious'
        AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY c DESC
        LIMIT 10
        """
    ).fetchall()

    top_attacking_ips = [
        {
            "source_ip": row["source_ip"],
            "c": row["c"]
        }
        for row in attacking_rows
    ]

    conn.close()

    return {
        "total_logs": total_logs,
        "normal_logs": normal_logs,
        "suspicious_logs": suspicious_logs,
        "critical_incidents": critical_incidents,
        "most_active_ip": most_active_ip,
        "most_used_protocol": most_used_protocol,
        "logs_over_time": logs_over_time,
        "attack_types": attack_types,
        "protocol_distribution": protocol_distribution,
        "severity_distribution": severity_distribution,
        "top_attacking_ips": top_attacking_ips
    }