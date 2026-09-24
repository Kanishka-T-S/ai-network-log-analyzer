import numpy as np
import pandas as pd
import joblib

# Columns to strictly exclude from ML feature matrix
EXCLUDED_COLUMNS = {
    "label",
    "attack_cat",
    "target",
    "class",
    "id",
    "source_ip",
    "destination_ip",
    "timestamp",
    "raw_log",
    "severity",
    "batch_id",
    "status",
    "anomaly_score",
    "risk_score",
    "description",
    "_pred",
    "_score",
}


class UNSWPreprocessor:
    """
    Reusable preprocessing and feature engineering pipeline for UNSW-NB15 training
    and inference on incoming network logs.
    """

    def __init__(self):
        self.proto_map = {}
        self.service_map = {}
        self.feature_names = []
        self.is_fitted = False

    def _normalize_columns(self, df):
        df = df.copy()
        df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
        return df

    def _map_schema(self, df):
        """Map incoming log column names to UNSW network feature names."""
        df = df.copy()

        # Map ports
        if "sport" not in df.columns:
            if "source_port" in df.columns:
                df["sport"] = df["source_port"]
            else:
                df["sport"] = 0

        if "dsport" not in df.columns:
            if "destination_port" in df.columns:
                df["dsport"] = df["destination_port"]
            else:
                df["dsport"] = 0

        # Map bytes and packets
        if "sbytes" not in df.columns:
            if "bytes_sent" in df.columns:
                df["sbytes"] = df["bytes_sent"]
            else:
                df["sbytes"] = 0

        if "spkts" not in df.columns:
            if "packets" in df.columns:
                df["spkts"] = df["packets"]
            else:
                df["spkts"] = 0

        if "dbytes" not in df.columns:
            df["dbytes"] = 0

        if "dpkts" not in df.columns:
            df["dpkts"] = 0

        # Map proto / protocol
        if "proto" not in df.columns:
            if "protocol" in df.columns:
                df["proto"] = df["protocol"]
            else:
                df["proto"] = "-"

        # Map service / event_type
        if "service" not in df.columns:
            if "event_type" in df.columns:
                df["service"] = df["event_type"]
            else:
                df["service"] = "-"

        # Ensure numeric fields default to 0 if absent
        numeric_defaults = [
            "dur", "rate", "sload", "dload", "sttl", "dttl", "sloss", "dloss",
            "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
            "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
            "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
            "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
            "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
            "ct_srv_dst", "is_sm_ips_ports"
        ]

        for col in numeric_defaults:
            if col not in df.columns:
                df[col] = 0.0

        return df

    def fit(self, df):
        """Learn categorical encoding mappings from training dataset."""
        df_norm = self._normalize_columns(df)
        df_mapped = self._map_schema(df_norm)

        # Build proto map (1-indexed, reserve 0 for unknown)
        unique_protos = (
            df_mapped["proto"]
            .astype(str)
            .str.strip()
            .str.lower()
            .unique()
        )
        self.proto_map = {p: i + 1 for i, p in enumerate(sorted(unique_protos))}

        # Build service map (1-indexed, reserve 0 for unknown)
        unique_services = (
            df_mapped["service"]
            .astype(str)
            .str.strip()
            .str.lower()
            .unique()
        )
        self.service_map = {s: i + 1 for i, s in enumerate(sorted(unique_services))}

        # Determine feature names by running transform once
        df_trans = self.transform(df, is_fitting=True)
        self.feature_names = df_trans.columns.tolist()
        self.is_fitted = True
        return self

    def transform(self, df, is_fitting=False):
        """Transform network log DataFrame into numeric feature matrix."""
        df_norm = self._normalize_columns(df)
        df_mapped = self._map_schema(df_norm)

        # Categorical Encoding
        proto_str = df_mapped["proto"].astype(str).str.strip().str.lower()
        df_mapped["proto_encoded"] = proto_str.map(self.proto_map).fillna(0).astype(int)

        service_str = df_mapped["service"].astype(str).str.strip().str.lower()
        df_mapped["service_encoded"] = service_str.map(self.service_map).fillna(0).astype(int)

        # Ensure ports, bytes, packets are numeric
        for c in ["sport", "dsport", "sbytes", "dbytes", "spkts", "dpkts"]:
            df_mapped[c] = pd.to_numeric(df_mapped[c], errors="coerce").fillna(0)

        # Derived features
        total_bytes = df_mapped["sbytes"] + df_mapped["dbytes"]
        total_packets = df_mapped["spkts"] + df_mapped["dpkts"]

        df_mapped["bytes_per_packet"] = total_bytes / np.maximum(total_packets, 1)
        df_mapped["log_bytes"] = np.log1p(np.maximum(0, total_bytes))
        df_mapped["log_packets"] = np.log1p(np.maximum(0, total_packets))

        sport = df_mapped["sport"]
        dsport = df_mapped["dsport"]
        df_mapped["is_well_known_port"] = (
            ((sport > 0) & (sport < 1024)) | ((dsport > 0) & (dsport < 1024))
        ).astype(int)

        # Define numeric feature columns
        candidate_features = [
            "sport", "dsport", "sbytes", "dbytes", "spkts", "dpkts",
            "dur", "rate", "sload", "dload",
            "proto_encoded", "service_encoded",
            "bytes_per_packet", "log_bytes", "log_packets", "is_well_known_port",
            "sttl", "dttl", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
            "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
            "smean", "dmean", "trans_depth", "response_body_len",
            "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
            "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
            "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
        ]

        # Filter out any excluded columns strictly
        features_to_use = [
            c for c in candidate_features if c not in EXCLUDED_COLUMNS
        ]

        if is_fitting:
            self.feature_names = features_to_use

        # Create output DataFrame
        X = pd.DataFrame(index=df.index)
        for col in features_to_use:
            if col in df_mapped.columns:
                series = pd.to_numeric(df_mapped[col], errors="coerce")
                # Replace infinity and NaN with 0
                series = series.replace([np.inf, -np.inf], np.nan).fillna(0)
                X[col] = series
            else:
                X[col] = 0.0

        return X

    def fit_transform(self, df):
        self.fit(df)
        return self.transform(df)

    def save(self, filepath):
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath):
        return joblib.load(filepath)
