import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from config import Config
from utils.unsw_preprocessor import UNSWPreprocessor


# Legacy fixed mappings (Preserved for backwards compatibility with legacy model)
PROTOCOL_MAP = {
    "TCP": 1,
    "UDP": 2,
    "ICMP": 3
}

EVENT_TYPE_MAP = {
    "Connection": 1,
    "DNS Query": 2,
    "File Transfer": 3,
    "Login Failure": 4,
    "Ping": 5
}

FEATURE_COLUMNS = [
    "source_port",
    "destination_port",
    "bytes_sent",
    "packets",
    "protocol_encoded",
    "event_type_encoded",
]


def load_unsw_preprocessor():
    """Load tuned UNSW-NB15 preprocessor artifact."""
    prep_path = Config.UNSW_PREPROCESSOR_PATH
    if os.path.exists(prep_path):
        return UNSWPreprocessor.load(prep_path)
    # Fall back if file missing
    return UNSWPreprocessor()


def preprocess_legacy(df):
    """Legacy 6-feature preprocessing logic."""
    df = df.copy()

    if "protocol" not in df.columns:
        df["protocol"] = ""
    if "event_type" not in df.columns:
        df["event_type"] = ""
    for col in ["source_port", "destination_port", "bytes_sent", "packets"]:
        if col not in df.columns:
            df[col] = 0

    df["protocol"] = df["protocol"].astype(str).str.strip().str.upper()
    df["protocol_encoded"] = df["protocol"].map(PROTOCOL_MAP).fillna(0).astype(int)

    df["event_type"] = df["event_type"].astype(str).str.strip()
    df["event_type_encoded"] = df["event_type"].map(EVENT_TYPE_MAP).fillna(0).astype(int)

    for col in ["source_port", "destination_port", "bytes_sent", "packets"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    features = df[FEATURE_COLUMNS].copy()
    return df, features


def preprocess_unsw(df):
    """UNSW 47-feature preprocessing adapter logic."""
    df = df.copy()
    preprocessor = load_unsw_preprocessor()
    features = preprocessor.transform(df)
    return df, features


def preprocess(df, model_type=None):
    """
    Convert network log data into numeric ML features.
    Supports 'unsw' (47 features) and 'legacy' (6 features).
    """
    model_type = (model_type or Config.MODEL_TYPE).lower()

    if model_type == "unsw":
        return preprocess_unsw(df)
    else:
        return preprocess_legacy(df)


def train_model(csv_path=None, save_path=None):
    """Train legacy Isolation Forest using sample_logs.csv."""
    csv_path = csv_path or os.path.join(Config.BASE_DIR, "data", "sample_logs.csv")
    save_path = save_path or Config.LEGACY_MODEL_PATH

    df = pd.read_csv(csv_path)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    _, features = preprocess_legacy(df)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.25,
        random_state=42,
        n_jobs=-1
    )
    model.fit(features)

    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump(model, save_path)
    return model


def load_model(model_type=None):
    """
    Load trained anomaly detection model based on configuration.
    Supports model_type: 'unsw' or 'legacy'.
    """
    model_type = (model_type or Config.MODEL_TYPE).lower()

    if model_type == "unsw":
        path = Config.UNSW_MODEL_PATH
        if not os.path.exists(path):
            # Fall back to legacy if tuned unsw model file doesn't exist
            path = Config.LEGACY_MODEL_PATH
    else:
        path = Config.LEGACY_MODEL_PATH

    if not os.path.exists(path):
        train_model()

    return joblib.load(path)


def predict_anomalies(features, model_type=None, threshold=None):
    """
    Predict whether network logs are normal (1) or anomalous (-1).
    Supports decision threshold offset tuning for UNSW model.
    """
    model_type = (model_type or Config.MODEL_TYPE).lower()
    model = load_model(model_type=model_type)

    scores = model.decision_function(features)

    if model_type == "unsw":
        cutoff = Config.UNSW_DECISION_THRESHOLD if threshold is None else threshold
        # If anomaly score < cutoff, classify as anomaly (-1), else normal (1)
        predictions = np.where(scores < cutoff, -1, 1)
    else:
        predictions = model.predict(features)

    return predictions, scores


def score_to_status(pred):
    """Convert Isolation Forest prediction into application status."""
    return "Normal" if pred == 1 else "Suspicious"


def compute_risk_score(anomaly_score):
    raw = abs(anomaly_score) * 100
    return int(min(100, max(20, raw)))