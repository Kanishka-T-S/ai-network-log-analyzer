import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
from sklearn.ensemble import IsolationForest

from config import Config
from utils.unsw_preprocessor import UNSWPreprocessor
from utils.detector import preprocess_legacy
# ---------------------------------------------------------
# Create small synthetic UNSW-style data for CI testing
# ---------------------------------------------------------

ci_data = pd.DataFrame({
    "source_port": [1234, 2345, 3456, 4567, 5678, 6789],
    "destination_port": [80, 443, 22, 8080, 53, 21],
    "bytes_sent": [100, 200, 300, 400, 500, 600],
    "packets": [10, 20, 30, 40, 50, 60],
    "protocol": ["tcp", "tcp", "udp", "tcp", "udp", "tcp"],
    "event_type": [
        "Connection",
        "Connection",
        "DNS Query",
        "File Transfer",
        "Ping",
        "Login Failure",
    ],
})


# ---------------------------------------------------------
# UNSW preprocessor
# ---------------------------------------------------------

preprocessor = UNSWPreprocessor()
features = preprocessor.fit_transform(ci_data)

os.makedirs(os.path.dirname(Config.UNSW_PREPROCESSOR_PATH), exist_ok=True)

preprocessor.save(Config.UNSW_PREPROCESSOR_PATH)


# ---------------------------------------------------------
# UNSW Isolation Forest
# ---------------------------------------------------------

unsw_model = IsolationForest(
    n_estimators=20,
    contamination=0.2,
    random_state=42,
)

unsw_model.fit(features)

import joblib

joblib.dump(
    unsw_model,
    Config.UNSW_MODEL_PATH
)


# ---------------------------------------------------------
# Legacy model
# ---------------------------------------------------------

legacy_df = ci_data.copy()

_, legacy_features = preprocess_legacy(legacy_df)

legacy_model = IsolationForest(
    n_estimators=20,
    contamination=0.25,
    random_state=42,
)

legacy_model.fit(legacy_features)

joblib.dump(
    legacy_model,
    Config.LEGACY_MODEL_PATH
)


print("CI test artifacts created successfully.")
print(f"UNSW features: {features.shape[1]}")
print(f"UNSW model: {Config.UNSW_MODEL_PATH}")
print(f"UNSW preprocessor: {Config.UNSW_PREPROCESSOR_PATH}")
print(f"Legacy model: {Config.LEGACY_MODEL_PATH}")