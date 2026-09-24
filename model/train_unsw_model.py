"""
Training script for UNSW-NB15 anomaly detection model.
Produces:
  - model/anomaly_model_unsw_nb15.pkl
  - model/unsw_nb15_preprocessor.pkl
"""
import os
import sys
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# Ensure project root is in path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.unsw_preprocessor import UNSWPreprocessor


def train_unsw_model(csv_path=None, model_save_path=None, preprocessor_save_path=None, contamination=0.02):
    """
    Train Isolation Forest model on UNSW-NB15 dataset and save model and preprocessor.
    """
    csv_path = csv_path or os.path.join(BASE_DIR, "data", "UNSW_NB15_training-set.csv")
    model_save_path = model_save_path or os.path.join(BASE_DIR, "model", "anomaly_model_unsw_nb15.pkl")
    preprocessor_save_path = preprocessor_save_path or os.path.join(BASE_DIR, "model", "unsw_nb15_preprocessor.pkl")

    print(f"Loading UNSW-NB15 dataset from: {csv_path}")
    raw_df = pd.read_csv(csv_path)
    
    # Drop rows that are entirely NaN (e.g., trailing empty lines)
    raw_df = raw_df.dropna(how="all").reset_index(drop=True)
    dataset_size = len(raw_df)
    print(f"Training dataset size: {dataset_size} rows")

    # Fit preprocessor and extract feature matrix
    preprocessor = UNSWPreprocessor()
    features = preprocessor.fit_transform(raw_df)

    feature_names = features.columns.tolist()
    feature_count = len(feature_names)
    print(f"Final feature count: {feature_count}")
    print(f"Features: {feature_names}")

    # Train Isolation Forest with specified hyperparameters
    print(f"Training IsolationForest(n_estimators=200, contamination={contamination}, random_state=42, n_jobs=-1)...")
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(features)

    # Save artifacts
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(model, model_save_path)
    preprocessor.save(preprocessor_save_path)

    print(f"Saved UNSW-NB15 model to: {model_save_path}")
    print(f"Saved preprocessing artifacts to: {preprocessor_save_path}")

    return model, preprocessor, features


if __name__ == "__main__":
    train_unsw_model()
