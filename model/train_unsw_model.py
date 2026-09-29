"""
Training script for UNSW-NB15 anomaly detection model.

MLflow tracks:
  - Training parameters
  - Dataset information
  - Training metrics
  - Model artifact
  - Preprocessor artifact

Produces:
  - model/anomaly_model_unsw_nb15.pkl
  - model/unsw_nb15_preprocessor.pkl
"""

import os
import sys
import time

import pandas as pd
import joblib
import mlflow
import mlflow.sklearn

from sklearn.ensemble import IsolationForest


# Ensure project root is in path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


from utils.unsw_preprocessor import UNSWPreprocessor


# MLflow experiment
mlflow.set_experiment("network-log-anomaly-detection")


def train_unsw_model(
    csv_path=None,
    model_save_path=None,
    preprocessor_save_path=None,
    contamination=0.02
):
    """
    Train Isolation Forest model on UNSW-NB15 dataset
    and track the training process using MLflow.
    """

    csv_path = csv_path or os.path.join(
        BASE_DIR,
        "data",
        "UNSW_NB15_training-set.csv"
    )

    model_save_path = model_save_path or os.path.join(
        BASE_DIR,
        "model",
        "anomaly_model_unsw_nb15.pkl"
    )

    preprocessor_save_path = preprocessor_save_path or os.path.join(
        BASE_DIR,
        "model",
        "unsw_nb15_preprocessor.pkl"
    )

    print(f"Loading UNSW-NB15 dataset from: {csv_path}")

    raw_df = pd.read_csv(csv_path)

    # Drop completely empty rows
    raw_df = raw_df.dropna(how="all").reset_index(drop=True)

    dataset_size = len(raw_df)

    print(f"Training dataset size: {dataset_size} rows")

    # Start MLflow run
    with mlflow.start_run(run_name="UNSW-NB15-IsolationForest"):

        start_time = time.time()

        # -----------------------------
        # Dataset information
        # -----------------------------

        mlflow.log_param("dataset", "UNSW-NB15")
        mlflow.log_param("model_type", "IsolationForest")
        mlflow.log_param("n_estimators", 200)
        mlflow.log_param("contamination", contamination)
        mlflow.log_param("random_state", 42)

        mlflow.log_metric("dataset_rows", dataset_size)

        # -----------------------------
        # Preprocessing
        # -----------------------------

        preprocessor = UNSWPreprocessor()

        features = preprocessor.fit_transform(raw_df)

        feature_names = features.columns.tolist()
        feature_count = len(feature_names)

        print(f"Final feature count: {feature_count}")
        print(f"Features: {feature_names}")

        mlflow.log_metric("feature_count", feature_count)

        # -----------------------------
        # Train Isolation Forest
        # -----------------------------

        print(
            "Training IsolationForest("
            "n_estimators=200, "
            f"contamination={contamination}, "
            "random_state=42, "
            "n_jobs=-1)..."
        )

        model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )

        model.fit(features)

        # -----------------------------
        # Training metrics
        # -----------------------------

        training_time = time.time() - start_time

        mlflow.log_metric(
            "training_time_seconds",
            training_time
        )

        # -----------------------------
        # Save artifacts
        # -----------------------------

        os.makedirs(
            os.path.dirname(model_save_path),
            exist_ok=True
        )

        joblib.dump(
            model,
            model_save_path
        )

        preprocessor.save(
            preprocessor_save_path
        )

        print(
            f"Saved UNSW-NB15 model to: "
            f"{model_save_path}"
        )

        print(
            f"Saved preprocessing artifacts to: "
            f"{preprocessor_save_path}"
        )

        # -----------------------------
        # Log artifacts to MLflow
        # -----------------------------

        mlflow.log_artifact(
            model_save_path,
            artifact_path="model"
        )

        mlflow.log_artifact(
            preprocessor_save_path,
            artifact_path="preprocessor"
        )

        # Log sklearn model
        mlflow.sklearn.log_model(
    		model,
    		name="isolation_forest_model",
    		skops_trusted_types=["sklearn.tree._tree.Tree"]
	)
        print("\nMLflow run completed successfully.")

        print(
            f"MLflow Run ID: "
            f"{mlflow.active_run().info.run_id}"
        )

    return model, preprocessor, features


if __name__ == "__main__":
    train_unsw_model()