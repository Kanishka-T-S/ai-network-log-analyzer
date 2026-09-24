"""
Calibrate Isolation Forest anomaly scores into an attack probability.

Uses the official UNSW-NB15 testing set:
    label = 0 -> Normal
    label = 1 -> Attack
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    brier_score_loss,
)

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.unsw_preprocessor import UNSWPreprocessor


TEST_DATA_PATH = os.path.join(
    BASE_DIR, "data", "UNSW_NB15_testing-set.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR, "model", "anomaly_model_unsw_nb15_tuned.pkl"
)

PREPROCESSOR_PATH = os.path.join(
    BASE_DIR, "model", "unsw_nb15_preprocessor_tuned.pkl"
)

CALIBRATOR_PATH = os.path.join(
    BASE_DIR, "model", "risk_calibrator.pkl"
)


def main():

    print("Loading UNSW-NB15 testing dataset...")
    df = pd.read_csv(TEST_DATA_PATH)

    print(f"Dataset size: {len(df)}")

    y_true = df["label"].astype(int).values

    X_df = df.drop(
        columns=["label", "attack_cat"],
        errors="ignore"
    )

    print("Loading preprocessor...")
    preprocessor = UNSWPreprocessor.load(
        PREPROCESSOR_PATH
    )

    print("Transforming features...")
    X = preprocessor.transform(X_df)

    print("Loading Isolation Forest...")
    model = joblib.load(MODEL_PATH)

    print("Calculating anomaly scores...")
    scores = model.decision_function(X)

    # Isolation Forest:
    # lower score = more anomalous
    #
    # Logistic regression needs a higher value
    # to represent greater attack likelihood.
    X_score = (-scores).reshape(-1, 1)

    print("Training probability calibrator...")

    calibrator = LogisticRegression(
        random_state=42,
        max_iter=1000
    )

    calibrator.fit(X_score, y_true)

    probabilities = calibrator.predict_proba(X_score)[:, 1]

    predictions = (probabilities >= 0.5).astype(int)

    accuracy = accuracy_score(
        y_true,
        predictions
    )

    precision = precision_score(
        y_true,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        predictions,
        zero_division=0
    )

    brier = brier_score_loss(
        y_true,
        probabilities
    )

    print("\n" + "=" * 60)
    print("RISK CALIBRATION RESULTS")
    print("=" * 60)

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print(f"Brier Score: {brier:.4f}")

    print("\nExample score → probability mapping:")

    for score in [
        -0.15,
        -0.10,
        -0.05,
        0.00,
        0.05,
        0.10,
        0.15,
        0.20
    ]:

        probability = calibrator.predict_proba(
            np.array([[-score]])
        )[0, 1]

        print(
            f"Score {score:7.3f}"
            f" -> Risk {probability * 100:6.2f}%"
        )

    joblib.dump(
        calibrator,
        CALIBRATOR_PATH
    )

    print("\nCalibrator saved:")
    print(CALIBRATOR_PATH)

    print("\nCalibration completed successfully.")


if __name__ == "__main__":
    main()