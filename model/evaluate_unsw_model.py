"""
Evaluate the tuned UNSW-NB15 Isolation Forest model
and compare multiple decision thresholds.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    accuracy_score,
)


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.unsw_preprocessor import UNSWPreprocessor


TEST_DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "UNSW_NB15_testing-set.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "anomaly_model_unsw_nb15_tuned.pkl"
)

PREPROCESSOR_PATH = os.path.join(
    BASE_DIR,
    "model",
    "unsw_nb15_preprocessor_tuned.pkl"
)


# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

def evaluate_model():

    for path in [
        TEST_DATA_PATH,
        MODEL_PATH,
        PREPROCESSOR_PATH
    ]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Required file not found:\n{path}"
            )

    print("\nLoading UNSW-NB15 testing dataset...")
    test_df = pd.read_csv(TEST_DATA_PATH)

    print(f"Testing dataset size: {len(test_df)}")

    print("Loading tuned model...")
    model = joblib.load(MODEL_PATH)

    print("Loading tuned preprocessor...")
    preprocessor = UNSWPreprocessor.load(
        PREPROCESSOR_PATH
    )

    # -----------------------------------------------------
    # Ground truth
    # -----------------------------------------------------

    if "label" not in test_df.columns:
        raise ValueError(
            "Testing dataset does not contain 'label'."
        )

    y_true = test_df["label"].astype(int).values

    # -----------------------------------------------------
    # Remove target columns
    # -----------------------------------------------------

    X_df = test_df.drop(
        columns=["label", "attack_cat"],
        errors="ignore"
    )

    # -----------------------------------------------------
    # Preprocessing
    # -----------------------------------------------------

    X_test = preprocessor.transform(X_df)

    if X_test.shape[1] != 47:
        raise ValueError(
            f"Expected 47 features, got {X_test.shape[1]}"
        )

    print(f"Feature count: {X_test.shape[1]}")

    # -----------------------------------------------------
    # Anomaly scores
    # -----------------------------------------------------

    print("\nCalculating anomaly scores...")

    scores = model.decision_function(X_test)

    # -----------------------------------------------------
    # Ground truth distribution
    # -----------------------------------------------------

    actual_normal = int(np.sum(y_true == 0))
    actual_attack = int(np.sum(y_true == 1))

    print("\nGROUND TRUTH")
    print("-" * 60)
    print(f"Normal : {actual_normal}")
    print(f"Attack : {actual_attack}")

    # -----------------------------------------------------
    # Threshold evaluation
    # -----------------------------------------------------

    thresholds = [
        -0.05,
        -0.02,
        0.00,
        0.02,
        0.04,
        0.05,
        0.06,
        0.07,
        0.08,
        0.09,
        0.10,
        0.11,
    ]

    results = []

    print("\nTHRESHOLD COMPARISON")
    print("=" * 80)
    print(
        f"{'Threshold':>10} "
        f"{'Accuracy':>10} "
        f"{'Precision':>10} "
        f"{'Recall':>10} "
        f"{'F1':>10} "
        f"{'FP':>8} "
        f"{'FN':>8}"
    )
    print("-" * 80)

    for threshold in thresholds:

        # Score below threshold = anomaly
        y_pred = np.where(
            scores < threshold,
            1,
            0
        )

        accuracy = accuracy_score(
            y_true,
            y_pred
        )

        precision = precision_score(
            y_true,
            y_pred,
            zero_division=0
        )

        recall = recall_score(
            y_true,
            y_pred,
            zero_division=0
        )

        f1 = f1_score(
            y_true,
            y_pred,
            zero_division=0
        )

        cm = confusion_matrix(
            y_true,
            y_pred,
            labels=[0, 1]
        )

        tn, fp, fn, tp = cm.ravel()

        results.append({
            "threshold": threshold,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fp": int(fp),
            "fn": int(fn),
            "tn": int(tn),
            "tp": int(tp),
        })

        print(
            f"{threshold:>10.2f} "
            f"{accuracy:>10.4f} "
            f"{precision:>10.4f} "
            f"{recall:>10.4f} "
            f"{f1:>10.4f} "
            f"{fp:>8} "
            f"{fn:>8}"
        )

    # -----------------------------------------------------
    # Best threshold by F1
    # -----------------------------------------------------

    best = max(
        results,
        key=lambda x: x["f1"]
    )

    print("\n" + "=" * 80)
    print("BEST THRESHOLD BY F1")
    print("=" * 80)

    print(f"Threshold : {best['threshold']:.2f}")
    print(f"Accuracy  : {best['accuracy']:.4f}")
    print(f"Precision : {best['precision']:.4f}")
    print(f"Recall    : {best['recall']:.4f}")
    print(f"F1-Score  : {best['f1']:.4f}")
    print(f"False Positives: {best['fp']}")
    print(f"False Negatives: {best['fn']}")
    print(f"True Negatives : {best['tn']}")
    print(f"True Positives : {best['tp']}")

    # -----------------------------------------------------
    # Score statistics
    # -----------------------------------------------------

    print("\nANOMALY SCORE STATISTICS")
    print("-" * 60)
    print(f"Minimum : {scores.min():.6f}")
    print(f"Maximum : {scores.max():.6f}")
    print(f"Mean    : {scores.mean():.6f}")

    print("\nEvaluation completed successfully.\n")

    return {
        "dataset_size": len(test_df),
        "best_threshold": float(best["threshold"]),
        "accuracy": float(best["accuracy"]),
        "precision": float(best["precision"]),
        "recall": float(best["recall"]),
        "f1_score": float(best["f1"]),
        "false_positives": int(best["fp"]),
        "false_negatives": int(best["fn"]),
        "true_negatives": int(best["tn"]),
        "true_positives": int(best["tp"]),
        "feature_count": int(X_test.shape[1]),
    }


if __name__ == "__main__":
    evaluate_model()