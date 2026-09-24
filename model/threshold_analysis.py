import os
import sys
import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

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


def main():

    print("Loading test dataset...")
    df = pd.read_csv(TEST_DATA_PATH)

    print("Loading tuned model...")
    model = joblib.load(MODEL_PATH)

    print("Loading tuned preprocessor...")
    preprocessor = UNSWPreprocessor.load(
        PREPROCESSOR_PATH
    )

    y_true = df["label"].astype(int).values

    X_df = df.drop(
        columns=["label", "attack_cat"],
        errors="ignore"
    )

    X = preprocessor.transform(X_df)

    scores = model.decision_function(X)

    print("\n" + "=" * 90)
    print("             UNSW-NB15 THRESHOLD ANALYSIS")
    print("=" * 90)

    print(
        f"{'Threshold':>12} "
        f"{'Accuracy':>10} "
        f"{'Precision':>10} "
        f"{'Recall':>10} "
        f"{'F1':>10} "
        f"{'FP':>8} "
        f"{'FN':>8} "
        f"{'Pred.Attack':>12}"
    )

    print("-" * 90)

    thresholds = [
    	0.10,
    	0.11,
    	0.12,
   	0.13,
    	0.14,
    	0.15,
    	0.16,
    	0.17,
    	0.18,
    	0.19,
    	0.20,
    	0.21,
    	0.22
    ]
    results = []

    for threshold in thresholds:

        # Lower anomaly score = more anomalous
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

        tn, fp, fn, tp = confusion_matrix(
            y_true,
            y_pred
        ).ravel()

        predicted_attack = int(
            np.sum(y_pred == 1)
        )

        print(
            f"{threshold:>12.2f} "
            f"{accuracy:>10.4f} "
            f"{precision:>10.4f} "
            f"{recall:>10.4f} "
            f"{f1:>10.4f} "
            f"{fp:>8} "
            f"{fn:>8} "
            f"{predicted_attack:>12}"
        )

        results.append({
            "threshold": threshold,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fp": fp,
            "fn": fn,
            "predicted_attack": predicted_attack
        })

    results_df = pd.DataFrame(results)

    # Best F1
    best_f1 = results_df.loc[
        results_df["f1"].idxmax()
    ]

    # Best recall while maintaining precision >= 0.70
    valid_precision = results_df[
        results_df["precision"] >= 0.70
    ]

    print("\n" + "=" * 90)
    print("BEST F1 THRESHOLD")
    print("=" * 90)

    print(
        f"Threshold : {best_f1['threshold']:.2f}"
    )
    print(
        f"Accuracy  : {best_f1['accuracy']:.4f}"
    )
    print(
        f"Precision : {best_f1['precision']:.4f}"
    )
    print(
        f"Recall    : {best_f1['recall']:.4f}"
    )
    print(
        f"F1-Score  : {best_f1['f1']:.4f}"
    )

    if not valid_precision.empty:

        best_recall = valid_precision.loc[
            valid_precision["recall"].idxmax()
        ]

        print("\n" + "=" * 90)
        print("BEST RECALL WITH PRECISION >= 70%")
        print("=" * 90)

        print(
            f"Threshold : {best_recall['threshold']:.2f}"
        )
        print(
            f"Accuracy  : {best_recall['accuracy']:.4f}"
        )
        print(
            f"Precision : {best_recall['precision']:.4f}"
        )
        print(
            f"Recall    : {best_recall['recall']:.4f}"
        )
        print(
            f"F1-Score  : {best_recall['f1']:.4f}"
        )

    print("\nAnalysis completed.")


if __name__ == "__main__":
    main()