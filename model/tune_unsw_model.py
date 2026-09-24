"""
Hyperparameter and Threshold Tuning Script for UNSW-NB15 Anomaly Detection Model.
Saves best candidate model to model/anomaly_model_unsw_nb15_tuned.pkl
"""
import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.unsw_preprocessor import UNSWPreprocessor
from model.evaluate_unsw_model import build_evaluation_dataset


def run_experiments():
    # 1. Load training data
    train_path = os.path.join(BASE_DIR, "data", "UNSW_NB15_training-set.csv")
    train_df = pd.read_csv(train_path).dropna(how="all").reset_index(drop=True)

    # 2. Load evaluation data
    eval_df = build_evaluation_dataset()

    # 3. Fit preprocessor on training data
    preprocessor = UNSWPreprocessor()
    X_train = preprocessor.fit_transform(train_df)

    # Extract target from evaluation set
    if "label" in eval_df.columns:
        y_eval = eval_df["label"].astype(int).values
    else:
        y_eval = (eval_df["attack_cat"] != "Normal").astype(int).values

    eval_df_prediction = eval_df.drop(columns=["label", "attack_cat"], errors="ignore")
    X_eval = preprocessor.transform(eval_df_prediction)

    # 4. Define hyperparameter grid
    contaminations = [0.01, 0.02, 0.03, 0.04, 0.05, 0.08]
    n_estimators_list = [100, 200, 300]
    max_samples_list = ["auto", 0.8, 256]
    max_features_list = [1.0, 0.8]

    # Baseline configuration (Experiment 1)
    experiments = []

    # Run Baseline first
    base_model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )
    base_model.fit(X_train)
    base_preds = np.where(base_model.predict(X_eval) == -1, 1, 0)
    cm_base = confusion_matrix(y_eval, base_preds)
    tn, fp, fn, tp = cm_base.ravel() if cm_base.shape == (2, 2) else (0, 0, 0, 0)
    
    base_res = {
        "name": "Baseline Model",
        "contamination": 0.02,
        "params": "n_est=200, samples=auto, feat=1.0",
        "precision": precision_score(y_eval, base_preds, zero_division=0),
        "recall": recall_score(y_eval, base_preds, zero_division=0),
        "f1": f1_score(y_eval, base_preds, zero_division=0),
        "accuracy": accuracy_score(y_eval, base_preds),
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "tn": tn,
        "model": base_model,
        "threshold": None
    }
    experiments.append(base_res)

    print("Running hyperparameter grid search across IsolationForest configurations...")

    exp_counter = 1
    best_f1 = base_res["f1"]
    best_exp = base_res

    for cont in contaminations:
        for n_est in n_estimators_list:
            for max_samp in max_samples_list:
                for max_feat in max_features_list:
                    exp_counter += 1
                    model = IsolationForest(
                        n_estimators=n_est,
                        contamination=cont,
                        max_samples=max_samp,
                        max_features=max_feat,
                        random_state=42,
                        n_jobs=-1
                    )
                    model.fit(X_train)
                    scores = model.decision_function(X_eval)

                    # Evaluate standard prediction (threshold=0 on decision_function)
                    preds_default = np.where(model.predict(X_eval) == -1, 1, 0)
                    cm = confusion_matrix(y_eval, preds_default)
                    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
                    prec = precision_score(y_eval, preds_default, zero_division=0)
                    rec = recall_score(y_eval, preds_default, zero_division=0)
                    f1 = f1_score(y_eval, preds_default, zero_division=0)
                    acc = accuracy_score(y_eval, preds_default)

                    param_str = f"n_est={n_est}, samp={max_samp}, feat={max_feat}"
                    exp_entry = {
                        "name": f"Exp {exp_counter}",
                        "contamination": cont,
                        "params": param_str,
                        "precision": prec,
                        "recall": rec,
                        "f1": f1,
                        "accuracy": acc,
                        "fp": fp,
                        "fn": fn,
                        "tp": tp,
                        "tn": tn,
                        "model": model,
                        "threshold": None
                    }
                    experiments.append(exp_entry)

                    # Also test decision threshold offset tuning
                    for thresh_offset in [-0.05, -0.02, 0.02, 0.05]:
                        # Predict anomaly if score < thresh_offset
                        preds_thresh = np.where(scores < thresh_offset, 1, 0)
                        cm_t = confusion_matrix(y_eval, preds_thresh)
                        tn_t, fp_t, fn_t, tp_t = cm_t.ravel() if cm_t.shape == (2, 2) else (0, 0, 0, 0)
                        prec_t = precision_score(y_eval, preds_thresh, zero_division=0)
                        rec_t = recall_score(y_eval, preds_thresh, zero_division=0)
                        f1_t = f1_score(y_eval, preds_thresh, zero_division=0)
                        acc_t = accuracy_score(y_eval, preds_thresh)

                        thresh_entry = {
                            "name": f"Exp {exp_counter} (thr={thresh_offset})",
                            "contamination": cont,
                            "params": f"{param_str}, thr={thresh_offset}",
                            "precision": prec_t,
                            "recall": rec_t,
                            "f1": f1_t,
                            "accuracy": acc_t,
                            "fp": fp_t,
                            "fn": fn_t,
                            "tp": tp_t,
                            "tn": tn_t,
                            "model": model,
                            "threshold": thresh_offset
                        }
                        experiments.append(thresh_entry)

    # Sort experiments by F1-score descending, then Recall descending
    sorted_exps = sorted(experiments, key=lambda x: (x["f1"], x["recall"], -x["fp"]), reverse=True)
    best_candidate = sorted_exps[0]

    # Print comparison table
    print("\n" + "=" * 105)
    print("                      HYPERPARAMETER & THRESHOLD EXPERIMENT COMPARISON TABLE")
    print("=" * 105)
    header = f"{'Model / Exp':<28} | {'Contam':<6} | {'Parameters':<35} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FP':<4} | {'FN':<4}"
    print(header)
    print("-" * 105)

    # Display baseline, top 10 candidates, and selected tuned model
    display_rows = [base_res] + sorted_exps[:10]
    seen_names = set()
    for row in display_rows:
        if row["name"] in seen_names:
            continue
        seen_names.add(row["name"])
        p_str = (row["params"][:33] + "..") if len(row["params"]) > 35 else row["params"]
        line = f"{row['name']:<28} | {row['contamination']:<6.2f} | {p_str:<35} | {row['precision']:<6.4f} | {row['recall']:<6.4f} | {row['f1']:<6.4f} | {row['fp']:<4} | {row['fn']:<4}"
        print(line)

    print("=" * 105 + "\n")

    # Save best tuned model separately
    tuned_model_path = os.path.join(BASE_DIR, "model", "anomaly_model_unsw_nb15_tuned.pkl")
    tuned_prep_path = os.path.join(BASE_DIR, "model", "unsw_nb15_preprocessor_tuned.pkl")

    joblib.dump(best_candidate["model"], tuned_model_path)
    preprocessor.save(tuned_prep_path)

    print(f"Saved best tuned model to: {tuned_model_path}")
    print(f"Saved tuned preprocessor artifact to: {tuned_prep_path}")
    print(f"Best Tuned Configuration: {best_candidate['name']} ({best_candidate['params']})")
    print(f"  F1-Score: {best_candidate['f1']:.4f} | Precision: {best_candidate['precision']:.4f} | Recall: {best_candidate['recall']:.4f} | FP: {best_candidate['fp']} | FN: {best_candidate['fn']}")

    return sorted_exps, best_candidate


if __name__ == "__main__":
    run_experiments()
