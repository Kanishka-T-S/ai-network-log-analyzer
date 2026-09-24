import pytest
import pandas as pd
import numpy as np
from config import Config
from utils.detector import (
    load_unsw_preprocessor,
    preprocess,
    load_model,
    predict_anomalies,
)
from utils.agents.orchestrator import security_orchestrator
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_unsw_preprocessing_feature_count_and_ordering():
    """Verify UNSW preprocessor returns exactly 47 features in preprocessor order."""
    prep = load_unsw_preprocessor()
    assert prep is not None, "Failed to load UNSW preprocessor artifact"
    assert len(prep.feature_names) == 47, f"Expected 47 features, got {len(prep.feature_names)}"

    sample_log = pd.DataFrame([{
        "timestamp": "2026-07-11 10:32:00",
        "source_ip": "192.168.1.5",
        "destination_ip": "8.8.8.8",
        "protocol": "TCP",
        "source_port": 51515,
        "destination_port": 53,
        "bytes_sent": 450,
        "packets": 5,
        "event_type": "DNS Query",
        "severity": "Low"
    }])

    _, features = preprocess(sample_log, model_type="unsw")
    assert features.shape == (1, 47), f"Expected shape (1, 47), got {features.shape}"
    assert features.columns.tolist() == prep.feature_names, "Feature columns ordering does not match preprocessor artifact"

    # Verify no target columns are present in feature matrix
    for col in ["label", "attack_cat", "source_ip", "destination_ip"]:
        assert col not in features.columns, f"Target/metadata leakage: '{col}' found in feature matrix"


def test_model_loading_both_types():
    """Verify both tuned UNSW model and legacy model load successfully."""
    unsw_model = load_model(model_type="unsw")
    assert unsw_model is not None, "Failed to load tuned UNSW model"

    legacy_model = load_model(model_type="legacy")
    assert legacy_model is not None, "Failed to load legacy model"


def test_unsw_anomaly_prediction_and_threshold():
    """Verify UNSW anomaly prediction returns 1 (Normal) or -1 (Anomaly) with decision score."""
    sample_log = pd.DataFrame([{
        "source_port": 51515,
        "destination_port": 53,
        "bytes_sent": 450,
        "packets": 5,
        "protocol": "TCP",
        "event_type": "DNS Query"
    }])

    _, features = preprocess(sample_log, model_type="unsw")
    preds, scores = predict_anomalies(features, model_type="unsw", threshold=Config.UNSW_DECISION_THRESHOLD)

    assert len(preds) == 1
    assert len(scores) == 1
    assert preds[0] in (1, -1), f"Unexpected prediction value: {preds[0]}"
    assert isinstance(float(scores[0]), float), "Score must be a float"


def test_security_orchestrator_unsw_integration():
    """Verify SecurityOrchestrator works end-to-end with the tuned UNSW model."""
    normal_log = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "bytes_sent": 120,
        "packets": 2,
        "protocol": "UDP",
        "event_type": "DNS Query",
        "severity": "Low"
    }

    result = security_orchestrator.analyze_log(row=normal_log)

    required_keys = [
        "anomaly_prediction", "anomaly_score", "threat_type",
        "severity", "confidence", "recommended_action", "explanation"
    ]
    for key in required_keys:
        assert key in result, f"Missing required key '{key}' in SecurityOrchestrator output"

    assert result["anomaly_prediction"] in (1, -1)
    assert isinstance(result["anomaly_score"], float)


def test_flask_health_endpoint(client):
    """Test GET /health endpoint."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "network-log-analyzer"


def test_flask_analyze_endpoint(client):
    """Test POST /analyze endpoint using tuned UNSW model."""
    payload = {
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.1",
        "destination_port": 22,
        "packets": 120,
        "bytes_sent": 5000,
        "protocol": "TCP",
        "event_type": "Login Failure"
    }
    res = client.post("/analyze", json=payload)
    assert res.status_code == 200
    data = res.get_json()

    for key in ["anomaly_prediction", "anomaly_score", "threat_type", "severity", "confidence", "recommended_action", "explanation"]:
        assert key in data, f"Missing key '{key}' in API response"

    assert data["threat_type"] == "Brute Force Login"


def test_model_comparison_identical_logs():
    """Compare identical test logs processed by Legacy vs Tuned UNSW models."""
    test_logs = pd.DataFrame([
        {
            "source_ip": "192.168.1.5",
            "destination_ip": "8.8.8.8",
            "source_port": 51515,
            "destination_port": 53,
            "bytes_sent": 450,
            "packets": 5,
            "protocol": "TCP",
            "event_type": "DNS Query"
        },
        {
            "source_ip": "192.168.1.12",
            "destination_ip": "10.0.0.20",
            "source_port": 53000,
            "destination_port": 22,
            "bytes_sent": 1200,
            "packets": 300,
            "protocol": "TCP",
            "event_type": "Login Failure"
        },
        {
            "source_ip": "192.168.1.18",
            "destination_ip": "185.23.44.9",
            "source_port": 54000,
            "destination_port": 443,
            "bytes_sent": 50000000,
            "packets": 15000,
            "protocol": "TCP",
            "event_type": "File Transfer"
        }
    ])

    # 1. Legacy Model predictions
    _, legacy_feats = preprocess(test_logs, model_type="legacy")
    legacy_preds, legacy_scores = predict_anomalies(legacy_feats, model_type="legacy")

    # 2. Tuned UNSW Model predictions
    _, unsw_feats = preprocess(test_logs, model_type="unsw")
    unsw_preds, unsw_scores = predict_anomalies(unsw_feats, model_type="unsw", threshold=Config.UNSW_DECISION_THRESHOLD)

    assert len(legacy_preds) == 3
    assert len(unsw_preds) == 3
    assert unsw_feats.shape[1] == 47
    assert legacy_feats.shape[1] == 6

    print("\n--- MODEL COMPARISON RESULTS ---")
    for i in range(3):
        print(f"Log {i+1} [{test_logs.loc[i, 'event_type']}]:")
        print(f"  Legacy Model -> Pred: {legacy_preds[i]}, Score: {legacy_scores[i]:.4f}")
        print(f"  Tuned UNSW   -> Pred: {unsw_preds[i]}, Score: {unsw_scores[i]:.4f}")
