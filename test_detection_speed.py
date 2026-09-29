import time
import pandas as pd
import pytest

from utils import db
from utils.detector import preprocess, predict_anomalies
from utils.agents.orchestrator import security_orchestrator


def test_detection_speed():

    print("\n=== DETECTION SPEED TEST ===")

    # ---------------------------------------------------------
    # 1. Fetch unanalyzed logs
    # ---------------------------------------------------------
    start = time.time()

    rows = db.fetch_unanalyzed_logs()

    fetch_time = time.time() - start

    print(f"Rows fetched: {len(rows)}")
    print(f"Fetch time: {fetch_time:.2f} seconds")

    # No logs available → skip benchmark
    if not rows:
        pytest.skip("No unanalyzed logs available for detection speed test")

    # ---------------------------------------------------------
    # 2. DataFrame + preprocessing
    # ---------------------------------------------------------
    start = time.time()

    df = pd.DataFrame([dict(r) for r in rows])
    df, features = preprocess(df)

    preprocessing_time = time.time() - start

    print(f"Feature shape: {features.shape}")
    print(f"Preprocessing time: {preprocessing_time:.2f} seconds")

    # Safety check
    assert len(features) > 0, "Preprocessing produced zero feature rows"

    # ---------------------------------------------------------
    # 3. Model prediction
    # ---------------------------------------------------------
    start = time.time()

    preds, scores = predict_anomalies(features)

    prediction_time = time.time() - start

    print(f"Prediction time: {prediction_time:.2f} seconds")

    # Verify prediction output
    assert len(preds) == len(features)
    assert len(scores) == len(features)

    # ---------------------------------------------------------
    # 4. Agent analysis
    # ---------------------------------------------------------
    start = time.time()

    suspicious = 0

    for index, (_, row) in enumerate(df.iterrows()):

        analysis = security_orchestrator.analyze_log(
            row=row.to_dict(),
            anomaly_prediction=preds[index],
            anomaly_score=scores[index]
        )

        assert "status" in analysis

        if analysis["status"] == "Suspicious":
            suspicious += 1

    agent_time = time.time() - start

    print(f"Agent analysis time: {agent_time:.2f} seconds")
    print(f"Suspicious: {suspicious}")

    print("=== TEST COMPLETE ===")

    # Basic performance assertions
    assert fetch_time >= 0
    assert preprocessing_time >= 0
    assert prediction_time >= 0
    assert agent_time >= 0