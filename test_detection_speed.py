import time
import pandas as pd

from utils import db
from utils.detector import preprocess, predict_anomalies
from utils.agents.orchestrator import security_orchestrator
from utils.detector import compute_risk_score


print("=== DETECTION SPEED TEST ===")

# 1. Fetch
start = time.time()

rows = db.fetch_unanalyzed_logs()

print(f"Rows fetched: {len(rows)}")
print(f"Fetch time: {time.time() - start:.2f} seconds")


# 2. DataFrame + preprocessing
start = time.time()

df = pd.DataFrame([dict(r) for r in rows])
df, features = preprocess(df)

print(f"Feature shape: {features.shape}")
print(f"Preprocessing time: {time.time() - start:.2f} seconds")


# 3. Model prediction
start = time.time()

preds, scores = predict_anomalies(features)

print(f"Prediction time: {time.time() - start:.2f} seconds")


# 4. Agent analysis
start = time.time()

suspicious = 0

for _, row in df.iterrows():

    analysis = security_orchestrator.analyze_log(
        row=row.to_dict(),
        anomaly_prediction=preds[_],
        anomaly_score=scores[_]
    )

    if analysis["status"] == "Suspicious":
        suspicious += 1

print(f"Agent analysis time: {time.time() - start:.2f} seconds")
print(f"Suspicious: {suspicious}")


print("=== TEST COMPLETE ===")