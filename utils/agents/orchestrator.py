"""
Agent Orchestrator

Coordinates Anomaly Detection, Threat Analysis Agent, and Response Agent
into a unified Security Incident Analysis pipeline.
"""

from utils.agents.threat_agent import threat_agent
from utils.agents.response_agent import response_agent


class SecurityOrchestrator:

    def analyze_log(
        self,
        row,
        anomaly_prediction=None,
        anomaly_score=None,
        port_scan_counts=None,
        ddos_counts=None,
        bruteforce_counts=None
    ):
        """
        Execute the complete security pipeline for a network log:
        Network Log -> Anomaly Detection -> Threat Analysis Agent -> Incident Response Agent -> Final Security Decision
        """
        # Ensure row is a dictionary safely
        if hasattr(row, "to_dict"):
            row_dict = row.to_dict()
        elif isinstance(row, dict):
            row_dict = row
        else:
            row_dict = dict(row)

        # Step 1: Anomaly Detection (if not pre-computed by caller)
        if anomaly_prediction is None or anomaly_score is None:
            import pandas as pd
            from utils.detector import preprocess, predict_anomalies

            df_single = pd.DataFrame([row_dict])
            _, features = preprocess(df_single)
            preds, scores = predict_anomalies(features)
            anomaly_prediction = int(preds[0])
            anomaly_score = float(scores[0])

        # Step 2: Threat Analysis Agent
        threat_result = threat_agent.analyze(
            row=row_dict,
            anomaly_prediction=anomaly_prediction,
            anomaly_score=anomaly_score,
            port_scan_counts=port_scan_counts,
            ddos_counts=ddos_counts,
            bruteforce_counts=bruteforce_counts
        )

        # Step 3: Incident Response Agent
        response_result = response_agent.generate_response(
            threat_result
        )

        # Step 4: Final Security Decision
        threat_type = threat_result.get("threat_type", "Unknown Attack")
        severity = response_result.get("severity") or threat_result.get("severity", "Low")
        confidence = threat_result.get("confidence", "Low")
        recommended_actions = response_result.get("recommended_actions") or response_result.get("actions", [])
        explanation = response_result.get("explanation") or threat_result.get("explanation", "")

        return {
            "anomaly_prediction": int(anomaly_prediction),
            "anomaly_score": float(anomaly_score),
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "recommended_action": recommended_actions,
            "recommended_actions": recommended_actions,
            "explanation": explanation,
            "reason": threat_result.get("reason", explanation),
            "status": threat_result.get("status", "Normal"),
            "priority": response_result.get("priority", "Low"),
            "threat": threat_result,
            "response": response_result
        }


# Reusable orchestrator
security_orchestrator = SecurityOrchestrator()