from utils.response_engine import get_response_actions


class ResponseAgent:

    def generate_response(self, threat_result):
        """
        Generate a structured incident response plan based on
        the output of ThreatAnalysisAgent.
        """
        threat_type = threat_result.get(
            "threat_type",
            "Unknown Attack"
        )

        confidence = threat_result.get(
            "confidence",
            "Low"
        )

        severity = threat_result.get(
            "severity",
            "Low"
        )

        reason = threat_result.get(
            "reason"
        ) or threat_result.get(
            "explanation",
            "Anomalous network activity detected."
        )

        # Retrieve recommended remediation actions
        actions = get_response_actions(threat_type)

        # Determine response priority based on threat type, severity, and confidence
        if threat_type == "Normal Activity":
            priority = "Low"
            response_explanation = (
                "Traffic is within normal operational baseline. "
                "No immediate incident mitigation required."
            )
        elif severity in ("Critical", "High") or confidence == "High":
            priority = "High"
            response_explanation = (
                f"High priority incident ({threat_type}, {severity} severity). "
                "Immediate mitigation and administrator notification recommended."
            )
        elif severity == "Medium" or confidence == "Medium":
            priority = "Medium"
            response_explanation = (
                f"Medium priority finding ({threat_type}). "
                "Analysts should review evidence and execute recommended actions."
            )
        else:
            priority = "Low"
            response_explanation = (
                f"Low priority finding ({threat_type}). "
                "Monitor source host for recurring suspicious events."
            )

        return {
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "priority": priority,
            "recommended_actions": actions,
            "actions": actions,
            "reason": reason,
            "explanation": response_explanation
        }


response_agent = ResponseAgent()