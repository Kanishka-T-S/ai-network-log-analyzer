"""
Threat Analysis Agent

Combines ML anomaly detection, existing security rules,
and network-log context to make a structured incident decision.
"""

from utils.classifier import classify_threat, generate_description


class ThreatAnalysisAgent:

    def analyze(
        self,
        row,
        anomaly_prediction,
        anomaly_score,
        port_scan_counts=None,
        ddos_counts=None,
        bruteforce_counts=None
    ):
        """
        Analyze a network log and produce a structured threat assessment.
        """

        # Convert ML prediction into a readable value
        ml_status = (
            "Normal"
            if anomaly_prediction == 1
            else "Suspicious"
        )

        # Base log row severity
        raw_severity = row.get("severity", "Low")
        severity = raw_severity.capitalize() if isinstance(raw_severity, str) and raw_severity else "Low"

        # Use the existing security classifier as evidence
        rule_threat = classify_threat(
            row,
            port_scan_ip_counts=port_scan_counts,
            ddos_dest_counts=ddos_counts,
            bruteforce_ip_counts=bruteforce_counts
        )

        # Collect evidence
        evidence = []

        if ml_status == "Suspicious":
            evidence.append(
                "Isolation Forest detected anomalous behavior"
            )

        if rule_threat != "Unknown Attack":
            evidence.append(
                f"Security rules indicate {rule_threat}"
            )

        packets = row.get("packets", 0) or 0
        bytes_sent = row.get("bytes_sent", 0) or 0
        destination_port = row.get("destination_port", 0) or 0

        if packets > 1000:
            evidence.append(
                f"High packet volume detected: {packets}"
            )

        if bytes_sent > 1_000_000:
            evidence.append(
                f"Large data transfer detected: {bytes_sent} bytes"
            )

        if destination_port in (22, 23, 3389):
            evidence.append(
                f"Sensitive destination port detected: {destination_port}"
            )

        # Determine final threat, confidence, and narrative reason
        if ml_status == "Normal":
            if rule_threat == "Unknown Attack":
                final_threat = "Normal Activity"
                confidence = "High"
                reason = "Traffic metrics align with normal operational baseline."
                if not evidence:
                    evidence.append("Traffic metrics within normal operating parameters")
            else:
                # ML considered normal, but rule triggered (e.g., failed logins or port probes)
                final_threat = rule_threat
                confidence = "Medium"
                reason = generate_description(rule_threat, row)
        elif rule_threat != "Unknown Attack":
            final_threat = rule_threat
            confidence = "High" if len(evidence) >= 2 else "Medium"
            reason = generate_description(rule_threat, row)
        else:
            final_threat = "Unknown Attack"
            confidence = "Medium"
            reason = generate_description("Unknown Attack", row)

        # Adjust severity level for high-risk threat types
        if final_threat in ("DDoS", "Data Exfiltration") and severity in ("Low", "Medium"):
            severity = "High"
        elif final_threat == "Malware Communication" and severity == "Low":
            severity = "Medium"

        return {
            "status": ml_status,
            "threat_type": final_threat,
            "severity": severity,
            "confidence": confidence,
            "anomaly_score": float(anomaly_score),
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "destination_port": destination_port,
            "reason": reason,
            "explanation": reason,
            "evidence": evidence
        }


# Create reusable agent instance
threat_agent = ThreatAnalysisAgent()