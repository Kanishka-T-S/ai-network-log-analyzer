"""
Threat Analysis Agent

Combines ML anomaly detection, UNSW-NB15 attack labels,
existing security rules, and network-log context.
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

        # ---------------------------------------------------------
        # 1. ML anomaly status
        # ---------------------------------------------------------
        ml_status = (
            "Normal"
            if anomaly_prediction == 1
            else "Suspicious"
        )

        # ---------------------------------------------------------
        # 2. Severity
        # ---------------------------------------------------------
        raw_severity = row.get("severity", "Low")

        severity = (
            raw_severity.capitalize()
            if isinstance(raw_severity, str) and raw_severity
            else "Low"
        )

        # ---------------------------------------------------------
        # 3. UNSW-NB15 attack category
        # ---------------------------------------------------------
        attack_cat = row.get("attack_cat")

        if attack_cat is not None:
            attack_cat = str(attack_cat).strip()

        # Handle empty / missing attack category
        if not attack_cat or attack_cat.lower() in (
            "nan",
            "none",
            "null",
            ""
        ):
            attack_cat = None

        # Map UNSW-NB15 labels to readable threat names
        unsw_threat_map = {
            "normal": "Normal Activity",
            "exploits": "Exploit Attack",
            "fuzzers": "Fuzzing Attack",
            "reconnaissance": "Reconnaissance Attack",
            "dos": "DDoS Attack",
            "backdoor": "Backdoor Attack",
            "analysis": "Analysis Attack",
            "generic": "Generic Attack",
            "shellcode": "Shellcode Attack",
            "worms": "Worm Attack"
        }

        dataset_threat = None

        if attack_cat:
            dataset_threat = unsw_threat_map.get(
                attack_cat.lower()
            )

        # ---------------------------------------------------------
        # 4. Existing security-rule classifier
        # ---------------------------------------------------------
        rule_threat = classify_threat(
            row,
            port_scan_ip_counts=port_scan_counts,
            ddos_dest_counts=ddos_counts,
            bruteforce_ip_counts=bruteforce_counts
        )

        # ---------------------------------------------------------
        # 5. Evidence
        # ---------------------------------------------------------
        evidence = []

        if ml_status == "Suspicious":
            evidence.append(
                "Isolation Forest detected anomalous behavior"
            )

        # Dataset label evidence
        if dataset_threat and dataset_threat != "Normal Activity":
            evidence.append(
                f"UNSW-NB15 dataset label indicates {dataset_threat}"
            )

        # Existing rule evidence
        if rule_threat not in (
            "Unknown Attack",
            "Normal Activity"
        ):
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

        # ---------------------------------------------------------
        # 6. Determine final threat
        # ---------------------------------------------------------

        # IMPORTANT:
        # If UNSW-NB15 contains an explicit attack_cat,
        # use it as the threat type.
        if dataset_threat:

            final_threat = dataset_threat

            if dataset_threat == "Normal Activity":
                confidence = "High"
                reason = (
                    "UNSW-NB15 dataset label identifies this traffic "
                    "as normal activity."
                )

                if not evidence:
                    evidence.append(
                        "Traffic labeled as normal in UNSW-NB15 dataset"
                    )

            else:
                confidence = "High"

                reason = (
                    f"UNSW-NB15 dataset label identifies this traffic "
                    f"as {dataset_threat}."
                )

        # ---------------------------------------------------------
        # 7. Otherwise use existing ML + security rules
        # ---------------------------------------------------------
        elif rule_threat not in (
            "Unknown Attack",
            "Normal Activity"
        ):

            final_threat = rule_threat

            confidence = (
                "High"
                if len(evidence) >= 2
                else "Medium"
            )

            reason = generate_description(
                rule_threat,
                row
            )

        elif ml_status == "Normal":

            final_threat = "Normal Activity"
            confidence = "High"

            reason = (
                "Traffic metrics align with normal "
                "operational baseline."
            )

            if not evidence:
                evidence.append(
                    "Traffic metrics within normal operating parameters"
                )

        else:

            final_threat = "Unknown Attack"
            confidence = "Medium"

            reason = generate_description(
                "Unknown Attack",
                row
            )

        # ---------------------------------------------------------
        # 8. Severity adjustment
        # ---------------------------------------------------------
        if final_threat in (
            "DDoS",
            "DDoS Attack",
            "Data Exfiltration"
        ) and severity in ("Low", "Medium"):
            severity = "High"


        elif final_threat == "Malware Communication" and severity == "Low":

            severity = "Medium"

        # ---------------------------------------------------------
        # 9. Return structured result
        # ---------------------------------------------------------
        return {
            "status": ml_status,
            "threat_type": final_threat,
            "severity": severity,
            "confidence": confidence,
            "anomaly_score": float(anomaly_score),

            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "destination_port": destination_port,

            "attack_cat": attack_cat,

            "reason": reason,
            "explanation": reason,
            "evidence": evidence
        }


# Create reusable agent instance
threat_agent = ThreatAnalysisAgent()