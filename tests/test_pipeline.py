import pytest
from utils.agents.threat_agent import ThreatAnalysisAgent, threat_agent
from utils.agents.response_agent import ResponseAgent, response_agent
from utils.agents.orchestrator import SecurityOrchestrator, security_orchestrator
from utils.classifier import classify_threat, generate_description
from utils.response_engine import get_response_actions


# ---------------------------------------------------------------------------
# 1. Normal Network Traffic Test
# ---------------------------------------------------------------------------
def test_normal_network_traffic():
    normal_row = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "bytes_sent": 120,
        "packets": 2,
        "event_type": "DNS Query",
        "severity": "Low"
    }

    result = security_orchestrator.analyze_log(
        row=normal_row,
        anomaly_prediction=1,
        anomaly_score=0.25
    )

    assert result["anomaly_prediction"] == 1
    assert result["status"] == "Normal"
    assert result["threat_type"] == "Normal Activity"
    assert result["confidence"] == "High"
    assert result["priority"] == "Low"
    assert "No immediate action required" in result["recommended_action"]
    assert "normal operational baseline" in result["explanation"].lower()


# ---------------------------------------------------------------------------
# 2. Port Scan Test
# ---------------------------------------------------------------------------
def test_port_scan_detection():
    port_scan_row = {
        "source_ip": "10.0.0.88",
        "destination_ip": "192.168.1.1",
        "destination_port": 8080,
        "bytes_sent": 300,
        "packets": 5,
        "event_type": "Connection",
        "severity": "Medium"
    }

    result = security_orchestrator.analyze_log(
        row=port_scan_row,
        anomaly_prediction=-1,
        anomaly_score=-0.45,
        port_scan_counts={"10.0.0.88": 10}
    )

    assert result["threat_type"] == "Port Scan"
    assert result["anomaly_prediction"] == -1
    assert "Block source IP" in result["recommended_action"]
    assert "Close unused/unnecessary ports" in result["recommended_action"]


# ---------------------------------------------------------------------------
# 3. DDoS Activity Test
# ---------------------------------------------------------------------------
def test_ddos_detection():
    ddos_row = {
        "source_ip": "172.16.0.40",
        "destination_ip": "10.0.0.1",
        "destination_port": 80,
        "bytes_sent": 50000,
        "packets": 2500,
        "event_type": "Connection",
        "severity": "Medium"
    }

    result = security_orchestrator.analyze_log(
        row=ddos_row,
        anomaly_prediction=-1,
        anomaly_score=-0.85
    )

    assert result["threat_type"] == "DDoS"
    assert result["severity"] == "High"
    assert result["priority"] == "High"
    assert "Rate limit traffic from source" in result["recommended_action"]
    assert "Block malicious IP range" in result["recommended_action"]


# ---------------------------------------------------------------------------
# 4. Brute-Force / Login Failure Activity Test
# ---------------------------------------------------------------------------
def test_brute_force_login_activity():
    brute_force_row = {
        "source_ip": "203.0.113.5",
        "destination_ip": "192.168.1.100",
        "destination_port": 22,
        "bytes_sent": 800,
        "packets": 12,
        "event_type": "Login Failure",
        "severity": "High"
    }

    result = security_orchestrator.analyze_log(
        row=brute_force_row,
        anomaly_prediction=-1,
        anomaly_score=-0.60,
        bruteforce_counts={"203.0.113.5": 6}
    )

    assert result["threat_type"] == "Brute Force Login"
    assert result["confidence"] == "High"
    assert "Block source IP" in result["recommended_action"]
    assert "Force password reset for targeted account" in result["recommended_action"]


# ---------------------------------------------------------------------------
# 5. ML Anomaly Detected + Rule-Based Threat Detected Test
# ---------------------------------------------------------------------------
def test_ml_anomaly_and_rule_threat_detected():
    exfil_row = {
        "source_ip": "192.168.1.50",
        "destination_ip": "198.51.100.2",
        "destination_port": 443,
        "bytes_sent": 5000000,
        "packets": 400,
        "event_type": "File Transfer",
        "severity": "Medium"
    }

    threat_assessment = threat_agent.analyze(
        row=exfil_row,
        anomaly_prediction=-1,
        anomaly_score=-0.72
    )

    assert threat_assessment["status"] == "Suspicious"
    assert threat_assessment["threat_type"] == "Data Exfiltration"
    assert threat_assessment["confidence"] == "High"
    assert threat_assessment["severity"] == "High"
    assert len(threat_assessment["evidence"]) >= 2


# ---------------------------------------------------------------------------
# 6. ML Anomaly Detected But No Specific Rule Matched Test
# ---------------------------------------------------------------------------
def test_ml_anomaly_detected_no_rule_matched():
    unknown_anomaly_row = {
        "source_ip": "10.0.0.99",
        "destination_ip": "172.16.0.4",
        "destination_port": 8080,
        "bytes_sent": 250,
        "packets": 10,
        "event_type": "Custom Protocol",
        "severity": "Low"
    }

    result = security_orchestrator.analyze_log(
        row=unknown_anomaly_row,
        anomaly_prediction=-1,
        anomaly_score=-0.35
    )

    assert result["status"] == "Suspicious"
    assert result["threat_type"] == "Unknown Attack"
    assert result["confidence"] == "Medium"
    assert result["priority"] == "Medium"
    assert "Escalate to a security analyst" in result["recommended_action"]
    assert "manual review recommended" in result["reason"].lower()


# ---------------------------------------------------------------------------
# 7. Missing Optional Fields Test
# ---------------------------------------------------------------------------
def test_missing_optional_fields():
    incomplete_row = {
        "source_ip": "10.0.0.1"
    }

    # Must execute safely without throwing KeyError or TypeError
    result = security_orchestrator.analyze_log(row=incomplete_row)

    assert "anomaly_prediction" in result
    assert "anomaly_score" in result
    assert "threat_type" in result
    assert "severity" in result
    assert "confidence" in result
    assert "recommended_action" in result
    assert "explanation" in result
    assert isinstance(result["recommended_action"], list)


# ---------------------------------------------------------------------------
# 8. Incident Response Action Test
# ---------------------------------------------------------------------------
def test_incident_response_action():
    threat_inputs = [
        ("Port Scan", "High"),
        ("DDoS", "High"),
        ("Brute Force Login", "High"),
        ("Malware Communication", "Medium"),
        ("Data Exfiltration", "High"),
        ("Unknown Attack", "Medium"),
        ("Normal Activity", "Low")
    ]

    for threat_type, expected_priority in threat_inputs:
        mock_threat_result = {
            "threat_type": threat_type,
            "confidence": "High" if expected_priority == "High" else "Medium",
            "severity": expected_priority,
            "explanation": f"Test description for {threat_type}"
        }

        response = response_agent.generate_response(mock_threat_result)

        assert response["threat_type"] == threat_type
        assert isinstance(response["recommended_actions"], list)
        assert len(response["recommended_actions"]) > 0
        assert "priority" in response
        assert "explanation" in response


# ---------------------------------------------------------------------------
# 9. End-to-End Security Orchestrator Test
# ---------------------------------------------------------------------------
def test_end_to_end_security_orchestrator():
    raw_log = {
        "timestamp": "2026-08-25 14:30:00",
        "source_ip": "192.168.1.200",
        "destination_ip": "10.0.0.2",
        "protocol": "TCP",
        "source_port": 49152,
        "destination_port": 31337,
        "bytes_sent": 600,
        "packets": 5,
        "event_type": "File Transfer",
        "severity": "High"
    }

    # Execute full pipeline starting from raw log without pre-computed scores
    decision = security_orchestrator.analyze_log(row=raw_log)

    required_keys = [
        "anomaly_prediction",
        "anomaly_score",
        "threat_type",
        "severity",
        "confidence",
        "recommended_action",
        "explanation"
    ]

    for key in required_keys:
        assert key in decision, f"Missing required key '{key}' in security orchestrator output"

    assert decision["threat_type"] == "Malware Communication"
    assert decision["severity"] == "High"
    assert "Isolate affected host from the network" in decision["recommended_action"]
