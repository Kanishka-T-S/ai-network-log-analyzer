import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "network-log-analyzer"


def test_analyze_success(client):
    payload = {
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.1",
        "destination_port": 22,
        "packets": 120,
        "bytes_sent": 5000,
        "event_type": "Login Failure"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.get_json()

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
        assert key in data, f"Missing key '{key}' in API response"

    assert data["threat_type"] == "Brute Force Login"
    assert isinstance(data["recommended_action"], list)


def test_analyze_invalid_content_type(client):
    response = client.post("/analyze", data="plain text body", content_type="text/plain")
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data


def test_analyze_missing_required_fields(client):
    payload = {
        "destination_ip": "192.168.1.1"
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert "source_ip" in data["error"]
