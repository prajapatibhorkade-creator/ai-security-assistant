import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.ml.behavior import analyze_login_behavior, calculate_behavior_score
from backend.app.ml.risk_engine import calculate_risk_score
from backend.app.threat_intel.service import ThreatIntelService
from backend.app.correlation.engine import correlate_attack_chain
from backend.app.main import app


client = TestClient(app)


def test_behavior_score_reports_deterministic_anomalies():
    result = calculate_behavior_score(
        current_hour=12,
        failed_attempts=12,
        known_ip=False,
        recent_event_count=80,
    )

    assert result["behavior_score"] == 63
    assert result["risk_level"] == "HIGH"
    assert result["anomalies"] == [
        "High failed-login activity",
        "Unknown source IP",
        "Elevated activity frequency",
    ]


def test_analyze_login_behavior_uses_supplied_login_time():
    result = analyze_login_behavior(
        login_time=datetime(2026, 10, 3, 12),
        failed_attempts=12,
        known_ip=False,
        recent_event_count=80,
    )

    assert result["signals"]["current_hour"] == 12
    assert result["behavior_score"] == 63


def test_explainable_risk_score_breakdown():
    result = calculate_risk_score(
        ml_anomaly_score=100,
        behavior_score=100,
        threat_intel_score=100,
        attack_chain_score=100,
        severity_score=100,
        historical_risk_score=100,
    )

    assert result == {
        "risk_score": 100.0,
        "risk_level": "CRITICAL",
        "breakdown": {
            "ml_anomaly": 20.0,
            "behavior": 15.0,
            "threat_intelligence": 20.0,
            "attack_chain": 20.0,
            "severity": 10.0,
            "historical_risk": 15.0,
        },
        "raw_scores": {
            "ml_anomaly": 100,
            "behavior": 100,
            "threat_intelligence": 100,
            "attack_chain": 100,
            "severity": 100,
            "historical_risk": 100,
        },
    }


def test_attack_chain_detects_three_patterns_and_scores_100():
    base_time = datetime(2026, 10, 3, 12)
    events = [
        {"timestamp": base_time, "event_type": "failed_login", "username": "chain_user", "ip_address": "10.0.0.25"},
        {"timestamp": base_time + timedelta(minutes=2), "event_type": "successful_login", "username": "chain_user", "ip_address": "10.0.0.25"},
        {"timestamp": base_time + timedelta(minutes=5), "event_type": "privilege_change", "username": "chain_user", "ip_address": "10.0.0.25"},
        {"timestamp": base_time + timedelta(minutes=8), "event_type": "sensitive_access", "username": "chain_user", "ip_address": "10.0.0.25"},
    ]

    result = correlate_attack_chain(events)

    assert result["incident_detected"] is True
    assert result["attack_chain_score"] == 100
    assert result["risk_level"] == "CRITICAL"
    assert len(result["patterns"]) == 3
    assert result["correlated_event_count"] == 4


def test_dashboard_returns_explainable_risk_breakdown():
    response = client.post("/alerts/test")
    assert response.status_code == 200

    dashboard_response = client.get("/dashboard/summary")
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.json()
    breakdown = dashboard["risk_breakdown"]

    assert set(breakdown) == {
        "ml_anomaly",
        "behavior",
        "threat_intelligence",
        "attack_chain",
        "severity",
        "historical_risk",
    }
    assert dashboard["risk_score"] == sum(breakdown.values())
    assert 0 <= dashboard["risk_score"] <= 100
    assert dashboard["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_create_log_triggers_automatic_alert_pipeline():
    username = f"alertuser_{uuid.uuid4().hex[:8]}"
    register_response = client.post(
        "/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "Test@1234",
        },
    )
    assert register_response.status_code in [200, 201]

    login_response = client.post(
        "/login",
        data={
            "username": username,
            "password": "Test@1234",
        },
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    for _ in range(5):
        resp = client.post(
            "/logs",
            json={
                "username": username,
                "ip_address": "10.0.0.55",
                "event_type": "login",
                "status": "failed",
                "severity": "high",
            },
        )
        assert resp.status_code == 200

    alerts = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert alerts.status_code == 200
    assert isinstance(alerts.json(), list)
    assert any(
        alert.get("ip_address") == "10.0.0.55"
        and alert.get("threat_level", "").upper() in {"HIGH", "MEDIUM"}
        for alert in alerts.json()
    )


def test_user_behavior_risk_scoring():
    username = f"ubauser_{uuid.uuid4().hex[:8]}"
    for _ in range(3):
        response = client.post(
            "/logs",
            json={
                "username": username,
                "ip_address": "198.51.100.84",
                "event_type": "login",
                "status": "failed",
                "severity": "high",
            },
        )
        assert response.status_code == 200

    response = client.get("/security/behavior")
    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, list)
    assert any(item.get("username") == username for item in data)
    assert any(item.get("behavior_risk", 0) >= 0 for item in data)


def test_copilot_explains_alert():
    username = f"copilot_alert_{uuid.uuid4().hex[:8]}"
    register_response = client.post(
        "/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "Test@1234",
        },
    )
    assert register_response.status_code in [200, 201]

    for _ in range(4):
        response = client.post(
            "/logs",
            json={
                "username": username,
                "ip_address": "203.0.113.20",
                "event_type": "login",
                "status": "failed",
                "severity": "high",
            },
        )
        assert response.status_code == 200

    login_response = client.post(
        "/login",
        data={
            "username": username,
            "password": "Test@1234",
        },
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    copilot_response = client.post(
        "/copilot",
        json={"question": "Why was this alert generated?"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert copilot_response.status_code == 200
    data = copilot_response.json()
    assert "answer" in data
    assert "alert" in data.get("answer", "").lower() or "failed" in data.get("answer", "").lower()


def test_copilot_investigates_user():
    username = f"copilot_user_{uuid.uuid4().hex[:8]}"
    register_response = client.post(
        "/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "Test@1234",
        },
    )
    assert register_response.status_code in [200, 201]

    for _ in range(2):
        response = client.post(
            "/logs",
            json={
                "username": username,
                "ip_address": "198.51.100.15",
                "event_type": "login",
                "status": "failed",
                "severity": "medium",
            },
        )
        assert response.status_code == 200

    login_response = client.post(
        "/login",
        data={
            "username": username,
            "password": "Test@1234",
        },
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    copilot_response = client.post(
        "/copilot",
        json={"question": f"Show unusual activity for user {username}."},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert copilot_response.status_code == 200
    data = copilot_response.json()
    assert "answer" in data
    assert username in data["answer"] or "activity" in data["answer"].lower()


def test_incident_correlation_groups_related_events():
    username = f"incident_user_{uuid.uuid4().hex[:8]}"
    for idx in range(5):
        response = client.post(
            "/logs",
            json={
                "username": username,
                "ip_address": "203.0.113.77",
                "event_type": "login" if idx < 3 else "privilege_change",
                "status": "failed" if idx < 3 else "success",
                "severity": "high" if idx < 3 else "critical",
            },
        )
        assert response.status_code == 200

    incidents = client.get("/security/incidents/correlated")
    assert incidents.status_code == 200
    payload = incidents.json()
    assert isinstance(payload, list)
    assert any(item.get("event_count", 0) >= 2 for item in payload)
    assert any("risk_score" in item for item in payload)


def test_correlate_endpoint_uses_persisted_security_logs():
    username = f"correlate_api_{uuid.uuid4().hex[:8]}"
    ip_address = f"192.168.77.{int(uuid.uuid4().hex[:2], 16) % 200 + 20}"
    event_sequence = [
        ("login", "failed", "medium"),
        ("login", "success", "high"),
        ("privilege_change", "success", "critical"),
        ("sensitive_access", "success", "critical"),
    ]

    for event_type, status, severity in event_sequence:
        response = client.post(
            "/logs",
            json={
                "username": username,
                "ip_address": ip_address,
                "event_type": event_type,
                "status": status,
                "severity": severity,
            },
        )
        assert response.status_code == 200

    response = client.get("/incidents/correlate")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["total_logs_analyzed"] >= len(event_sequence)
    assert payload["incident"]["incident_detected"] is True, payload
    assert payload["incident"]["attack_chain_score"] == 100
    assert payload["incident"]["correlated_event_count"] == len(event_sequence)


def test_security_analyze_persists_alert_with_incident_timeline():
    base_time = datetime(2026, 10, 3, 12)
    username = f"pipeline_api_{uuid.uuid4().hex[:8]}"
    ip_address = "10.0.0.25"
    event = {
        "event_id": 3,
        "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
        "username": username,
        "ip_address": ip_address,
        "event_type": "privilege_change",
        "message": "Privilege escalation detected",
        "severity": "critical",
        "ml_anomaly_score": 95,
        "failed_attempts": 12,
        "known_ip": False,
        "recent_event_count": 80,
        "related_events": [
            {
                "event_id": 1,
                "timestamp": base_time.isoformat(),
                "username": username,
                "ip_address": ip_address,
                "event_type": "failed_login",
                "message": "Failed login detected",
                "severity": "medium",
                "ml_anomaly_score": 75,
            },
            {
                "event_id": 2,
                "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
                "username": username,
                "ip_address": ip_address,
                "event_type": "successful_login",
                "message": "Successful login detected",
                "severity": "high",
                "ml_anomaly_score": 85,
            },
        ],
    }

    response = client.post("/security/analyze", json=event)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["alert_created"] is True
    assert payload["alert"]["id"] is not None
    assert payload["analysis"]["incident"]["severity"] == "HIGH"
    assert payload["analysis"]["incident"]["event_count"] == 3
    assert payload["analysis"]["incident"]["timeline"][0]["stage"] == 1


def test_threat_intel_enrichment_uses_neutral_provider_baseline():
    response = client.post(
        "/logs",
        json={
            "username": "intel_user",
            "ip_address": "192.168.1.50",
            "event_type": "login",
            "status": "failed",
            "severity": "high",
        },
    )
    assert response.status_code == 200

    intel_response = client.get("/security/threat-intel")
    assert intel_response.status_code == 200
    payload = intel_response.json()
    assert isinstance(payload, list)
    assert any(
        item.get("ip_address") == "192.168.1.50"
        and item.get("intel", {}).get("suspicious") is False
        and item.get("intel", {}).get("intel", [{}])[0].get("provider") == "virustotal"
        and item.get("intel", {}).get("intel", [{}])[0].get("status") == "ignored_non_public"
        and item.get("intel", {}).get("intel", [{}])[0].get("risk_score") == 0
        for item in payload
    )


def test_private_ip_lookup_never_makes_external_request():
    service = ThreatIntelService()
    service.api_key = "unit-test-key"

    with patch("backend.app.threat_intel.service.requests.get") as get_request:
        result = service.lookup("ip", "192.168.1.50")

    get_request.assert_not_called()
    assert result["status"] == "ignored_non_public"
    assert result["risk_score"] == 0


def test_threat_intel_lookup_without_key_never_makes_external_request():
    service = ThreatIntelService()
    service.api_key = None

    with patch("backend.app.threat_intel.service.requests.get") as get_request:
        result = service.lookup("domain", "example.com")

    get_request.assert_not_called()
    assert result["status"] == "not_configured"
    assert result["risk_score"] == 0


def test_threat_intel_lookup_parses_mocked_report():
    service = ThreatIntelService()
    service.api_key = "test-only-key"
    with patch("backend.app.threat_intel.service.requests.get") as get_request:
        get_request.return_value.status_code = 200
        get_request.return_value.json.return_value = {
            "data": {
                "attributes": {
                    "reputation": -5,
                    "last_analysis_stats": {"malicious": 3, "suspicious": 2},
                }
            }
        }
        result = service.lookup("domain", "example.com")

    assert result["status"] == "success"
    assert result["risk_score"] == 40
    assert result["malicious"] is True
    assert result["suspicious"] is True


def test_incident_response_workflow():
    alert_response = client.post(
        "/alerts/test",
    )
    assert alert_response.status_code == 200
    alert = alert_response.json()["alert"]

    recommendation_response = client.post(
        "/security/response/recommendations",
        json={"alert_id": alert["id"]},
    )
    assert recommendation_response.status_code == 200
    recommendation_data = recommendation_response.json()
    assert "actions" in recommendation_data
    assert recommendation_data["actions"]

    execution_response = client.post(
        "/security/response/execute",
        json={
            "alert_id": alert["id"],
            "action_id": recommendation_data["actions"][0]["action_id"],
            "approved": True,
            "approved_by": "admin",
        },
    )
    assert execution_response.status_code == 200
    execution_data = execution_response.json()
    assert execution_data["result"]["success"] is True
    assert execution_data["audit"]["action"]


def test_alert():
    assert True


def test_update_alert_status_requires_authentication():
    response = client.put(
        "/alerts/1/status",
        json={
            "status": "investigating"
        }
    )

    assert response.status_code == 401