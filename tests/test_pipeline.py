from datetime import datetime, timedelta
from unittest.mock import patch

from backend.app.pipeline import analyze_security_event


def test_unified_pipeline_combines_behavior_correlation_and_risk():
    base_time = datetime(2026, 10, 3, 12)
    related_events = [
        {
            "timestamp": base_time,
            "username": "pipeline_user",
            "ip_address": "10.0.0.25",
            "event_type": "failed_login",
            "message": "Failed login detected",
            "severity": "medium",
            "ml_anomaly_score": 75,
        },
        {
            "timestamp": base_time + timedelta(minutes=2),
            "username": "pipeline_user",
            "ip_address": "10.0.0.25",
            "event_type": "successful_login",
            "message": "Successful login detected",
            "severity": "high",
            "ml_anomaly_score": 85,
        },
    ]
    current_event = {
        "event_id": 3,
        "timestamp": base_time + timedelta(minutes=5),
        "username": "pipeline_user",
        "ip_address": "10.0.0.25",
        "event_type": "privilege_change",
        "message": "Privilege escalation detected",
        "severity": "critical",
        "ml_anomaly_score": 95,
        "failed_attempts": 12,
        "known_ip": False,
        "recent_event_count": 80,
    }

    result = analyze_security_event(current_event, related_events)

    assert result["event"]["event_type"] == "privilege_change"
    assert result["attack_correlation"]["incident_detected"] is True
    assert result["attack_correlation"]["attack_chain_score"] == 70
    assert len(result["attack_correlation"]["patterns"]) == 2
    assert result["advanced_detection"]["pattern_score"] == 75
    assert {finding["type"] for finding in result["advanced_detection"]["findings"]} == {
        "account_takeover",
        "privilege_escalation",
    }
    assert result["entity_analysis"]["unique_users"] == 1
    assert result["entity_analysis"]["unique_ips"] == 1
    assert result["historical_risk_score"] == 0
    assert result["risk_analysis"]["raw_scores"]["attack_chain"] == 75
    assert result["risk_analysis"]["raw_scores"]["historical_risk"] == 0
    assert result["incident"]["severity"] == "HIGH"
    assert result["incident"]["event_count"] == 3
    assert [item["stage"] for item in result["incident"]["timeline"]] == [1, 2, 3]
    assert result["risk_analysis"]["risk_score"] > 0
    assert result["event"]["risk_score"] == result["risk_analysis"]["risk_score"]
    assert result["final_decision"]["incident_detected"] is True


def test_pipeline_uses_isolation_forest_when_score_is_not_provided():
    event = {
        "timestamp": "2026-10-03T23:00:00",
        "username": "model_user",
        "ip_address": "10.0.0.26",
        "event_type": "failed_login",
        "message": "Failed login detected",
        "severity": "high",
        "failed_attempts": 12,
        "known_ip": False,
        "recent_event_count": 100,
    }

    with patch(
        "backend.app.ml.training.predict_security_event",
        return_value={
            "is_anomaly": True,
            "model_prediction": -1,
            "anomaly_score": -0.12,
        },
    ):
        result = analyze_security_event(event)

    assert result["ml_analysis"]["score_source"] == "isolation_forest"
    assert result["event"]["ml_anomaly_score"] == 100.0