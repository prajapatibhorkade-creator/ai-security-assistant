try:
    from app.pipeline import analyze_security_event
except ModuleNotFoundError:
    from backend.app.pipeline import analyze_security_event


def test_security_pipeline():
    event = {
        "event_id": 999,
        "username": "test_user",
        "ip_address": "203.0.113.50",
        "event_type": "failed_login",
        "message": "Failed login detected",
        "severity": "high",
        "ml_anomaly_score": 85,
        "failed_attempts": 8,
        "known_ip": False,
        "recent_event_count": 60,
    }

    result = analyze_security_event(event)

    assert "event" in result
    assert "risk_analysis" in result
    assert "behavior_analysis" in result
    assert "threat_intelligence" in result
    assert "attack_correlation" in result
    assert "final_decision" in result
    assert 0 <= result["risk_analysis"]["risk_score"] <= 100