from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from backend.app.ai_copilot import generate_security_explanation
from backend.app.incident_report import generate_incident_report
from backend.app.main import app


client = TestClient(app)


def _attack_event_payload():
    base_time = datetime(2026, 10, 3, 12)
    username = "report_pipeline_user"
    ip_address = "10.0.0.25"
    return {
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
                "timestamp": base_time.isoformat(),
                "username": username,
                "ip_address": ip_address,
                "event_type": "failed_login",
                "message": "Failed login detected",
                "severity": "medium",
            },
            {
                "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
                "username": username,
                "ip_address": ip_address,
                "event_type": "successful_login",
                "message": "Successful login detected",
                "severity": "high",
            },
        ],
    }


def test_local_copilot_explains_patterns_and_recommends_actions():
    explanation = generate_security_explanation({
        "risk_analysis": {"risk_score": 85, "risk_level": "CRITICAL"},
        "attack_correlation": {"patterns": [{"pattern": "Login → Privilege Escalation"}]},
        "behavior_analysis": {"anomalies": ["Unknown source IP"]},
        "threat_intelligence": {"indicators": [{"type": "ip", "value": "10.0.0.25"}]},
    })

    assert explanation["risk_score"] == 85
    assert explanation["detected_patterns"] == ["Login → Privilege Escalation"]
    assert "Unknown source IP" in explanation["behavior_anomalies"]
    assert "Investigate the incident immediately." in explanation["recommendations"]


def test_incident_report_includes_incident_and_timeline():
    report = generate_incident_report({
        "event": {"username": "alice", "ip_address": "10.0.0.1", "event_type": "failed_login"},
        "risk_analysis": {"risk_score": 70, "risk_level": "HIGH", "breakdown": {"behavior": 10}},
        "attack_correlation": {
            "incident_detected": True,
            "attack_chain_score": 70,
            "patterns": [{"pattern": "Failed → Successful Login"}],
            "timeline": [{"event_type": "failed_login"}],
        },
        "incident": {"incident_id": "INC-0001", "timeline": [{"stage": 1}]},
        "final_decision": {"incident_detected": True},
    })

    assert report["incident_id"] == "INC-0001"
    assert report["incident_detected"] is True
    assert report["attack_patterns"] == ["Failed → Successful Login"]
    assert report["timeline"] == [{"stage": 1}]


def test_copilot_and_report_apis_use_pipeline_output():
    event = _attack_event_payload()

    copilot_response = client.post("/security/copilot", json=event)
    assert copilot_response.status_code == 200
    copilot_payload = copilot_response.json()
    assert copilot_payload["status"] == "success"
    assert copilot_payload["copilot"]["risk_score"] == copilot_payload["analysis"]["risk_analysis"]["risk_score"]
    assert copilot_payload["copilot"]["detected_patterns"]

    report_response = client.post("/security/report", json=event)
    assert report_response.status_code == 200
    report_payload = report_response.json()
    assert report_payload["status"] == "success"
    assert report_payload["report"]["incident_detected"] is True
    assert report_payload["report"]["incident_id"].startswith("INC-")
    assert len(report_payload["report"]["timeline"]) == 3