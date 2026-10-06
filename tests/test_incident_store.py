from fastapi.testclient import TestClient

from backend.app import incident_store
from backend.app.main import app
from backend.app.pipeline import analyze_security_event


client = TestClient(app)


def _analysis(incident_id="INC-0001"):
    return {
        "event": {
            "username": "store_user",
            "ip_address": "10.0.0.25",
            "event_type": "privilege_change",
        },
        "risk_analysis": {
            "risk_score": 82,
            "risk_level": "CRITICAL",
        },
        "attack_correlation": {
            "attack_chain_score": 70,
            "patterns": [{"pattern": "Login → Privilege Escalation"}],
            "timeline": [{"event_type": "privilege_change"}],
        },
        "incident": {
            "incident_id": incident_id,
            "status": "open",
            "attack_chain_score": 70,
            "patterns": [{"pattern": "Login → Privilege Escalation"}],
            "timeline": [{"stage": 1, "event_type": "privilege_change"}],
        },
        "final_decision": {"incident_detected": True},
    }


def test_incident_records_persist_with_sequential_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store, "INCIDENT_FILE", tmp_path / "incidents.json")

    first = incident_store.create_incident_record(_analysis())
    second = incident_store.create_incident_record(_analysis())

    assert first["incident_id"] == "INC-0001"
    assert second["incident_id"] == "INC-0002"
    assert incident_store.get_incidents() == [first, second]


def test_incident_history_endpoint_and_security_headers(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store, "INCIDENT_FILE", tmp_path / "incidents.json")
    incident_store.create_incident_record(_analysis())

    response = client.get("/security/incidents")

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["incidents"][0]["incident_id"] == "INC-0001"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Cache-Control"] == "no-store"


def test_pipeline_persists_datetime_pattern_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(incident_store, "INCIDENT_FILE", tmp_path / "incidents.json")
    event = {
        "event_id": 3,
        "timestamp": "2026-10-03T12:05:00",
        "username": "persist_pipeline",
        "ip_address": "10.0.0.25",
        "event_type": "privilege_change",
        "message": "Privilege escalation detected",
        "severity": "critical",
        "ml_anomaly_score": 95,
        "known_ip": False,
        "related_events": [
            {
                "timestamp": "2026-10-03T12:00:00",
                "username": "persist_pipeline",
                "ip_address": "10.0.0.25",
                "event_type": "failed_login",
                "message": "Failed login detected",
                "severity": "medium",
            },
            {
                "timestamp": "2026-10-03T12:02:00",
                "username": "persist_pipeline",
                "ip_address": "10.0.0.25",
                "event_type": "successful_login",
                "message": "Successful login detected",
                "severity": "high",
            },
        ],
    }

    result = analyze_security_event(event, event.pop("related_events"))

    assert result["incident"]["incident_id"] == "INC-0001"
    stored = incident_store.get_incidents()
    assert len(stored) == 1
    assert stored[0]["patterns"][0]["evidence"][0]["_timestamp"] == "2026-10-03T12:00:00"