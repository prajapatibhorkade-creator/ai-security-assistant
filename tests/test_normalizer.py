from backend.app.events.normalizer import normalize_event, normalize_events


def test_normalize_events_detects_expected_types_and_preserves_scores():
    events = normalize_events([
        {"event_id": 1, "message": "Failed login detected", "severity": " MEDIUM ", "risk_score": 45},
        {"event_id": 2, "message": "Successful login detected", "severity": "high"},
        {"event_id": 3, "message": "Privilege escalation detected", "severity": "critical"},
    ])

    assert [event["event_type"] for event in events] == [
        "failed_login",
        "successful_login",
        "privilege_change",
    ]
    assert events[0]["timestamp"]
    assert events[0]["severity"] == "medium"
    assert events[0]["risk_score"] == 45.0
    assert events[1]["risk_score"] == 0.0


def test_normalize_event_keeps_explicit_type_and_normalizes_unknown_severity():
    event = normalize_event({
        "event_type": "Custom_Event",
        "message": "Failed login detected",
        "severity": "urgent",
    })

    assert event["event_type"] == "custom_event"
    assert event["severity"] == "unknown"