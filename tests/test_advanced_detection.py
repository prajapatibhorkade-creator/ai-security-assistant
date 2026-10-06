from backend.app.correlation.patterns import calculate_pattern_score, detect_advanced_patterns
from backend.app.ml.entity_analysis import analyze_entities
from backend.app.ml.historical_risk import calculate_historical_risk


def test_advanced_patterns_detect_multiple_attack_signals():
    events = [
        {"event_type": "failed_login", "username": "u1", "ip_address": "192.0.2.1"}
        for _ in range(5)
    ]
    events.extend([
        {"event_type": "successful_login", "username": "u2", "ip_address": "192.0.2.2"},
        {"event_type": "privilege_change", "username": "u3", "ip_address": "192.0.2.3", "known_ip": False},
        {"event_type": "sensitive_access", "username": "u3", "ip_address": "192.0.2.3"},
        {"event_type": "sensitive_access", "username": "u3", "ip_address": "192.0.2.3"},
    ])

    findings = detect_advanced_patterns(events)

    assert {finding["type"] for finding in findings} == {
        "brute_force",
        "account_takeover",
        "privilege_escalation",
        "data_access_anomaly",
        "multi_user_activity",
        "multi_ip_activity",
    }
    assert calculate_pattern_score(findings) == 100


def test_entity_and_historical_analysis_summarize_prior_events():
    events = [
        {"username": "alice", "ip_address": "192.0.2.1"}
        for _ in range(5)
    ]
    events.extend([
        {"username": "bob", "ip_address": "192.0.2.2"},
        {"username": "carol", "ip_address": "192.0.2.3"},
    ])

    entities = analyze_entities(events)

    assert entities["unique_users"] == 3
    assert entities["unique_ips"] == 3
    assert entities["suspicious_users"] == [{"username": "alice", "event_count": 5}]
    assert calculate_historical_risk([20, 120, -5]) == 16.0
    assert calculate_historical_risk([]) == 0.0