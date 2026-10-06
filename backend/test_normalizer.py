try:
    from app.events.normalizer import normalize_events
except ModuleNotFoundError:
    from backend.app.events.normalizer import normalize_events


raw_events = [
    {
        "event_id": 1,
        "timestamp": "2026-10-03T21:30:00",
        "username": "praja",
        "ip_address": "10.0.0.25",
        "message": "Failed login detected",
        "severity": "medium",
        "ml_anomaly_score": 72,
        "behavior_score": 40,
        "threat_intel_score": 0,
        "risk_score": 45,
        "risk_level": "MEDIUM",
    },
    {
        "event_id": 2,
        "timestamp": "2026-10-03T21:32:00",
        "username": "praja",
        "ip_address": "10.0.0.25",
        "message": "Successful login detected",
        "severity": "high",
        "ml_anomaly_score": 85,
        "behavior_score": 70,
        "threat_intel_score": 20,
        "risk_score": 65,
        "risk_level": "HIGH",
    },
    {
        "event_id": 3,
        "timestamp": "2026-10-03T21:35:00",
        "username": "praja",
        "ip_address": "10.0.0.25",
        "message": "Privilege escalation detected",
        "severity": "critical",
        "ml_anomaly_score": 95,
        "behavior_score": 80,
        "threat_intel_score": 30,
        "risk_score": 90,
        "risk_level": "CRITICAL",
    },
]


def main():
    events = normalize_events(raw_events)
    print("\n==============================")
    print("EVENT NORMALIZATION ENGINE")
    print("==============================")

    for event in events:
        print("\nEvent ID:", event["event_id"])
        print("Timestamp:", event["timestamp"])
        print("Username:", event["username"])
        print("IP:", event["ip_address"])
        print("Event Type:", event["event_type"])
        print("Severity:", event["severity"])
        print("ML Score:", event["ml_anomaly_score"])
        print("Behavior Score:", event["behavior_score"])
        print("Threat Intel Score:", event["threat_intel_score"])
        print("Risk Score:", event["risk_score"])
        print("Risk Level:", event["risk_level"])


if __name__ == "__main__":
    main()