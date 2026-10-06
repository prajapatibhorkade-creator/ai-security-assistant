from datetime import datetime, timedelta

try:
    from app.correlation.engine import correlate_attack_chain
except ModuleNotFoundError:
    from backend.app.correlation.engine import correlate_attack_chain


def main():
    base_time = datetime.now()
    events = [
        {
            "timestamp": base_time,
            "event_type": "failed_login",
            "username": "praja",
            "ip_address": "10.0.0.25",
            "severity": "medium",
        },
        {
            "timestamp": base_time + timedelta(minutes=2),
            "event_type": "successful_login",
            "username": "praja",
            "ip_address": "10.0.0.25",
            "severity": "high",
        },
        {
            "timestamp": base_time + timedelta(minutes=5),
            "event_type": "privilege_change",
            "username": "praja",
            "ip_address": "10.0.0.25",
            "severity": "critical",
        },
        {
            "timestamp": base_time + timedelta(minutes=8),
            "event_type": "sensitive_access",
            "username": "praja",
            "ip_address": "10.0.0.25",
            "severity": "critical",
        },
    ]

    result = correlate_attack_chain(events)
    print("\n==============================")
    print("ATTACK CORRELATION ENGINE")
    print("==============================")
    print(f"\nIncident Detected: {result['incident_detected']}")
    print(f"Incident ID: {result['incident_id']}")
    print(f"Attack Chain Score: {result['attack_chain_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print("\nDetected Attack Patterns:")
    for pattern in result["patterns"]:
        print(
            f"- {pattern['pattern']} "
            f"| Severity: {pattern['severity']} "
            f"| Score: {pattern['score']}"
        )
    print("\nAttack Timeline:")
    for event in result["timeline"]:
        print(
            f"{event['timestamp']} | {event['event_type']} | "
            f"{event['username']} | {event['ip_address']}"
        )
    print("\nCorrelated Events:")
    print(result["correlated_event_count"])


if __name__ == "__main__":
    main()