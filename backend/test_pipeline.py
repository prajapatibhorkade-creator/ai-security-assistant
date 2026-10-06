from datetime import datetime, timedelta

try:
    from app.pipeline import analyze_security_event
except ModuleNotFoundError:
    from backend.app.pipeline import analyze_security_event


def main():
    base_time = datetime.now()
    previous_events = [
        {
            "event_id": 1,
            "timestamp": base_time,
            "username": "praja",
            "ip_address": "10.0.0.25",
            "event_type": "failed_login",
            "message": "Failed login detected",
            "severity": "medium",
            "ml_anomaly_score": 75,
        },
        {
            "event_id": 2,
            "timestamp": base_time + timedelta(minutes=2),
            "username": "praja",
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
        "username": "praja",
        "ip_address": "10.0.0.25",
        "event_type": "privilege_change",
        "message": "Privilege escalation detected",
        "severity": "critical",
        "ml_anomaly_score": 95,
        "failed_attempts": 12,
        "known_ip": False,
        "recent_event_count": 80,
    }

    result = analyze_security_event(current_event, related_events=previous_events)

    print("\n================================")
    print("UNIFIED SECURITY ANALYSIS")
    print("================================")
    print("\n[EVENT]")
    print("Type:", result["event"]["event_type"])
    print("User:", result["event"]["username"])
    print("IP:", result["event"]["ip_address"])

    print("\n[BEHAVIOR]")
    print("Score:", result["behavior_analysis"]["behavior_score"])
    for anomaly in result["behavior_analysis"]["anomalies"]:
        print("-", anomaly)

    print("\n[THREAT INTELLIGENCE]")
    print("Indicators:", result["threat_intelligence"]["indicators"])
    print("Score:", result["threat_intelligence"]["score"])

    print("\n[ATTACK CORRELATION]")
    correlation = result["attack_correlation"]
    print("Incident:", correlation["incident_detected"])
    print("Incident ID:", correlation["incident_id"])
    print("Attack Chain Score:", correlation["attack_chain_score"])
    for pattern in correlation["patterns"]:
        print("-", pattern["pattern"])

    print("\n[ADVANCED DETECTION]")
    advanced = result["advanced_detection"]
    print("Pattern Score:", advanced["pattern_score"])
    for finding in advanced["findings"]:
        print("-", finding["name"], "|", finding["severity"], "|", finding["score"])

    print("\n[ENTITY ANALYSIS]")
    print(result["entity_analysis"])

    print("\n[HISTORICAL RISK]")
    print(result["historical_risk_score"])

    print("\n[RISK ENGINE]")
    risk = result["risk_analysis"]
    print("Risk Score:", risk["risk_score"])
    print("Risk Level:", risk["risk_level"])
    print("Breakdown:", risk["breakdown"])

    print("\n[INCIDENT]")
    print(result["incident"])

    print("\n[FINAL DECISION]")
    decision = result["final_decision"]
    print("Risk:", decision["risk_score"])
    print("Level:", decision["risk_level"])
    print("Incident Detected:", decision["incident_detected"])


if __name__ == "__main__":
    main()