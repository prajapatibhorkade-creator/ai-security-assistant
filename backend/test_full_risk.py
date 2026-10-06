try:
    from app.ml.behavior import analyze_login_behavior
    from app.ml.risk_engine import calculate_risk_score
    from app.threat_intel.extractor import extract_indicators
    from app.threat_intel.service import enrich_indicators
except ModuleNotFoundError:
    from backend.app.ml.behavior import analyze_login_behavior
    from backend.app.ml.risk_engine import calculate_risk_score
    from backend.app.threat_intel.extractor import extract_indicators
    from backend.app.threat_intel.service import enrich_indicators


def main():
    log_text = """
Failed login activity detected.
Source IP: 192.168.1.50
"""

    indicators = extract_indicators(log_text)
    print("\n=== INDICATORS ===")
    for indicator in indicators:
        print(indicator)

    intel_results = enrich_indicators(indicators)
    print("\n=== THREAT INTELLIGENCE ===")
    for result in intel_results:
        print(result)

    threat_intel_score = max(
        [result.get("risk_score", 0) for result in intel_results],
        default=0,
    )

    behavior_result = analyze_login_behavior(
        failed_attempts=12,
        known_ip=False,
        recent_event_count=80,
    )
    behavior_score = behavior_result["behavior_score"]
    print("\n=== BEHAVIOR ANALYSIS ===")
    print(f"Behavior Score: {behavior_score}")
    for anomaly in behavior_result["anomalies"]:
        print(f"- {anomaly}")

    risk_result = calculate_risk_score(
        ml_anomaly_score=85,
        behavior_score=behavior_score,
        threat_intel_score=threat_intel_score,
        attack_chain_score=0,
        severity_score=80,
    )

    print("\n=== FINAL SECURITY RISK ===")
    print(f"Risk Score: {risk_result['risk_score']}/100")
    print(f"Risk Level: {risk_result['risk_level']}")
    print("\nRisk Breakdown:")
    for key, value in risk_result["breakdown"].items():
        print(f"- {key}: {value}")


if __name__ == "__main__":
    main()