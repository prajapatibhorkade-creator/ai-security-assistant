try:
    from app.ml.behavior import analyze_login_behavior
    from app.ml.risk_engine import calculate_risk_score
except ModuleNotFoundError:
    from backend.app.ml.behavior import analyze_login_behavior
    from backend.app.ml.risk_engine import calculate_risk_score


# Analyze current user behavior
behavior_result = analyze_login_behavior(
    failed_attempts=12,
    known_ip=False,
    recent_event_count=80,
)

# Get behavior risk
behavior_score = behavior_result["behavior_score"]

# Calculate combined security risk
risk_result = calculate_risk_score(
    ml_anomaly_score=85,
    behavior_score=behavior_score,
    threat_intel_score=0,
    attack_chain_score=0,
    severity_score=80,
)

print("\n=== USER BEHAVIOR ===")
print(f"Behavior Score: {behavior_score}")
print(f"Behavior Level: {behavior_result['risk_level']}")

print("\nDetected Anomalies:")
for anomaly in behavior_result["anomalies"]:
    print(f"- {anomaly}")

print("\n=== COMBINED SECURITY RISK ===")
print(f"Risk Score: {risk_result['risk_score']}")
print(f"Risk Level: {risk_result['risk_level']}")

print("\nRisk Breakdown:")
for key, value in risk_result["breakdown"].items():
    print(f"- {key}: {value}")