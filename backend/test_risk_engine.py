try:
    from app.ml.risk_engine import calculate_risk_score
except ModuleNotFoundError:
    from backend.app.ml.risk_engine import calculate_risk_score


result = calculate_risk_score(
    ml_anomaly_score=100,
    behavior_score=100,
    threat_intel_score=100,
    attack_chain_score=100,
    severity_score=100,
)

print(result)