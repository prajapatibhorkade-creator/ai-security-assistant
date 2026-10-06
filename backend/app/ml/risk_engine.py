from typing import Any, Dict


def _clamp(value: float, minimum: float = 0, maximum: float = 100) -> float:
    """Keep a numeric value inside the allowed range."""
    return max(minimum, min(value, maximum))


def calculate_risk_score(
    ml_anomaly_score: float = 0,
    behavior_score: float = 0,
    threat_intel_score: float = 0,
    attack_chain_score: float = 0,
    severity_score: float = 0,
    historical_risk_score: float = 0,
) -> Dict[str, Any]:
    """Calculate an explainable cybersecurity risk score.

    Each component contributes to the final score. The result is normalized
    to a 0-100 scale.
    """
    ml_anomaly_score = _clamp(ml_anomaly_score)
    behavior_score = _clamp(behavior_score)
    threat_intel_score = _clamp(threat_intel_score)
    attack_chain_score = _clamp(attack_chain_score)
    severity_score = _clamp(severity_score)
    historical_risk_score = _clamp(historical_risk_score)

    weighted_ml = ml_anomaly_score * 0.20
    weighted_behavior = behavior_score * 0.15
    weighted_threat_intel = threat_intel_score * 0.20
    weighted_attack_chain = attack_chain_score * 0.20
    weighted_severity = severity_score * 0.10
    weighted_historical = historical_risk_score * 0.15

    final_score = (
        weighted_ml
        + weighted_behavior
        + weighted_threat_intel
        + weighted_attack_chain
        + weighted_severity
        + weighted_historical
    )
    final_score = round(_clamp(final_score), 2)

    if final_score >= 80:
        risk_level = "CRITICAL"
    elif final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    breakdown = {
        "ml_anomaly": round(weighted_ml, 2),
        "behavior": round(weighted_behavior, 2),
        "threat_intelligence": round(weighted_threat_intel, 2),
        "attack_chain": round(weighted_attack_chain, 2),
        "severity": round(weighted_severity, 2),
        "historical_risk": round(weighted_historical, 2),
    }

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "raw_scores": {
            "ml_anomaly": round(ml_anomaly_score, 2),
            "behavior": round(behavior_score, 2),
            "threat_intelligence": round(threat_intel_score, 2),
            "attack_chain": round(attack_chain_score, 2),
            "severity": round(severity_score, 2),
            "historical_risk": round(historical_risk_score, 2),
        },
    }


__all__ = ["calculate_risk_score"]