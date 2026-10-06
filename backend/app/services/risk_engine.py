from collections.abc import Iterable


def calculate_risk_scores(logs: Iterable) -> list[dict]:
    """Calculate risk scores for failed login activity grouped by IP."""
    ip_counts: dict[str, int] = {}

    for log in logs:
        if log.event_type != "login" or log.status != "failed":
            continue

        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    results = []
    for ip_address, failed_attempts in ip_counts.items():
        if failed_attempts >= 5:
            risk_level = "HIGH"
            risk_score = 90
        elif failed_attempts >= 3:
            risk_level = "MEDIUM"
            risk_score = 60
        else:
            risk_level = "LOW"
            risk_score = 20

        results.append({
            "ip_address": ip_address,
            "failed_attempts": failed_attempts,
            "risk_score": risk_score,
            "risk_level": risk_level,
        })

    return results
def calculate_risk_score(
    failed_logins=0,
    suspicious_events=0,
    ml_anomaly=False,
    threat_level="low"
):
    score = 0
    threat_level = threat_level.lower()

    # Failed login attempts
    if failed_logins >= 5:
        score += 30
    elif failed_logins >= 3:
        score += 15

    # Suspicious events
    if suspicious_events >= 3:
        score += 30
    elif suspicious_events >= 1:
        score += 15

    # ML anomaly
    if ml_anomaly:
        score += 25

    # Threat level
    if threat_level == "critical":
        score += 20
    elif threat_level == "high":
        score += 15
    elif threat_level == "medium":
        score += 10

    # Maximum score = 100
    return min(score, 100)


def get_risk_level(score):
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 30:
        return "medium"
    else:
        return "low"
