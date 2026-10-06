def classify_threat(
    failed_attempts,
    unique_users,
    event_frequency,
    severity_score,
    ml_anomaly
):
    """
    Classify suspicious security activity
    based on rule-based security indicators
    and ML anomaly detection.
    """

    if ml_anomaly and failed_attempts >= 5:
        return {
            "threat_type": "Brute Force Attack",
            "threat_level": "HIGH",
            "confidence": 0.95
        }

    if failed_attempts >= 5 and unique_users >= 3:
        return {
            "threat_type": "Credential Attack",
            "threat_level": "HIGH",
            "confidence": 0.90
        }

    if ml_anomaly:
        return {
            "threat_type": "Suspicious Login Activity",
            "threat_level": "MEDIUM",
            "confidence": 0.80
        }

    if failed_attempts >= 3:
        return {
            "threat_type": "Repeated Login Failures",
            "threat_level": "MEDIUM",
            "confidence": 0.75
        }

    return {
        "threat_type": "Normal Authentication Activity",
        "threat_level": "LOW",
        "confidence": 0.60
    }