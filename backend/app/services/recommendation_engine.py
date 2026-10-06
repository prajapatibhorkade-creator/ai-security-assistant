def generate_recommendation(
    threat_level: str = "low",
    risk_score: int | float = 0,
    ml_anomaly: bool = False,
) -> str:
    """Return an operational recommendation for a detected threat."""
    normalized_level = threat_level.lower()

    if normalized_level in {"critical", "high"} or risk_score >= 80:
        return (
            "Investigate this activity immediately, review related logs, "
            "and consider blocking the source IP."
        )

    if normalized_level == "medium" or risk_score >= 50 or ml_anomaly:
        return (
            "Monitor this activity closely and review additional "
            "authentication and security events."
        )

    return "Continue normal security monitoring."
def get_recommended_action(threat_type, threat_level, risk_score):
    """
    Generate a recommended security action
    based on threat type, severity and risk score.
    """

    if threat_level == "critical" or risk_score >= 80:
        return "Immediately investigate the incident and isolate the affected IP."

    if threat_type == "Brute Force Attack":
        return "Temporarily block the IP and investigate repeated login failures."

    if threat_type == "port_scan":
        return "Monitor the source IP and investigate exposed network services."

    if threat_type == "unauthorized_access":
        return "Review authentication logs and verify the affected account."

    if threat_type == "privilege_escalation":
        return "Review account privileges and investigate unauthorized privilege changes."

    if threat_type == "malware_detected":
        return "Isolate the affected system and perform malware investigation."

    if threat_level == "high":
        return "Investigate the alert and monitor the affected IP."

    if threat_level == "medium":
        return "Monitor the activity and review related security logs."

    return "Continue monitoring the activity."
