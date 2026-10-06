def generate_alert(threat):
    """
    Generate a security alert based on threat classification.
    """

    threat_type = threat["threat_type"]
    threat_level = threat["threat_level"]
    confidence = threat["confidence"]

    if threat_level == "HIGH":
        action = "Investigate immediately and consider blocking the source IP."

    elif threat_level == "MEDIUM":
        action = "Monitor the source IP and review authentication activity."

    else:
        action = "Continue normal monitoring."

    return {
        "alert": True if threat_level in ["HIGH", "MEDIUM"] else False,
        "threat_type": threat_type,
        "threat_level": threat_level,
        "confidence": confidence,
        "recommended_action": action
    }