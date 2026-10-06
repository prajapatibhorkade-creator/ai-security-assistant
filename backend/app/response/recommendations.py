from backend.app.response.actions import get_allowed_actions


def build_response_recommendations(threat_type: str | None = None, threat_level: str | None = None, risk_score: int | float = 0):
    """Build a SOAR-style recommendation payload for a detected threat."""
    normalized_type = (threat_type or "security_alert").lower()
    normalized_level = (threat_level or "medium").lower()

    if "brute" in normalized_type or "login" in normalized_type:
        recommendations = [
            "Investigate the affected account for recent login anomalies.",
            "Review source IP reputation and prior failed login behavior.",
            "Require account verification before allowing the next sign-in.",
        ]
        actions = get_allowed_actions(threat_type="Brute Force", risk_score=risk_score)
    elif "privilege" in normalized_type or "escal" in normalized_type:
        recommendations = [
            "Review privileged changes and role assignments for the affected account.",
            "Investigate whether the account was used to access protected resources.",
            "Lock down access and verify the legitimacy of the changes.",
        ]
        actions = get_allowed_actions(threat_type="Privilege Anomaly", risk_score=risk_score)
    elif "suspicious" in normalized_type or "session" in normalized_type:
        recommendations = [
            "Investigate the active session and device trust indicators.",
            "Review IP/session-timing correlation for suspicious access patterns.",
            "Validate the end user and reset session tokens if required.",
        ]
        actions = get_allowed_actions(threat_type="Suspicious Login", risk_score=risk_score)
    else:
        recommendations = [
            "Review recent user activity and authentication patterns.",
            "Check if the source IP or device appears in active threat intelligence feeds.",
            "Validate the associated account and confirm whether the activity was expected.",
        ]
        actions = get_allowed_actions(threat_type=threat_type, risk_score=risk_score)

    if normalized_level in {"critical", "high"} or risk_score >= 80:
        recommendations.insert(0, "High-priority review is required; escalate to the on-duty analyst immediately.")
        actions = [
            action for action in actions if action["action_id"] in {
                "investigate_account",
                "review_source_ip",
                "require_account_verification",
                "block_source_ip",
            }
        ]

    return {
        "threat_type": threat_type or "security_alert",
        "threat_level": threat_level or "medium",
        "risk_score": risk_score,
        "summary": "Approval-based incident response workflow is ready for analyst review.",
        "recommendations": recommendations,
        "actions": [
            {
                "action_id": action["action_id"],
                "title": action["title"],
                "description": action["description"],
                "category": action["category"],
                "requires_approval": action["requires_approval"],
            }
            for action in actions
        ],
    }
