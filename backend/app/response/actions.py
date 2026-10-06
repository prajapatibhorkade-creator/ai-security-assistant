DEFAULT_ACTIONS = [
    {
        "action_id": "investigate_account",
        "title": "Investigate affected account",
        "description": "Review recent login activity and confirm if the account was used legitimately.",
        "category": "account",
        "requires_approval": True,
    },
    {
        "action_id": "review_source_ip",
        "title": "Review source IP activity",
        "description": "Inspect whether the source IP has prior suspicious activity or known malicious reputation.",
        "category": "network",
        "requires_approval": True,
    },
    {
        "action_id": "require_account_verification",
        "title": "Account verification required",
        "description": "Require the user to verify their identity before allowing the next login or privilege change.",
        "category": "account",
        "requires_approval": True,
    },
    {
        "action_id": "review_privileged_actions",
        "title": "Review privileged actions",
        "description": "Check for unauthorized privilege escalation, role changes, or high-privilege actions.",
        "category": "privilege",
        "requires_approval": True,
    },
    {
        "action_id": "investigate_session",
        "title": "Investigate session integrity",
        "description": "Review browser session, device trust, and access tokens for suspicious reuse.",
        "category": "session",
        "requires_approval": True,
    },
    {
        "action_id": "block_source_ip",
        "title": "Block source IP",
        "description": "Temporarily block the source IP if the risk remains elevated after analyst review.",
        "category": "network",
        "requires_approval": True,
    },
]


def get_allowed_actions(threat_type: str | None = None, risk_score: int | float = 0):
    """Return the allowed response actions for a given threat and risk context."""
    threat_name = (threat_type or "").lower()

    if "brute" in threat_name or "login" in threat_name:
        return [
            action for action in DEFAULT_ACTIONS if action["action_id"] in {
                "investigate_account",
                "review_source_ip",
                "require_account_verification",
            }
        ]

    if "privilege" in threat_name or "escal" in threat_name:
        return [
            action for action in DEFAULT_ACTIONS if action["action_id"] in {
                "review_privileged_actions",
                "investigate_account",
                "require_account_verification",
            }
        ]

    if "suspicious" in threat_name or "session" in threat_name:
        return [
            action for action in DEFAULT_ACTIONS if action["action_id"] in {
                "investigate_session",
                "review_source_ip",
                "require_account_verification",
            }
        ]

    if risk_score >= 80:
        return [
            action for action in DEFAULT_ACTIONS if action["action_id"] in {
                "investigate_account",
                "review_source_ip",
                "block_source_ip",
                "require_account_verification",
            }
        ]

    return DEFAULT_ACTIONS[:3]
