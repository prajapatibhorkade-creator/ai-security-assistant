from __future__ import annotations


def get_indicator_reputation(indicator: str, indicator_type: str):
    """Return a lightweight reputation record for a known indicator type."""
    if not indicator:
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "unknown",
            "confidence": "low",
            "reports": 0,
            "related_threat": "unknown",
            "first_seen": "unknown",
        }

    lower = indicator.lower()

    if indicator_type == "ip":
        suspicious_ips = {"203.0.113.20", "203.0.113.77", "198.51.100.15", "10.0.0.55"}
        if lower in suspicious_ips or lower.startswith("203."):
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "reputation": "suspicious",
                "confidence": "high",
                "reports": 12,
                "related_threat": "brute_force",
                "first_seen": "unknown",
            }

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "trusted",
            "confidence": "medium",
            "reports": 1,
            "related_threat": "none",
            "first_seen": "unknown",
        }

    if indicator_type == "domain":
        if "suspicious" in lower or "malware" in lower or "phish" in lower:
            return {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "reputation": "suspicious",
                "confidence": "high",
                "reports": 9,
                "related_threat": "credential_phishing",
                "first_seen": "unknown",
            }

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "unknown",
            "confidence": "low",
            "reports": 0,
            "related_threat": "unknown",
            "first_seen": "unknown",
        }

    if indicator_type == "hash":
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "suspicious",
            "confidence": "high",
            "reports": 7,
            "related_threat": "malware_delivery",
            "first_seen": "unknown",
        }

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation": "unknown",
        "confidence": "low",
        "reports": 0,
        "related_threat": "unknown",
        "first_seen": "unknown",
    }
