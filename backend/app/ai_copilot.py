from typing import Any, Dict, List


def generate_security_explanation(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a human-readable explanation from security analysis results."""
    risk = analysis.get("risk_analysis", {})
    risk_score = risk.get("risk_score", 0)
    risk_level = risk.get("risk_level", "LOW")

    correlation = analysis.get("attack_correlation", {})
    patterns = correlation.get("patterns", [])
    advanced_findings = analysis.get("advanced_detection", {}).get("findings", [])
    detected_patterns = [
        pattern.get("pattern") or pattern.get("name")
        for pattern in [*patterns, *advanced_findings]
        if pattern.get("pattern") or pattern.get("name")
    ]

    behavior = analysis.get("behavior_analysis", {})
    anomalies = behavior.get("anomalies", [])
    intel = analysis.get("threat_intelligence", {})
    indicators = intel.get("indicators", [])

    explanation_parts: List[str] = []
    if detected_patterns:
        explanation_parts.append(
            "Multiple security events or advanced indicators were correlated into a suspicious attack sequence."
        )
    if anomalies:
        explanation_parts.append("User behavior analysis identified unusual activity.")
    if indicators:
        explanation_parts.append(
            f"{len(indicators)} security indicator(s) were extracted from the event."
        )
    if not explanation_parts:
        explanation_parts.append("No strong multi-stage attack evidence was identified.")

    if risk_score >= 80:
        recommendations = [
            "Investigate the incident immediately.",
            "Review affected user activity.",
            "Review the source IP and related events.",
            "Validate privilege changes.",
        ]
    elif risk_score >= 60:
        recommendations = [
            "Investigate the suspicious activity.",
            "Review authentication history.",
            "Validate the affected account.",
        ]
    elif risk_score >= 30:
        recommendations = [
            "Monitor the affected account.",
            "Review recent security events.",
        ]
    else:
        recommendations = ["Continue monitoring."]

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": " ".join(explanation_parts),
        "recommendations": recommendations,
        "detected_patterns": detected_patterns,
        "behavior_anomalies": anomalies,
        "indicators": indicators,
    }