from collections import Counter
from typing import Any, Dict, List


def generate_security_analytics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate event types, severity, risk levels, and average risk."""
    if not events:
        return {
            "total_events": 0,
            "event_types": {},
            "severity_distribution": {},
            "risk_levels": {},
            "average_risk_score": 0,
        }

    event_types = Counter(event.get("event_type", "unknown") for event in events)
    severity_distribution = Counter(event.get("severity", "unknown") for event in events)
    risk_levels = Counter(event.get("risk_level", "LOW") for event in events)
    risk_scores = [float(event.get("risk_score", 0)) for event in events]
    average_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

    return {
        "total_events": len(events),
        "event_types": dict(event_types),
        "severity_distribution": dict(severity_distribution),
        "risk_levels": dict(risk_levels),
        "average_risk_score": round(average_risk, 2),
    }