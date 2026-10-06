from datetime import datetime
from typing import Any, Dict


def build_incident_timeline(events: list) -> list:
    """Build a chronological timeline with numbered attack stages."""
    ordered_events = sorted(
        events,
        key=lambda event: str(event.get("timestamp") or ""),
    )
    return [
        {
            "stage": index,
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type", "unknown"),
            "username": event.get("username"),
            "ip_address": event.get("ip_address"),
            "severity": event.get("severity", "unknown"),
        }
        for index, event in enumerate(ordered_events, start=1)
    ]


def create_incident(
    attack_chain_score: float,
    patterns: list,
    timeline: list,
) -> Dict[str, Any]:
    """Create a normalized security incident from a correlated attack chain."""
    if attack_chain_score >= 80:
        severity = "CRITICAL"
    elif attack_chain_score >= 60:
        severity = "HIGH"
    elif attack_chain_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    normalized_timeline = build_incident_timeline(timeline)
    return {
        "incident_id": "INC-0001",
        "status": "open",
        "severity": severity,
        "attack_chain_score": attack_chain_score,
        "patterns": patterns,
        "timeline": normalized_timeline,
        "event_count": len(normalized_timeline),
    }