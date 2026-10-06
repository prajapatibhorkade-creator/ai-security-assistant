from datetime import datetime
from typing import Any, Dict


def generate_incident_report(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a structured incident report from pipeline results."""
    event = analysis.get("event", {})
    risk = analysis.get("risk_analysis", {})
    correlation = analysis.get("attack_correlation", {})
    incident = analysis.get("incident")
    advanced_findings = analysis.get("advanced_detection", {}).get("findings", [])
    final_decision = analysis.get("final_decision", {})

    attack_patterns = [
        pattern.get("pattern") or pattern.get("name")
        for pattern in [*correlation.get("patterns", []), *advanced_findings]
        if pattern.get("pattern") or pattern.get("name")
    ]
    timeline = (
        incident.get("timeline")
        if incident
        else correlation.get("timeline", [])
    )

    return {
        "report_generated_at": datetime.now().isoformat(),
        "incident_id": incident.get("incident_id") if incident else None,
        "incident_detected": final_decision.get(
            "incident_detected",
            correlation.get("incident_detected", False),
        ),
        "affected_user": event.get("username"),
        "source_ip": event.get("ip_address"),
        "event_type": event.get("event_type"),
        "risk_score": risk.get("risk_score", 0),
        "risk_level": risk.get("risk_level", "LOW"),
        "attack_chain_score": event.get(
            "attack_chain_score",
            correlation.get("attack_chain_score", 0),
        ),
        "attack_patterns": attack_patterns,
        "timeline": timeline,
        "risk_breakdown": risk.get("breakdown", {}),
    }