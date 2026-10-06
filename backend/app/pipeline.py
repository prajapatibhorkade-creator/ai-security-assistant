from typing import Any, Dict, List
from datetime import datetime

from .correlation.engine import correlate_attack_chain
from .correlation.patterns import calculate_pattern_score, detect_advanced_patterns
from .events.normalizer import normalize_event
from .incidents.manager import create_incident
from .incident_store import create_incident_record
from .ml.behavior import analyze_login_behavior
from .ml.entity_analysis import analyze_entities
from .ml.historical_risk import calculate_historical_risk
from .ml.risk_engine import calculate_risk_score
from .threat_intel.extractor import extract_indicators
from .threat_intel.service import enrich_indicators


def analyze_security_event(
    raw_event: Dict[str, Any],
    related_events: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Run a security event through the available intelligence pipeline."""
    event = normalize_event(raw_event)

    try:
        event_hour = datetime.fromisoformat(event["timestamp"]).hour
    except (TypeError, ValueError):
        event_hour = datetime.now().hour
    known_ip = bool(raw_event.get("known_ip", True))
    ml_features = [
        int(raw_event.get("failed_attempts", 0)),
        int(raw_event.get("recent_event_count", 0)),
        int(event_hour < 6 or event_hour >= 22),
        int(not known_ip),
        int(event["event_type"] == "sensitive_access"),
    ]
    from .ml.training import predict_security_event

    ml_analysis = predict_security_event(ml_features)
    if "ml_anomaly_score" not in raw_event:
        event["ml_anomaly_score"] = 100.0 if ml_analysis["is_anomaly"] else 0.0
    ml_analysis["score_source"] = (
        "event_input" if "ml_anomaly_score" in raw_event else "isolation_forest"
    )

    behavior_result = analyze_login_behavior(
        failed_attempts=int(raw_event.get("failed_attempts", 0)),
        known_ip=bool(raw_event.get("known_ip", True)),
        recent_event_count=int(raw_event.get("recent_event_count", 0)),
    )
    behavior_score = behavior_result["behavior_score"]

    indicator_text = " ".join(
        value for value in (event["message"], event["ip_address"] or "") if value
    )
    indicators = extract_indicators(indicator_text)
    intel_results = enrich_indicators(indicators)
    threat_intel_score = max(
        (result.get("risk_score", 0) for result in intel_results),
        default=0,
    )

    correlation_events = []
    for related_event in related_events or []:
        normalized_related = normalize_event(related_event)
        normalized_related["known_ip"] = bool(related_event.get("known_ip", True))
        correlation_events.append(normalized_related)

    event["known_ip"] = bool(raw_event.get("known_ip", True))
    correlation_events.append(event)
    correlation_result = correlate_attack_chain(correlation_events)
    attack_chain_score = correlation_result.get("attack_chain_score", 0)

    advanced_findings = detect_advanced_patterns(correlation_events)
    advanced_pattern_score = calculate_pattern_score(advanced_findings)
    entity_analysis = analyze_entities(correlation_events)
    previous_scores = [
        float(item.get("risk_score", 0))
        for item in correlation_events[:-1]
    ]
    historical_risk_score = calculate_historical_risk(previous_scores)
    combined_attack_chain_score = max(attack_chain_score, advanced_pattern_score)

    incident_detected = correlation_result["incident_detected"] or bool(advanced_findings)
    incident = None
    if incident_detected:
        incident_timeline = (
            correlation_result["timeline"]
            if correlation_result["incident_detected"]
            else correlation_events
        )
        incident = create_incident(
            attack_chain_score=combined_attack_chain_score,
            patterns=correlation_result["patterns"] + advanced_findings,
            timeline=incident_timeline,
        )

    severity_map = {
        "low": 10,
        "medium": 40,
        "high": 70,
        "critical": 100,
    }
    severity_score = severity_map.get(event["severity"], 0)

    risk_result = calculate_risk_score(
        ml_anomaly_score=event["ml_anomaly_score"],
        behavior_score=behavior_score,
        threat_intel_score=threat_intel_score,
        attack_chain_score=combined_attack_chain_score,
        severity_score=severity_score,
        historical_risk_score=historical_risk_score,
    )

    event.update({
        "behavior_score": behavior_score,
        "threat_intel_score": threat_intel_score,
        "attack_chain_score": combined_attack_chain_score,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
    })

    result = {
        "event": event,
        "ml_analysis": ml_analysis,
        "behavior_analysis": behavior_result,
        "threat_intelligence": {
            "indicators": indicators,
            "results": intel_results,
            "score": threat_intel_score,
        },
        "attack_correlation": correlation_result,
        "advanced_detection": {
            "findings": advanced_findings,
            "pattern_score": advanced_pattern_score,
        },
        "entity_analysis": entity_analysis,
        "historical_risk_score": historical_risk_score,
        "risk_analysis": risk_result,
        "incident": incident,
        "final_decision": {
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "incident_detected": incident_detected,
        },
    }

    if incident is not None:
        incident_record = create_incident_record(result)
        incident["incident_id"] = incident_record["incident_id"]

    return result