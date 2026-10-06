from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List


CORRELATION_WINDOW_MINUTES = 30


def _normalize_event(event):
    if isinstance(event, dict):
        return {
            "id": event.get("id"),
            "username": event.get("username"),
            "ip_address": event.get("ip_address"),
            "event_type": event.get("event_type") or event.get("action"),
            "status": event.get("status"),
            "severity": event.get("severity"),
            "timestamp": event.get("timestamp"),
        }

    return {
        "id": getattr(event, "id", None),
        "username": getattr(event, "username", None),
        "ip_address": getattr(event, "ip_address", None),
        "event_type": getattr(event, "event_type", None) or getattr(event, "action", None),
        "status": getattr(event, "status", None),
        "severity": getattr(event, "severity", None),
        "timestamp": getattr(event, "timestamp", None),
    }


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.now()


def _same_context(event_a: Dict[str, Any], event_b: Dict[str, Any]) -> bool:
    same_user = (
        event_a.get("username") is not None
        and event_a.get("username") == event_b.get("username")
    )
    same_ip = (
        event_a.get("ip_address") is not None
        and event_a.get("ip_address") == event_b.get("ip_address")
    )
    return same_user or same_ip


def _detect_attack_patterns(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    patterns = []
    pattern_rules = [
        (
            "failed_login",
            "successful_login",
            "Brute Force → Successful Login",
            "HIGH",
            35,
        ),
        (
            "successful_login",
            "privilege_change",
            "Successful Login → Privilege Escalation",
            "CRITICAL",
            35,
        ),
        (
            "privilege_change",
            "sensitive_access",
            "Privilege Escalation → Sensitive Access",
            "CRITICAL",
            30,
        ),
    ]

    for current, next_event in zip(events, events[1:]):
        current_type = str(current.get("event_type", "")).lower()
        next_type = str(next_event.get("event_type", "")).lower()
        for start_type, end_type, name, severity, score in pattern_rules:
            if current_type == start_type and next_type == end_type:
                patterns.append({
                    "pattern": name,
                    "severity": severity,
                    "score": score,
                    "evidence": [current, next_event],
                })

    return patterns


def correlate_attack_chain(
    events: List[Dict[str, Any]],
    correlation_window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> Dict[str, Any]:
    """Correlate ordered events into a scored attack-chain report."""
    if not events:
        return {
            "incident_detected": False,
            "incident_id": None,
            "attack_chain_score": 0,
            "risk_level": "LOW",
            "patterns": [],
            "timeline": [],
            "correlated_event_count": 0,
            "correlation_window_minutes": correlation_window_minutes,
            "message": "No events supplied.",
        }

    normalized_events = []
    for event in events:
        normalized = _normalize_event(event)
        normalized["_timestamp"] = _parse_timestamp(normalized.get("timestamp"))
        normalized_events.append(normalized)
    normalized_events.sort(key=lambda event: event["_timestamp"])

    groups = []
    current_group = []
    for event in normalized_events:
        if not current_group:
            current_group = [event]
            continue

        previous = current_group[-1]
        within_window = (
            event["_timestamp"] - previous["_timestamp"]
            <= timedelta(minutes=correlation_window_minutes)
        )
        if within_window and _same_context(previous, event):
            current_group.append(event)
        else:
            groups.append(current_group)
            current_group = [event]
    if current_group:
        groups.append(current_group)

    correlated_events, patterns = max(
        (
            (group, _detect_attack_patterns(group))
            for group in groups
        ),
        key=lambda item: (
            sum(pattern["score"] for pattern in item[1]),
            len(item[0]),
        ),
    )
    attack_chain_score = min(100, sum(pattern["score"] for pattern in patterns))
    if attack_chain_score >= 80:
        risk_level = "CRITICAL"
    elif attack_chain_score >= 60:
        risk_level = "HIGH"
    elif attack_chain_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    timeline = [
        {
            "timestamp": event["_timestamp"].isoformat(),
            "event_type": event.get("event_type"),
            "username": event.get("username"),
            "ip_address": event.get("ip_address"),
            "severity": event.get("severity") or "unknown",
        }
        for event in correlated_events
    ]
    incident_detected = bool(patterns)

    return {
        "incident_detected": incident_detected,
        "incident_id": "INC-0001" if incident_detected else None,
        "attack_chain_score": attack_chain_score,
        "risk_level": risk_level,
        "patterns": patterns,
        "timeline": timeline,
        "correlated_event_count": len(correlated_events),
        "correlation_window_minutes": correlation_window_minutes,
    }


def correlate_events(events, max_time_gap_minutes: int = 30):
    """Group related security events into attack sequences based on user, IP, time, and threat similarity."""
    if not events:
        return []

    normalized = [_normalize_event(event) for event in events]
    sorted_events = sorted(
        normalized,
        key=lambda item: item["timestamp"] or datetime.utcnow(),
    )

    groups = []
    current_group = []
    for event in sorted_events:
        if not current_group:
            current_group = [event]
            continue

        last = current_group[-1]
        last_time = last["timestamp"] or datetime.utcnow()
        current_time = event["timestamp"] or datetime.utcnow()
        delta_minutes = abs((current_time - last_time).total_seconds() / 60.0)

        same_user = (last["username"] and event["username"] and last["username"] == event["username"])
        same_ip = (last["ip_address"] and event["ip_address"] and last["ip_address"] == event["ip_address"])
        related_threat = (
            last["event_type"] and event["event_type"]
            and (
                "login" in str(last["event_type"]).lower()
                or "login" in str(event["event_type"]).lower()
                or "privilege" in str(last["event_type"]).lower()
                or "privilege" in str(event["event_type"]).lower()
                or "access" in str(last["event_type"]).lower()
                or "access" in str(event["event_type"]).lower()
            )
        )

        if delta_minutes <= max_time_gap_minutes and (same_user or same_ip or related_threat):
            current_group.append(event)
        else:
            if len(current_group) >= 2:
                groups.append(current_group)
            current_group = [event]

    if len(current_group) >= 2:
        groups.append(current_group)

    return groups


def build_incident(events):
    """Reduce a related event cluster into a single incident with combined risk and summary details."""
    if not events:
        return None

    correlated = correlate_events(events)
    if not correlated:
        return None

    selected = max(correlated, key=len)
    usernames = {event.get("username") for event in selected if event.get("username")}
    ips = {event.get("ip_address") for event in selected if event.get("ip_address")}
    count = len(selected)

    risk_score = min(100, 35 + (count * 8) + (5 if len(usernames) > 1 else 0) + (10 if len(ips) > 1 else 0))
    labels = [
        event.get("event_type") or "security_event"
        for event in selected
        if event.get("event_type")
    ]

    if any("login" in label.lower() for label in labels):
        chain = "Possible Brute Force → Account Compromise"
    elif any("privilege" in label.lower() for label in labels):
        chain = "Privilege Abuse → Unauthorized Action"
    else:
        chain = "Suspicious Activity → Potential Security Breach"

    incident = {
        "incident_id": f"INC-{datetime.utcnow().strftime('%d%H%M%S')}",
        "title": chain,
        "summary": f"{count} correlated security events involving {', '.join(sorted(usernames)[:2] or ['unknown'])}.",
        "events": selected,
        "event_count": count,
        "risk_score": risk_score,
        "usernames": sorted(usernames),
        "ip_addresses": sorted(ips),
        "timeline": [
            {
                "time": event.get("timestamp").strftime("%H:%M") if getattr(event.get("timestamp"), "strftime", None) else "unknown",
                "event": event.get("event_type") or "security_event",
                "status": event.get("status") or "unknown",
                "ip": event.get("ip_address") or "unknown",
            }
            for event in selected
        ],
    }
    return incident


__all__ = ["correlate_attack_chain", "correlate_events", "build_incident"]
