from datetime import datetime
from typing import Any, Dict, Optional


def _safe_timestamp(value: Any) -> str:
    """Convert timestamp values to ISO-format strings."""
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, str) and value:
        return value

    return datetime.now().isoformat()


def _normalize_severity(value: Any) -> str:
    """Normalize severity values to the supported labels."""
    if value is None:
        return "unknown"

    severity = str(value).lower().strip()
    allowed = {"low", "medium", "high", "critical", "unknown"}
    return severity if severity in allowed else "unknown"


def _detect_event_type(message: str) -> str:
    """Detect a normalized event type from a security message."""
    message = message.lower()

    if "failed login" in message or "login failed" in message:
        return "failed_login"

    if (
        "successful login" in message
        or "login success" in message
        or "logged in successfully" in message
    ):
        return "successful_login"

    if (
        "privilege escalation" in message
        or "privilege change" in message
        or "role changed" in message
        or "admin role" in message
    ):
        return "privilege_change"

    if "sensitive access" in message or "sensitive resource" in message:
        return "sensitive_access"

    if "logout" in message or "logged out" in message:
        return "logout"

    if "password changed" in message or "password reset" in message:
        return "password_change"

    if "file accessed" in message or "file access" in message:
        return "file_access"

    return "unknown"


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw security event into a standard security event."""
    message = str(event.get("message") or event.get("event") or "")
    event_type = event.get("event_type")
    if not event_type:
        event_type = _detect_event_type(message)

    return {
        "event_id": event.get("event_id"),
        "timestamp": _safe_timestamp(event.get("timestamp")),
        "username": event.get("username"),
        "ip_address": event.get("ip_address"),
        "event_type": str(event_type).lower(),
        "message": message,
        "severity": _normalize_severity(event.get("severity")),
        "ml_anomaly_score": float(event.get("ml_anomaly_score", 0)),
        "behavior_score": float(event.get("behavior_score", 0)),
        "threat_intel_score": float(event.get("threat_intel_score", 0)),
        "attack_chain_score": float(event.get("attack_chain_score", 0)),
        "risk_score": float(event.get("risk_score", 0)),
        "risk_level": event.get("risk_level", "LOW"),
    }


def normalize_events(events: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """Normalize multiple security events."""
    return [normalize_event(event) for event in events]


__all__ = ["normalize_event", "normalize_events"]