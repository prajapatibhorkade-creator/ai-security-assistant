from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional


def _clamp(value: float, minimum: float = 0, maximum: float = 100) -> float:
    return max(minimum, min(value, maximum))


def calculate_behavior_score(
    current_hour: int,
    failed_attempts: int = 0,
    known_ip: bool = True,
    recent_event_count: int = 0,
) -> Dict[str, Any]:
    """Calculate a behavior risk score from observable activity signals."""
    score = 0.0
    anomalies: List[str] = []

    if current_hour < 6 or current_hour >= 22:
        score += 30
        anomalies.append("Unusual login time")
    elif current_hour < 8 or current_hour >= 20:
        score += 10
        anomalies.append("Login outside normal working hours")

    if failed_attempts >= 10:
        score += 30
        anomalies.append("High failed-login activity")
    elif failed_attempts >= 5:
        score += 20
        anomalies.append("Elevated failed-login activity")
    elif failed_attempts >= 3:
        score += 10

    if not known_ip:
        score += 25
        anomalies.append("Unknown source IP")

    if recent_event_count >= 100:
        score += 15
        anomalies.append("Unusually high activity frequency")
    elif recent_event_count >= 50:
        score += 8
        anomalies.append("Elevated activity frequency")

    score = round(_clamp(score), 2)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "behavior_score": score,
        "risk_level": risk_level,
        "anomalies": anomalies,
        "signals": {
            "current_hour": current_hour,
            "failed_attempts": failed_attempts,
            "known_ip": known_ip,
            "recent_event_count": recent_event_count,
        },
    }


def analyze_login_behavior(
    login_time: Optional[datetime] = None,
    failed_attempts: int = 0,
    known_ip: bool = True,
    recent_event_count: int = 0,
) -> Dict[str, Any]:
    """Analyze login behavior, defaulting to the current local time."""
    if login_time is None:
        login_time = datetime.now()

    return calculate_behavior_score(
        current_hour=login_time.hour,
        failed_attempts=failed_attempts,
        known_ip=known_ip,
        recent_event_count=recent_event_count,
    )


def _safe_hour(value):
    if value is None:
        return None
    if hasattr(value, "hour"):
        return value.hour
    return int(value)


def _dominant_hour(logs):
    hours = [
        _safe_hour(log.timestamp)
        for log in logs
        if getattr(log, "timestamp", None) is not None
    ]
    if not hours:
        return 12
    return Counter(hours).most_common(1)[0][0]


def evaluate_user_behavior(logs):
    """Assess each user's behavior against their historical activity profile."""
    if not logs:
        return []

    grouped = defaultdict(list)
    for log in logs:
        grouped[log.username].append(log)

    results = []
    for username, user_logs in sorted(grouped.items()):
        user_logs = sorted(user_logs, key=lambda item: item.timestamp or datetime.utcnow())
        latest_log = user_logs[-1]
        latest_hour = _safe_hour(latest_log.timestamp) or datetime.utcnow().hour

        known_ips = {log.ip_address for log in user_logs}
        dominant_ip = Counter(log.ip_address for log in user_logs).most_common(1)[0][0]
        dominant_hour = _dominant_hour(user_logs)
        failed_attempts = sum(
            1
            for log in user_logs
            if log.status.lower() == "failed" and log.event_type.lower() in {"login", "failed_login"}
        )
        avg_events_per_day = max(1, len(user_logs) / max(1, len({log.timestamp.date() for log in user_logs})))
        last_hour_count = sum(
            1
            for log in user_logs
            if log.timestamp and abs((datetime.utcnow() - log.timestamp).total_seconds()) <= 3600
        )
        risk_score = 10
        signals = []

        if latest_log.ip_address not in known_ips:
            risk_score += 35
            signals.append("Unknown IP")
        elif latest_log.ip_address != dominant_ip:
            risk_score += 15
            signals.append("IP deviation")

        if failed_attempts >= 5:
            risk_score += 25
            signals.append("Failed-login anomaly")
        elif failed_attempts >= 3:
            risk_score += 15
            signals.append("Repeated failed attempts")

        if abs(latest_hour - dominant_hour) >= 6:
            risk_score += 30
            signals.append("Login time anomaly")

        if last_hour_count > avg_events_per_day * 2:
            risk_score += 20
            signals.append("Unusual request frequency")

        if latest_log.event_type.lower() == "login" and latest_log.status.lower() == "failed":
            risk_score += 10
            signals.append("Sudden activity spike")

        behavior_risk = min(100, risk_score)
        behavior_level = "LOW"
        if behavior_risk >= 75:
            behavior_level = "HIGH"
        elif behavior_risk >= 45:
            behavior_level = "MEDIUM"

        results.append({
            "username": username,
            "known_ips": sorted(known_ips),
            "dominant_ip": dominant_ip,
            "normal_login_hour": dominant_hour,
            "current_login_hour": latest_hour,
            "failed_attempts": failed_attempts,
            "behavior_risk": behavior_risk,
            "behavior_level": behavior_level,
            "anomaly": behavior_risk >= 60,
            "signals": signals or ["Normal activity pattern"],
        })

    return sorted(results, key=lambda item: item["behavior_risk"], reverse=True)


__all__ = [
    "analyze_login_behavior",
    "calculate_behavior_score",
    "evaluate_user_behavior",
]
