from collections.abc import Iterable

from backend.ml.alert_engine import generate_alert
from backend.ml.anomaly_detector import detect_anomalies
from backend.ml.feature_extractor import extract_features
from backend.ml.threat_classifier import classify_threat


def detect_threats(logs: Iterable) -> list[dict]:
    """Analyze failed security logs and return one result per source IP."""
    log_list = [
        log for log in logs
        if log.event_type == "login" and log.status == "failed"
    ]
    features = extract_features(log_list)
    if not features:
        return []

    features_by_ip = {
        feature["ip_address"]: feature
        for feature in features
    }
    ip_addresses = list(features_by_ip)
    attempts = [
        features_by_ip[ip]["failed_attempts"]
        for ip in ip_addresses
    ]
    ml_results = detect_anomalies(attempts)

    analysis = []
    for ip, result in zip(ip_addresses, ml_results):
        feature = features_by_ip[ip]
        ml_anomaly = bool(result["anomaly"])
        threat = classify_threat(
            failed_attempts=feature["failed_attempts"],
            unique_users=feature["unique_users"],
            event_frequency=feature["event_frequency"],
            severity_score=feature["severity_score"],
            ml_anomaly=ml_anomaly,
        )
        alert = generate_alert(threat)

        if ml_anomaly:
            risk_score = 90
            risk_level = "HIGH"
            recommendation = (
                "Investigate this IP immediately and "
                "review related security logs."
            )
        elif feature["failed_attempts"] >= 3:
            risk_score = 60
            risk_level = "MEDIUM"
            recommendation = "Monitor this IP for further suspicious activity."
        else:
            risk_score = 20
            risk_level = "LOW"
            recommendation = "Continue normal security monitoring."

        analysis.append({
            **feature,
            "ml_anomaly": ml_anomaly,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threat_type": threat["threat_type"],
            "threat_level": threat["threat_level"],
            "confidence": threat["confidence"],
            "alert": alert["alert"],
            "recommended_action": alert["recommended_action"],
            "recommendation": recommendation,
        })

    return analysis
from datetime import datetime, timedelta


def detect_brute_force(logs, threshold=5, time_window=5):
    """
    Detect multiple failed login attempts
    from the same IP within a short time window.
    """

    failed_logins = [
        log for log in logs
        if log.event_type == "login"
        and log.status == "failed"
    ]

    if not failed_logins:
        return {
            "detected": False,
            "threat_type": None,
            "message": "No brute-force activity detected"
        }

    now = datetime.utcnow()
    window_start = now - timedelta(minutes=time_window)

    recent_failures = [
        log for log in failed_logins
        if log.timestamp and log.timestamp >= window_start
    ]

    ip_counts = {}

    for log in recent_failures:
        ip = log.ip_address
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():

        if count >= threshold:
            return {
                "detected": True,
                "threat_type": "Brute Force Attack",
                "threat_level": "high",
                "ip_address": ip,
                "attempts": count,
                "message": f"{count} failed login attempts detected from {ip}"
            }

    return {
        "detected": False,
        "threat_type": None,
        "message": "No brute-force activity detected"
    }
def detect_failed_login_pattern(logs, threshold=5):
    """
    Detect repeated failed login attempts
    from the same IP address.
    """

    ip_counts = {}

    for log in logs:
        if log.event_type == "login" and log.status == "failed":

            ip = log.ip_address

            if ip not in ip_counts:
                ip_counts[ip] = 0

            ip_counts[ip] += 1

    for ip, count in ip_counts.items():

        if count >= threshold:
            return {
                "detected": True,
                "threat_type": "Brute Force Attack",
                "threat_level": "high",
                "ip_address": ip,
                "attempts": count
            }

    return {
        "detected": False,
        "threat_type": None,
        "threat_level": "low",
        "ip_address": None,
        "attempts": 0
    }
def detect_suspicious_activity(log):
    """
    Detect suspicious security events from a single log.
    """

    suspicious_events = [
        "port_scan",
        "unauthorized_access",
        "privilege_escalation",
        "malware_detected"
    ]

    if log.event_type in suspicious_events:
        return {
            "detected": True,
            "threat_type": log.event_type,
            "threat_level": "high",
            "message": f"Suspicious activity detected: {log.event_type}"
        }

    return {
        "detected": False,
        "threat_type": None,
        "threat_level": "low",
        "message": "No suspicious activity detected"
    }