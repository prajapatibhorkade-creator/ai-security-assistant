from datetime import datetime


def simulate_brute_force(username="test_user", ip_address="203.0.113.50", attempts=10):
    events = []
    for index in range(attempts):
        events.append({
            "event_id": index + 1,
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "ip_address": ip_address,
            "event_type": "failed_login",
            "message": "Failed login detected",
            "severity": "high",
            "failed_attempts": index + 1,
            "known_ip": False,
            "recent_event_count": index + 1,
            "ml_anomaly_score": 80,
        })

    events.append({
        "event_id": attempts + 1,
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "ip_address": ip_address,
        "event_type": "successful_login",
        "message": "Successful login detected after repeated failures",
        "severity": "critical",
        "failed_attempts": attempts,
        "known_ip": False,
        "recent_event_count": attempts + 1,
        "ml_anomaly_score": 95,
    })
    return events


def simulate_privilege_escalation(username="test_admin", ip_address="203.0.113.60"):
    return [
        {
            "event_id": 1,
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "ip_address": ip_address,
            "event_type": "successful_login",
            "message": "Successful login detected",
            "severity": "medium",
            "failed_attempts": 0,
            "known_ip": False,
            "recent_event_count": 5,
            "ml_anomaly_score": 50,
        },
        {
            "event_id": 2,
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "ip_address": ip_address,
            "event_type": "privilege_change",
            "message": "Privilege escalation detected",
            "severity": "critical",
            "failed_attempts": 0,
            "known_ip": False,
            "recent_event_count": 10,
            "ml_anomaly_score": 90,
        },
        {
            "event_id": 3,
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "ip_address": ip_address,
            "event_type": "sensitive_access",
            "message": "Sensitive resource access detected",
            "severity": "critical",
            "failed_attempts": 0,
            "known_ip": False,
            "recent_event_count": 20,
            "ml_anomaly_score": 95,
        },
    ]