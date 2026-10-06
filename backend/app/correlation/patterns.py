from typing import Any, Dict, List


def detect_advanced_patterns(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect suspicious attack patterns across normalized events."""
    findings = []
    if not events:
        return findings

    failed_logins = [event for event in events if event.get("event_type") == "failed_login"]
    if len(failed_logins) >= 5:
        findings.append({
            "type": "brute_force",
            "name": "Brute Force Activity",
            "severity": "HIGH",
            "score": 30,
            "evidence_count": len(failed_logins),
        })

    successful_logins = [event for event in events if event.get("event_type") == "successful_login"]
    unknown_ip_events = [event for event in events if event.get("known_ip") is False]
    if successful_logins and unknown_ip_events:
        findings.append({
            "type": "account_takeover",
            "name": "Possible Account Takeover",
            "severity": "CRITICAL",
            "score": 40,
            "evidence_count": len(successful_logins) + len(unknown_ip_events),
        })

    privilege_events = [event for event in events if event.get("event_type") == "privilege_change"]
    if privilege_events:
        findings.append({
            "type": "privilege_escalation",
            "name": "Privilege Escalation Activity",
            "severity": "CRITICAL",
            "score": 35,
            "evidence_count": len(privilege_events),
        })

    sensitive_events = [event for event in events if event.get("event_type") == "sensitive_access"]
    if len(sensitive_events) >= 2:
        findings.append({
            "type": "data_access_anomaly",
            "name": "Repeated Sensitive Resource Access",
            "severity": "HIGH",
            "score": 25,
            "evidence_count": len(sensitive_events),
        })

    usernames = {event.get("username") for event in events if event.get("username")}
    if len(usernames) >= 3:
        findings.append({
            "type": "multi_user_activity",
            "name": "Activity Across Multiple Accounts",
            "severity": "HIGH",
            "score": 25,
            "evidence_count": len(usernames),
        })

    ip_addresses = {event.get("ip_address") for event in events if event.get("ip_address")}
    if len(ip_addresses) >= 3:
        findings.append({
            "type": "multi_ip_activity",
            "name": "Distributed Source IP Activity",
            "severity": "HIGH",
            "score": 25,
            "evidence_count": len(ip_addresses),
        })

    return findings


def calculate_pattern_score(findings: List[Dict[str, Any]]) -> float:
    """Return a capped combined score for advanced pattern findings."""
    return min(100, sum(finding.get("score", 0) for finding in findings))