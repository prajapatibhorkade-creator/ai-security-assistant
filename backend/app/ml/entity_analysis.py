from collections import Counter
from typing import Any, Dict, List


def analyze_entities(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize users and source IPs across security events."""
    users = [event.get("username") for event in events if event.get("username")]
    ips = [event.get("ip_address") for event in events if event.get("ip_address")]
    user_counts = Counter(users)
    ip_counts = Counter(ips)

    return {
        "unique_users": len(user_counts),
        "unique_ips": len(ip_counts),
        "user_activity": dict(user_counts),
        "ip_activity": dict(ip_counts),
        "suspicious_users": [
            {"username": username, "event_count": count}
            for username, count in user_counts.items()
            if count >= 5
        ],
        "suspicious_ips": [
            {"ip_address": ip_address, "event_count": count}
            for ip_address, count in ip_counts.items()
            if count >= 5
        ],
    }