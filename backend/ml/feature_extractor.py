from collections import Counter


def extract_features(logs):
    """
    Extract security-related features from logs.
    """

    if not logs:
        return []

    ip_counter = Counter(log.ip_address for log in logs)
    user_counter = Counter(log.username for log in logs)

    features = []

    for log in logs:
        ip = log.ip_address
        username = log.username

        failed_attempts = ip_counter[ip]
        unique_users = len(
            {
                item.username
                for item in logs
                if item.ip_address == ip
            }
        )

        event_frequency = ip_counter[ip]

        severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }

        severity_score = severity_mapping.get(
            log.severity.lower(),
            1
        )

        features.append({
            "ip_address": ip,
            "username": username,
            "failed_attempts": failed_attempts,
            "unique_users": unique_users,
            "event_frequency": event_frequency,
            "severity_score": severity_score
        })

    return features