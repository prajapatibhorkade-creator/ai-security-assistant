from collections import defaultdict
from datetime import datetime, timedelta


REQUEST_LIMIT = 30
WINDOW_MINUTES = 1

request_history = defaultdict(list)


def is_rate_limited(ip_address: str) -> bool:
    now = datetime.utcnow()

    request_history[ip_address] = [
        timestamp
        for timestamp in request_history[ip_address]
        if now - timestamp < timedelta(minutes=WINDOW_MINUTES)
    ]

    if len(request_history[ip_address]) >= REQUEST_LIMIT:
        return True

    request_history[ip_address].append(now)

    return False
