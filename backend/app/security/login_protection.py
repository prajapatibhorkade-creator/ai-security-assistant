"""Protect login endpoints from repeated failed attempts by IP address."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock


MAX_FAILED_ATTEMPTS = 5
BLOCK_MINUTES = 10
ATTEMPT_WINDOW_MINUTES = 10

failed_attempts: defaultdict[str, list[datetime]] = defaultdict(list)
blocked_ips: dict[str, datetime] = {}
_lock = Lock()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def is_ip_blocked(ip_address: str) -> bool:
    with _lock:
        blocked_until = blocked_ips.get(ip_address)
        if blocked_until is None:
            return False

        if _utc_now() >= blocked_until:
            blocked_ips.pop(ip_address, None)
            failed_attempts.pop(ip_address, None)
            return False

        return True


def record_failed_attempt(ip_address: str) -> None:
    now = _utc_now()
    cutoff = now - timedelta(minutes=ATTEMPT_WINDOW_MINUTES)

    with _lock:
        failed_attempts[ip_address] = [
            timestamp
            for timestamp in failed_attempts[ip_address]
            if timestamp > cutoff
        ]
        failed_attempts[ip_address].append(now)

        if len(failed_attempts[ip_address]) >= MAX_FAILED_ATTEMPTS:
            blocked_ips[ip_address] = now + timedelta(minutes=BLOCK_MINUTES)


def clear_failed_attempts(ip_address: str) -> None:
    with _lock:
        failed_attempts.pop(ip_address, None)
        blocked_ips.pop(ip_address, None)
