import hashlib
import ipaddress
import re
from typing import Dict, List


DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_indicators(text: str) -> List[Dict[str, str]]:
    """Extract possible IP addresses, domains and SHA-256 hashes from text."""
    if not text:
        return []

    indicators = []

    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(match)
            indicators.append({"type": "ip", "value": match})
        except ValueError:
            pass

    for match in DOMAIN_PATTERN.findall(text):
        indicators.append({"type": "domain", "value": match.lower()})

    for match in HASH_PATTERN.findall(text):
        indicators.append({"type": "sha256", "value": match.lower()})

    unique = []
    seen = set()
    for indicator in indicators:
        key = (indicator["type"], indicator["value"])
        if key not in seen:
            seen.add(key)
            unique.append(indicator)

    return unique
