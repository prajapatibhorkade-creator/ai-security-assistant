import ipaddress
import os
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

from .extractor import extract_indicators

load_dotenv()


class ThreatIntelService:
    """VirusTotal API v3 integration with a provider-independent lookup API."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.api_key = None if api_key.upper() == "YOUR_API_KEY_HERE" else api_key or None

    def _headers(self) -> Dict[str, str]:
        return {
            "accept": "application/json",
            "x-apikey": self.api_key or "",
        }

    @staticmethod
    def _result(indicator_type: str, value: str, status: str, details: str) -> Dict[str, Any]:
        return {
            "indicator_type": indicator_type,
            "value": value,
            "provider": "virustotal",
            "status": status,
            "risk_score": 0,
            "details": details,
        }

    def lookup(self, indicator_type: str, value: str) -> Dict[str, Any]:
        if indicator_type == "ip":
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return self._result(indicator_type, value, "invalid", "Invalid IP address.")

            if not address.is_global:
                return self._result(
                    indicator_type,
                    value,
                    "ignored_non_public",
                    "Non-public IP addresses are not sent to VirusTotal.",
                )

        endpoint_map = {
            "ip": f"{self.BASE_URL}/ip_addresses/{value}",
            "domain": f"{self.BASE_URL}/domains/{value}",
            "sha256": f"{self.BASE_URL}/files/{value}",
            "sha1": f"{self.BASE_URL}/files/{value}",
            "md5": f"{self.BASE_URL}/files/{value}",
        }
        endpoint = endpoint_map.get(indicator_type)
        if not endpoint:
            return self._result(
                indicator_type,
                value,
                "unsupported",
                f"Unsupported indicator type: {indicator_type}",
            )

        if not self.api_key:
            return self._result(
                indicator_type,
                value,
                "not_configured",
                "VirusTotal API key is not configured.",
            )

        try:
            response = requests.get(endpoint, headers=self._headers(), timeout=10)
            if response.status_code == 404:
                return self._result(
                    indicator_type,
                    value,
                    "not_found",
                    "Indicator was not found in VirusTotal.",
                )

            response.raise_for_status()
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            risk_score = min(100, (malicious * 10) + (suspicious * 5))

            if malicious > 0:
                reputation_label = "malicious"
            elif suspicious > 0:
                reputation_label = "suspicious"
            else:
                reputation_label = "clean_or_unknown"

            return {
                "indicator_type": indicator_type,
                "value": value,
                "provider": "virustotal",
                "status": "success",
                "malicious": malicious > 0,
                "suspicious": suspicious > 0,
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "reputation": attributes.get("reputation", 0),
                "reputation_label": reputation_label,
                "risk_score": risk_score,
            }
        except requests.Timeout:
            return self._result(
                indicator_type,
                value,
                "timeout",
                "Threat intelligence request timed out.",
            )
        except requests.RequestException:
            return self._result(
                indicator_type,
                value,
                "error",
                "Threat intelligence request failed.",
            )


def enrich_indicators(indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    service = ThreatIntelService()
    return [
        service.lookup(
            indicator_type=indicator["type"],
            value=indicator["value"],
        )
        for indicator in indicators
    ]


def enrich_security_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Preserve the existing event API while enriching extracted indicators."""
    payload = event if isinstance(event, dict) else {}
    text_blob = " ".join(
        str(value)
        for value in [
            payload.get("username"),
            payload.get("ip_address"),
            payload.get("event_type"),
            payload.get("status"),
            payload.get("severity"),
            payload.get("details"),
            payload.get("message"),
        ]
        if value is not None
    )

    indicators = extract_indicators(text_blob)
    intel = enrich_indicators(indicators)
    suspicious = any(item.get("malicious", False) for item in intel)
    return {
        "indicators": indicators,
        "intel": intel,
        "suspicious": suspicious,
        "risk_boost": max((item.get("risk_score", 0) for item in intel), default=0),
        "summary": "Suspicious indicator observed" if suspicious else "No provider-reported malicious indicator",
    }
