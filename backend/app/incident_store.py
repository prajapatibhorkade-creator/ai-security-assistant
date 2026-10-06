import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


INCIDENT_FILE = Path(os.getenv(
    "INCIDENT_FILE",
    str(Path(__file__).resolve().parent.parent / "incidents.json"),
))
_STORE_LOCK = threading.Lock()


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _load_incidents() -> List[Dict[str, Any]]:
    if not INCIDENT_FILE.exists():
        return []
    try:
        with INCIDENT_FILE.open("r", encoding="utf-8") as file:
            incidents = json.load(file)
        return incidents if isinstance(incidents, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def create_incident_record(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Append an incident record with an atomic file replacement."""
    with _STORE_LOCK:
        incidents = _load_incidents()
        previous_ids = [
            int(str(record["incident_id"]).split("-")[-1])
            for record in incidents
            if str(record.get("incident_id", "")).startswith("INC-")
            and str(record["incident_id"]).split("-")[-1].isdigit()
        ]
        incident_id = f"INC-{max(previous_ids, default=0) + 1:04d}"
        event = analysis.get("event", {})
        risk = analysis.get("risk_analysis", {})
        correlation = analysis.get("attack_correlation", {})
        managed_incident = analysis.get("incident") or {}

        incident = {
            "incident_id": incident_id,
            "created_at": datetime.now().isoformat(),
            "status": managed_incident.get("status", "open"),
            "incident_detected": analysis.get("final_decision", {}).get(
                "incident_detected", bool(managed_incident)
            ),
            "username": event.get("username"),
            "ip_address": event.get("ip_address"),
            "event_type": event.get("event_type"),
            "risk_score": risk.get("risk_score", 0),
            "risk_level": risk.get("risk_level", "LOW"),
            "attack_chain_score": managed_incident.get(
                "attack_chain_score",
                event.get("attack_chain_score", correlation.get("attack_chain_score", 0)),
            ),
            "patterns": managed_incident.get("patterns", correlation.get("patterns", [])),
            "timeline": managed_incident.get("timeline", correlation.get("timeline", [])),
        }
        incidents.append(incident)

        INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = INCIDENT_FILE.with_suffix(INCIDENT_FILE.suffix + ".tmp")
        try:
            with temporary_path.open("w", encoding="utf-8") as file:
                json.dump(_json_safe(incidents), file, indent=2)
            os.replace(temporary_path, INCIDENT_FILE)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
        return incident


def get_incidents() -> List[Dict[str, Any]]:
    with _STORE_LOCK:
        return _load_incidents()