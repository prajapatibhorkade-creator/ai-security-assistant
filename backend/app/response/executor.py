from datetime import datetime

from backend.app.models.audit_log import AuditLog
from backend.app.response.actions import get_allowed_actions


def execute_approved_action(db, action_id: str, alert_id: int | None = None, approved: bool = False, approved_by: str | None = None, details: str | None = None, ip_address: str | None = None):
    """Execute a response action only after analyst approval is confirmed."""
    allowed = []
    for action in get_allowed_actions():
        allowed.append(action["action_id"])

    if action_id not in allowed:
        raise ValueError(f"Unsupported response action: {action_id}")

    if not approved:
        return {
            "result": {
                "success": False,
                "message": "Action requires analyst approval before execution.",
            },
            "audit": None,
        }

    action_name = next(
        (item["title"] for item in get_allowed_actions() if item["action_id"] == action_id),
        action_id,
    )
    audit = AuditLog(
        username=approved_by or "system",
        action=action_name,
        target=f"alert_id:{alert_id}" if alert_id is not None else "incident",
        ip_address=ip_address,
        success=True,
        details=details or f"Approved by {approved_by or 'system'} for response action {action_id}.",
        timestamp=datetime.utcnow(),
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)

    return {
        "result": {
            "success": True,
            "message": action_name,
            "approved_by": approved_by or "system",
        },
        "audit": {
            "id": audit.id,
            "action": audit.action,
            "target": audit.target,
            "username": audit.username,
            "ip_address": audit.ip_address,
            "success": audit.success,
            "details": audit.details,
            "timestamp": audit.timestamp.isoformat() if audit.timestamp else None,
        },
    }
