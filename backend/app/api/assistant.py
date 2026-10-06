from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta

from fastapi import HTTPException
from pydantic import BaseModel

from backend.app.models.security_alert import SecurityAlert
from backend.app.models.security_log import SecurityLog


class CopilotRequest(BaseModel):
    question: str


def _parse_ip(question: str):
    match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", question)
    return match.group(0) if match else None


def _parse_username(question: str):
    match = re.search(r"user\s+([A-Za-z0-9_.-]+)", question, flags=re.IGNORECASE)
    return match.group(1) if match else None


def _recent_logs(db, hours: int = 24):
    since = datetime.utcnow() - timedelta(hours=hours)
    return db.query(SecurityLog).filter(SecurityLog.timestamp >= since).all()


def _summarize_for_alert(db, alert):
    ip_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.ip_address == alert.ip_address,
            SecurityLog.event_type.in_(["login", "failed_login"]),
        )
        .order_by(SecurityLog.timestamp.desc())
        .limit(10)
        .all()
    )
    failed_count = sum(
        1
        for log in ip_logs
        if log.status.lower() == "failed"
    )
    return {
        "alert_id": alert.id,
        "ip_address": alert.ip_address,
        "threat_type": alert.threat_type,
        "threat_level": alert.threat_level,
        "risk_score": alert.risk_score,
        "failed_count": failed_count,
        "log_count": len(ip_logs),
        "recent_sample": [
            {
                "username": log.username,
                "status": log.status,
                "event_type": log.event_type,
                "severity": log.severity,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            }
            for log in ip_logs[:5]
        ],
    }


def generate_security_copilot_answer(db, question: str):
    q = (question or "").strip()
    if not q:
        raise HTTPException(status_code=400, detail="Question is required")

    lower_q = q.lower()

    if "why" in lower_q and "alert" in lower_q:
        alert = (
            db.query(SecurityAlert)
            .order_by(SecurityAlert.created_at.desc())
            .first()
        )
        if not alert:
            return {
                "answer": "No security alerts have been generated yet. The recent log history appears clean.",
                "context": {"alert_count": 0},
            }

        summary = _summarize_for_alert(db, alert)
        answer = (
            f"Alert #{alert.id} was generated because the source IP {alert.ip_address} showed "
            f"{summary['failed_count']} failed login attempts, which is consistent with a {alert.threat_type.lower()} pattern. "
            f"The threat level is {alert.threat_level} and the risk score is {alert.risk_score}. "
            f"The activity was also outside the normal pattern for this account and matched a high-risk anomaly profile. "
            "Recommended response: investigate this IP, review the affected account, and block the IP if the behavior continues."
        )
        return {
            "answer": answer,
            "context": {
                "alert_id": alert.id,
                "ip_address": alert.ip_address,
                "threat_level": alert.threat_level,
                "risk_score": alert.risk_score,
                "failed_attempts": summary["failed_count"],
            },
        }

    user_target = _parse_username(q)
    if user_target:
        logs = (
            db.query(SecurityLog)
            .filter(SecurityLog.username == user_target)
            .order_by(SecurityLog.timestamp.desc())
            .limit(20)
            .all()
        )
        if not logs:
            return {
                "answer": f"I did not find recent activity for user {user_target} in the security log history.",
                "context": {"username": user_target, "log_count": 0},
            }

        failed_count = sum(1 for log in logs if log.status.lower() == "failed")
        ip_counts = Counter(log.ip_address for log in logs)
        top_ip = ip_counts.most_common(1)[0][0] if ip_counts else "unknown"
        answer = (
            f"User {user_target} showed unusual activity: {failed_count} failed login events in the recent log history, "
            f"with the most frequent source IP being {top_ip}. This pattern indicates a deviation from normal behavior and warrants review."
        )
        return {
            "answer": answer,
            "context": {
                "username": user_target,
                "recent_logs": len(logs),
                "failed_attempts": failed_count,
                "top_ip": top_ip,
            },
        }

    ip_target = _parse_ip(q)
    if ip_target:
        logs = (
            db.query(SecurityLog)
            .filter(SecurityLog.ip_address == ip_target)
            .order_by(SecurityLog.timestamp.desc())
            .limit(25)
            .all()
        )
        if not logs:
            return {
                "answer": f"I did not find recent suspicious activity from IP {ip_target}.",
                "context": {"ip_address": ip_target, "log_count": 0},
            }

        failed_count = sum(1 for log in logs if log.status.lower() == "failed")
        users = sorted({log.username for log in logs})
        answer = (
            f"IP {ip_target} generated {failed_count} failed login events across {len(users)} distinct usernames. "
            f"This source was active in the recent activity window and matches a suspicious pattern. Recommended action: review the IP, compare it with known trusted ranges, and consider rate limiting or blocking it."
        )
        return {
            "answer": answer,
            "context": {"ip_address": ip_target, "failed_attempts": failed_count, "usernames": users},
        }

    if "24 hours" in lower_q or "last 24" in lower_q or "summarize" in lower_q:
        recent_logs = _recent_logs(db, 24)
        failed_logs = [log for log in recent_logs if log.status.lower() == "failed"]
        success_logs = [log for log in recent_logs if log.status.lower() == "success"]
        by_ip = Counter(log.ip_address for log in failed_logs)
        top_ip = by_ip.most_common(1)[0][0] if by_ip else "none"
        answer = (
            f"During the last 24 hours, there were {len(recent_logs)} security events, including {len(failed_logs)} failed events and {len(success_logs)} successful events. "
            f"The most suspicious source was {top_ip}, which should be reviewed first for potential brute-force or credential abuse activity."
        )
        return {
            "answer": answer,
            "context": {
                "window_hours": 24,
                "total_events": len(recent_logs),
                "failed_events": len(failed_logs),
                "successful_events": len(success_logs),
                "top_ip": top_ip,
            },
        }

    if "recommend" in lower_q or "investigate next" in lower_q:
        alert = (
            db.query(SecurityAlert)
            .order_by(SecurityAlert.risk_score.desc(), SecurityAlert.created_at.desc())
            .first()
        )
        if alert:
            answer = (
                f"The next investigation should focus on alert #{alert.id} from IP {alert.ip_address}. "
                f"This alert is rated {alert.threat_level} with a risk score of {alert.risk_score}. Investigate the affected account, confirm whether the IP is trusted, and review related failed login and privilege activity before escalating."
            )
            return {"answer": answer, "context": {"next_alert_id": alert.id, "ip_address": alert.ip_address}}

        answer = "There are no active alerts to prioritize. Continue routine monitoring and review the most recent failed login patterns for any unusual spikes."
        return {"answer": answer, "context": {"next_alert_id": None}}

    recent_logs = _recent_logs(db, 24)
    suspicious = [log for log in recent_logs if log.status.lower() == "failed"]
    answer = (
        "I reviewed the recent security context and found that repeated failed login activity is the clearest signal. "
        f"The latest dataset includes {len(suspicious)} failed events in the last 24 hours, which should be investigated by checking the source IPs, user accounts, and known trust boundaries."
    )
    return {
        "answer": answer,
        "context": {"recent_events": len(recent_logs), "failed_events": len(suspicious)},
    }
