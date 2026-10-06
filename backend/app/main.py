import re

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.schemas.user import (
    RoleUpdate,
    Token,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from backend.app.security.login_protection import (
    clear_failed_attempts,
    is_ip_blocked,
    record_failed_attempt,
)
from backend.app.security.rate_limiter import is_rate_limited

from backend.app.database import Base, engine, get_db
from backend.app.models.audit_log import AuditLog
from backend.app.models.security_alert import SecurityAlert
from backend.app.models.security_log import SecurityLog
from backend.app.models.user import User
from backend.app.schemas.security_alert import (
    SecurityAlertResponse,
    SecurityAlertUpdate,
)
from backend.app.schemas.security_log import SecurityLogCreate, SecurityLogResponse
from backend.app.schemas.user import RoleUpdate, Token, UserCreate, UserResponse
from backend.app.auth.security import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from backend.ml.anomaly_detector import detect_anomalies
from backend.ml.feature_extractor import extract_features
from backend.ml.threat_classifier import classify_threat
from backend.ml.alert_engine import generate_alert
from backend.app.ml.behavior import evaluate_user_behavior
from backend.app.api.assistant import CopilotRequest, generate_security_copilot_answer
from backend.app.correlation.engine import build_incident, correlate_attack_chain, correlate_events
from backend.app.pipeline import analyze_security_event
from backend.app.ai_copilot import generate_security_explanation
from backend.app.incident_report import generate_incident_report
from backend.app.incident_store import get_incidents
from backend.app.analytics import generate_security_analytics
from backend.app.ml.risk_engine import calculate_risk_score as calculate_composite_risk_score
from backend.app.threat_intel.service import enrich_security_event
from backend.app.models.alert_status_history import AlertStatusHistory
from backend.app.response.executor import execute_approved_action
from backend.app.response.recommendations import build_response_recommendations

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Security Assistant",
    description="AI-powered cybersecurity monitoring and threat detection system",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home():
    return {
        "message": "AI Security Assistant is running!"
    }


@app.get("/logs", response_model=list[SecurityLogResponse])
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).all()

    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "username": log.username,
            "ip_address": log.ip_address,
            "event_type": log.event_type,
            "status": log.status,
            "severity": log.severity,
        }
        for log in logs
    ]
@app.get("/logs/{log_id}", response_model=SecurityLogResponse)
def get_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(SecurityLog).filter(SecurityLog.id == log_id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "username": log.username,
        "ip_address": log.ip_address,
        "event_type": log.event_type,
        "status": log.status,
        "severity": log.severity,
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/copilot")
def copilot_assistant(
    payload: CopilotRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = generate_security_copilot_answer(db, payload.question)
    return {
        "question": payload.question,
        "asked_by": current_user.get("username"),
        "answer": result["answer"],
        "context": result.get("context", {}),
    }


def _calculate_explainable_risk(
    db: Session,
    username: str | None,
    ip_address: str | None,
    severity: str | None,
    ml_anomaly: bool = False,
):
    logs = db.query(SecurityLog).all()
    user_logs = [log for log in logs if username and log.username == username]
    behavior_results = evaluate_user_behavior(user_logs)
    behavior_score = next(
        (item["behavior_risk"] for item in behavior_results if item["username"] == username),
        0,
    )

    event_intel = enrich_security_event({
        "username": username,
        "ip_address": ip_address,
        "event_type": "security_alert",
        "severity": severity,
    })
    threat_intelligence_score = 100 if event_intel["suspicious"] else 0

    related_logs = [
        log for log in logs
        if (username and log.username == username)
        or (ip_address and log.ip_address == ip_address)
    ]
    clusters = correlate_events(related_logs)
    incidents = [build_incident(cluster) for cluster in clusters]
    legacy_chain_score = max(
        (incident["risk_score"] for incident in incidents if incident),
        default=0,
    )
    chain_events = []
    for log in related_logs:
        event_type = log.event_type.lower()
        if event_type in {"login", "failed_login", "successful_login"}:
            if log.status.lower() == "failed":
                event_type = "failed_login"
            elif log.status.lower() in {"success", "successful"}:
                event_type = "successful_login"
        chain_events.append({
            "timestamp": log.timestamp,
            "event_type": event_type,
            "username": log.username,
            "ip_address": log.ip_address,
            "severity": log.severity,
        })
    chain_report = correlate_attack_chain(chain_events)
    attack_chain_score = max(legacy_chain_score, chain_report["attack_chain_score"])

    severity_scores = {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 100,
    }
    severity_value = severity_scores.get(str(severity).lower(), 0)

    return calculate_composite_risk_score(
        ml_anomaly_score=100 if ml_anomaly else 0,
        behavior_score=behavior_score,
        threat_intel_score=threat_intelligence_score,
        attack_chain_score=attack_chain_score,
        severity_score=severity_value,
    )


def _trigger_security_analysis(db: Session, log: SecurityLog):
    if log.status.lower() != "failed":
        return

    if log.event_type.lower() not in {"login", "failed_login"}:
        return

    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.status == "failed",
            SecurityLog.event_type.in_(["login", "failed_login"]),
        )
        .all()
    )

    if not failed_logs:
        return

    ip_counts = {}
    for item in failed_logs:
        ip_counts[item.ip_address] = ip_counts.get(item.ip_address, 0) + 1

    if log.ip_address not in ip_counts:
        return

    attempts = list(ip_counts.values())
    ml_results = detect_anomalies(attempts)
    result_by_ip = dict(zip(ip_counts.keys(), ml_results))
    result = result_by_ip.get(log.ip_address)

    if result is None:
        return

    count = ip_counts[log.ip_address]
    unique_users = len({
        item.username for item in failed_logs if item.ip_address == log.ip_address
    })

    threat = classify_threat(
        failed_attempts=count,
        unique_users=unique_users,
        event_frequency=count,
        severity_score={
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }.get(log.severity.lower(), 1),
        ml_anomaly=bool(result["anomaly"]),
    )
    alert = generate_alert(threat)

    if not (result["anomaly"] or count >= 3 or alert["alert"]):
        return

    existing_alert = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.ip_address == log.ip_address,
            SecurityAlert.threat_type == threat["threat_type"],
            SecurityAlert.threat_level == threat["threat_level"],
            SecurityAlert.status != "resolved",
        )
        .first()
    )

    if existing_alert is not None:
        return

    risk_assessment = _calculate_explainable_risk(
        db=db,
        username=log.username,
        ip_address=log.ip_address,
        severity=log.severity,
        ml_anomaly=bool(result["anomaly"]),
    )
    db.add(
        SecurityAlert(
            ip_address=log.ip_address,
            username=log.username,
            threat_type=threat["threat_type"],
            threat_level=threat["threat_level"],
            confidence=threat["confidence"],
            risk_score=risk_assessment["risk_score"],
            ml_anomaly=bool(result["anomaly"]),
            recommended_action=alert["recommended_action"],
        )
    )
    db.commit()


@app.post("/logs", response_model=SecurityLogResponse)
def create_security_log(
    log: SecurityLogCreate,
    db: Session = Depends(get_db)
):
    new_log = SecurityLog(
        username=log.username,
        ip_address=log.ip_address,
        event_type=log.event_type,
        status=log.status,
        severity=log.severity
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    _trigger_security_analysis(db, new_log)

    return {
        "id": new_log.id,
        "timestamp": new_log.timestamp.isoformat(),
        "username": new_log.username,
        "ip_address": new_log.ip_address,
        "event_type": new_log.event_type,
        "status": new_log.status,
        "severity": new_log.severity
    }


@app.get("/security/failed-logins", response_model=list[SecurityLogResponse])
def get_failed_logins(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .order_by(SecurityLog.timestamp.desc())
        .all()
    )

    return [
        {
            "id": log.id,
            "username": log.username,
            "ip_address": log.ip_address,
            "event_type": log.event_type,
            "status": log.status,
            "severity": log.severity,
            "timestamp": log.timestamp.isoformat()
        }
        for log in failed_logs
    ]
@app.get("/security/suspicious-logins")
def detect_suspicious_logins(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .all()
    )

    ip_counts = {}

    for log in failed_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    suspicious = []

    for ip, count in ip_counts.items():
        if count >= 5:
            suspicious.append({
                "ip_address": ip,
                "failed_attempts": count,
                "risk": "HIGH",
                "message": "Multiple failed login attempts detected"
            })

    return suspicious
@app.get("/security/risk-score")
def calculate_risk_score(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .all()
    )

    ip_counts = {}

    for log in failed_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    results = []

    for ip, count in ip_counts.items():

        if count >= 5:
            risk = "HIGH"
            score = 90
        elif count >= 3:
            risk = "MEDIUM"
            score = 60
        else:
            risk = "LOW"
            score = 20

        results.append({
            "ip_address": ip,
            "failed_attempts": count,
            "risk_score": score,
            "risk_level": risk
        })

    return results
@app.get("/security/alerts")
def get_security_alerts(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .all()
    )

    ip_counts = {}

    for log in failed_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    alerts = []

    for ip, count in ip_counts.items():
        if count >= 5:
            alerts.append({
                "ip_address": ip,
                "alert": "Brute-force login attempt suspected",
                "failed_attempts": count,
                "risk_level": "HIGH",
                "recommended_action": "Investigate and block the IP"
            })

    return alerts
@app.get("/security/analyze")
def analyze_security_events(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .all()
    )

    ip_counts = {}

    for log in failed_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    analysis = []

    for ip, count in ip_counts.items():

        if count >= 5:
            risk = "HIGH"
            threat = "Possible brute-force attack"
            explanation = (
                f"IP {ip} generated {count} failed login attempts. "
                "This behavior is suspicious and may indicate a brute-force attack."
            )
            recommendation = (
                "Investigate the source IP, review related logs, "
                "and consider blocking the IP if the activity is confirmed malicious."
            )

        elif count >= 3:
            risk = "MEDIUM"
            threat = "Repeated failed login attempts"
            explanation = (
                f"IP {ip} generated {count} failed login attempts."
            )
            recommendation = (
                "Monitor this IP and review additional authentication activity."
            )

        else:
            risk = "LOW"
            threat = "Low-level authentication anomaly"
            explanation = (
                f"IP {ip} generated {count} failed login attempt(s)."
            )
            recommendation = "Continue monitoring."

        analysis.append({
            "ip_address": ip,
            "failed_attempts": count,
            "risk_level": risk,
            "threat": threat,
            "explanation": explanation,
            "recommendation": recommendation
        })

    return analysis


@app.post("/security/analyze")
def analyze_security(event: dict, db: Session = Depends(get_db)):
    payload = dict(event)
    related_events = payload.pop("related_events", None)
    result = analyze_security_event(payload, related_events=related_events)

    decision = result["final_decision"]
    alert_created = decision["incident_detected"] or decision["risk_score"] >= 60
    alert_data = None

    if alert_created:
        normalized_event = result["event"]
        risk_analysis = result["risk_analysis"]
        alert = SecurityAlert(
            ip_address=normalized_event.get("ip_address") or "unknown",
            username=normalized_event.get("username"),
            threat_type=normalized_event.get("event_type") or "Unknown Threat",
            threat_level=decision["risk_level"].lower(),
            confidence=float(risk_analysis["raw_scores"]["ml_anomaly"]),
            risk_score=decision["risk_score"],
            ml_anomaly=risk_analysis["raw_scores"]["ml_anomaly"] >= 50,
            recommended_action=(
                "Investigate correlated attack chain immediately."
                if decision["incident_detected"]
                else "Review elevated security risk and related activity."
            ),
            status="open",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_data = {
            "id": alert.id,
            "status": alert.status,
            "risk_score": alert.risk_score,
            "threat_level": alert.threat_level,
        }

    return {
        "status": "success",
        "analysis": result,
        "alert_created": alert_created,
        "alert": alert_data,
    }


@app.post("/security/copilot")
def security_copilot(event: dict):
    payload = dict(event)
    related_events = payload.pop("related_events", None)
    analysis = analyze_security_event(payload, related_events=related_events)
    explanation = generate_security_explanation(analysis)
    return {
        "status": "success",
        "copilot": explanation,
        "analysis": analysis,
    }


@app.post("/security/report")
def security_report(event: dict):
    payload = dict(event)
    related_events = payload.pop("related_events", None)
    analysis = analyze_security_event(payload, related_events=related_events)
    report = generate_incident_report(analysis)
    return {
        "status": "success",
        "report": report,
    }


@app.get("/security/ml-analysis")
def ml_security_analysis(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.status == "failed",
            SecurityLog.event_type.in_(["login", "failed_login"])
        )
        .all()
    )

    ip_counts = {}

    for log in failed_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    if not ip_counts:
        return {
            "message": "No failed login activity found"
        }

    attempts = list(ip_counts.values())

    ml_results = detect_anomalies(attempts)

    analysis = []

    for (ip, count), result in zip(ip_counts.items(), ml_results):

        if result["anomaly"]:
            risk_score = 90
            risk_level = "HIGH"
            recommendation = "Investigate this IP immediately."

        elif count >= 3:
            risk_score = 60
            risk_level = "MEDIUM"
            recommendation = "Monitor this IP for further suspicious activity."

        else:
            risk_score = 20
            risk_level = "LOW"
            recommendation = "Continue normal monitoring."

        analysis.append({
            "ip_address": ip,
            "failed_attempts": count,
            "ml_anomaly": bool(result["anomaly"]),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendation": recommendation,
        })

    return analysis
@app.get("/security/features")
def security_features(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).all()

    features = extract_features(logs)

    return {
        "total_logs": len(logs),
        "features": features
    }


@app.get("/security/behavior")
def user_behavior_analysis(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.asc()).all()
    return evaluate_user_behavior(logs)


@app.get("/security/incidents/correlated")
def incidents_summary(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.asc()).all()
    clusters = correlate_events(logs)
    incidents = []

    for cluster in clusters:
        incident = build_incident(cluster)
        if incident is not None:
            incidents.append(incident)

    return sorted(incidents, key=lambda item: item["risk_score"], reverse=True)


@app.get("/security/incidents")
def security_incidents_history():
    return {
        "status": "success",
        "incidents": get_incidents(),
    }


@app.get("/incidents/correlate")
def correlate_security_events(db: Session = Depends(get_db)):
    """Analyze recent stored security logs for correlated attack chains."""
    logs = (
        db.query(SecurityLog)
        .order_by(SecurityLog.id.desc())
        .limit(200)
        .all()
    )

    events = []
    for log in reversed(logs):
        raw_type = (log.event_type or "").lower()
        status = (log.status or "").lower()

        if "failed_login" in raw_type or ("login" in raw_type and status == "failed"):
            event_type = "failed_login"
        elif "successful_login" in raw_type or ("login" in raw_type and status in {"success", "successful"}):
            event_type = "successful_login"
        elif "privilege" in raw_type or "role" in raw_type:
            event_type = "privilege_change"
        elif "sensitive_access" in raw_type or "sensitive resource" in raw_type:
            event_type = "sensitive_access"
        else:
            event_type = "unknown"

        events.append({
            "timestamp": log.timestamp,
            "event_type": event_type,
            "username": log.username,
            "ip_address": log.ip_address,
            "severity": log.severity or "unknown",
        })

    result = correlate_attack_chain(events)
    return {
        "status": "success",
        "total_logs_analyzed": len(logs),
        "incident": result,
    }


@app.get("/security/threat-intel")
def threat_intel_summary(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(25).all()
    enriched = []
    for log in logs:
        event_payload = {
            "username": log.username,
            "ip_address": log.ip_address,
            "event_type": log.event_type,
            "status": log.status,
            "severity": log.severity,
            "details": f"{log.event_type} {log.status}",
        }
        enriched.append({
            "id": log.id,
            "username": log.username,
            "ip_address": log.ip_address,
            "event_type": log.event_type,
            "status": log.status,
            "severity": log.severity,
            "intel": enrich_security_event(event_payload),
        })
    return enriched


@app.post("/security/response/recommendations")
def response_recommendations(payload: dict, db: Session = Depends(get_db)):
    alert_id = payload.get("alert_id")
    if alert_id is None:
        raise HTTPException(status_code=400, detail="alert_id is required")

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    recommendations = build_response_recommendations(
        threat_type=alert.threat_type,
        threat_level=alert.threat_level,
        risk_score=alert.risk_score,
    )

    return {
        "alert_id": alert.id,
        "incident_id": f"INC-{alert.id:04d}",
        "risk_score": alert.risk_score,
        "threat_type": alert.threat_type,
        "threat_level": alert.threat_level,
        "recommendations": recommendations["recommendations"],
        "actions": recommendations["actions"],
    }


@app.post("/security/response/execute")
def execute_response_action(payload: dict, db: Session = Depends(get_db)):
    alert_id = payload.get("alert_id")
    action_id = payload.get("action_id")
    approved = bool(payload.get("approved", False))
    approved_by = payload.get("approved_by") or "system"
    details = payload.get("details")

    if not action_id:
        raise HTTPException(status_code=400, detail="action_id is required")

    alert = None
    if alert_id is not None:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()

    execution = execute_approved_action(
        db=db,
        action_id=action_id,
        alert_id=alert_id,
        approved=approved,
        approved_by=approved_by,
        details=details,
        ip_address=alert.ip_address if alert else payload.get("ip_address"),
    )

    if not execution["result"]["success"]:
        return execution

    if alert is not None:
        alert.status = "investigating"
        db.commit()

    return {
        **execution,
        "incident_id": f"INC-{alert_id:04d}" if alert_id is not None else "INC-0000",
        "action_id": action_id,
        "approved_by": approved_by,
    }


@app.get("/security/threat-analysis")
def threat_analysis(db: Session = Depends(get_db)):
    failed_logs = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .all()
    )

    features = extract_features(failed_logs)
    if not features:
        return {
            "message": "No failed login activity found"
        }

    features_by_ip = {}
    for feature in features:
        features_by_ip[feature["ip_address"]] = feature

    ip_addresses = list(features_by_ip)
    attempts = [features_by_ip[ip]["failed_attempts"] for ip in ip_addresses]
    ml_results = detect_anomalies(attempts)

    analysis = []
    for ip, result in zip(ip_addresses, ml_results):
        feature = features_by_ip[ip]
        threat = classify_threat(
            failed_attempts=feature["failed_attempts"],
            unique_users=feature["unique_users"],
            event_frequency=feature["event_frequency"],
            severity_score=feature["severity_score"],
            ml_anomaly=result["anomaly"]
        )
        alert = generate_alert(threat)

        if result["anomaly"]:
            risk_score = 90
            risk_level = "HIGH"
            recommendation = (
                "Investigate this IP immediately and "
                "review related security logs."
            )
        elif feature["failed_attempts"] >= 3:
            risk_score = 60
            risk_level = "MEDIUM"
            recommendation = "Monitor this IP for further suspicious activity."
        else:
            risk_score = 20
            risk_level = "LOW"
            recommendation = "Continue normal security monitoring."

        if alert["alert"]:
            existing_alert = (
                db.query(SecurityAlert)
                .filter(
                    SecurityAlert.ip_address == ip,
                    SecurityAlert.threat_type == threat["threat_type"],
                    SecurityAlert.threat_level == threat["threat_level"]
                )
                .first()
            )

            if not existing_alert:
                db.add(SecurityAlert(
                    ip_address=ip,
                    username=feature["username"],
                    threat_type=threat["threat_type"],
                    threat_level=threat["threat_level"],
                    confidence=threat["confidence"],
                    risk_score=risk_score,
                    ml_anomaly=bool(result["anomaly"]),
                    recommended_action=alert["recommended_action"]
                ))
                db.commit()

        analysis.append({
            **feature,
            "ml_anomaly": bool(result["anomaly"]),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threat_type": threat["threat_type"],
            "threat_level": threat["threat_level"],
            "confidence": threat["confidence"],
            "alert": alert["alert"],
            "recommended_action": alert["recommended_action"],
            "recommendation": recommendation
        })

    return analysis


@app.post("/security/ml/train")
def train_security_model():
    from backend.app.ml.training import train_model

    return train_model()


@app.post("/security/ml/predict")
def predict_security_model(payload: dict):
    from backend.app.ml.training import predict_security_event

    features = payload.get("features")
    if not isinstance(features, list) or len(features) != 5:
        raise HTTPException(status_code=400, detail="features must contain exactly 5 values")
    try:
        prediction = predict_security_event(features)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "success", "prediction": prediction}


@app.get("/security/ml/evaluation")
def ml_evaluation():
    from backend.app.ml.evaluation import evaluate_predictions

    actual = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
    predicted = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
    metrics = evaluate_predictions(actual, predicted)
    return {"status": "success", "metrics": metrics}


@app.get("/security/analytics")
def security_analytics(db: Session = Depends(get_db)):
    logs = (
        db.query(SecurityLog)
        .order_by(SecurityLog.id.desc())
        .limit(1000)
        .all()
    )
    alerts = db.query(SecurityAlert).all()
    risk_by_ip = {}
    for alert in alerts:
        if alert.risk_score is not None:
            risk_by_ip[alert.ip_address] = max(
                risk_by_ip.get(alert.ip_address, 0),
                float(alert.risk_score),
            )

    events = []
    for log in logs:
        risk_score = risk_by_ip.get(log.ip_address, 0)
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        events.append({
            "event_type": log.event_type,
            "severity": log.severity or "unknown",
            "risk_score": risk_score,
            "risk_level": risk_level,
        })

    return {
        "status": "success",
        "analytics": generate_security_analytics(events),
    }


@app.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):

    total_logs = db.query(SecurityLog).count()

    failed_logins = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type.in_(["login", "failed_login"]),
            SecurityLog.status == "failed"
        )
        .count()
    )

    successful_logins = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.event_type == "login",
            SecurityLog.status == "success"
        )
        .count()
    )

    high_risk_alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.threat_level.in_(["HIGH", "high"])
        )
        .count()
    )

    medium_risk_alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.threat_level.in_(["MEDIUM", "medium"])
        )
        .count()
    )

    total_alerts = db.query(SecurityAlert).count()

    ml_anomalies = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.ml_anomaly == True)
        .count()
    )

    active_alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.status != "resolved")
        .order_by(SecurityAlert.risk_score.desc())
        .all()
    )

    risk_assessment = max(
        (
            _calculate_explainable_risk(
                db=db,
                username=alert.username,
                ip_address=alert.ip_address,
                severity=alert.threat_level,
                ml_anomaly=bool(alert.ml_anomaly),
            )
            for alert in active_alerts
        ),
        key=lambda item: item["risk_score"],
        default=calculate_composite_risk_score(),
    )
    if active_alerts:
        risk_alert = max(
            active_alerts,
            key=lambda alert: _calculate_explainable_risk(
                db=db,
                username=alert.username,
                ip_address=alert.ip_address,
                severity=alert.threat_level,
                ml_anomaly=bool(alert.ml_anomaly),
            )["risk_score"],
        )
    else:
        risk_alert = None

    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "total_alerts": total_alerts,
        "high_risk_alerts": high_risk_alerts,
        "medium_risk_alerts": medium_risk_alerts,
        "ml_anomalies": ml_anomalies,
        "risk_score": risk_assessment["risk_score"],
        "risk_level": risk_assessment["risk_level"],
        "risk_breakdown": risk_assessment["breakdown"],
        "risk_alert": {
            "id": risk_alert.id,
            "threat_type": risk_alert.threat_type,
            "username": risk_alert.username,
            "ip_address": risk_alert.ip_address,
        } if risk_alert else None,
    }


@app.get("/alerts/{alert_id}", response_model=SecurityAlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):

    alert = db.query(SecurityAlert).filter(
        SecurityAlert.id == alert_id
    ).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    return alert
@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(
        SecurityAlert.id == alert_id
    ).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    db.delete(alert)
    db.commit()

    return {
        "message": "Security alert deleted successfully",
        "alert_id": alert_id
    }
@app.patch("/alerts/{alert_id}", response_model=SecurityAlertResponse)
def update_alert(
    alert_id: int,
    alert_update: SecurityAlertUpdate,
    db: Session = Depends(get_db)
):
    alert = db.query(SecurityAlert).filter(
        SecurityAlert.id == alert_id
    ).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    alert.status = alert_update.status

    db.commit()
    db.refresh(alert)

    return alert
@app.get("/alerts", response_model=list[SecurityAlertResponse])
def get_alerts(
    threat_level: str | None = None,
    status: str | None = None,
    ip_address: str | None = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(SecurityAlert)

    if threat_level:
        query = query.filter(SecurityAlert.threat_level == threat_level)

    if status:
        query = query.filter(SecurityAlert.status == status)

    if ip_address:
        query = query.filter(SecurityAlert.ip_address == ip_address)

    return query.all()
@app.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):

    total_alerts = db.query(SecurityAlert).count()

    high_threats = db.query(SecurityAlert).filter(
        func.lower(SecurityAlert.threat_level) == "high"
    ).count()

    critical_threats = db.query(SecurityAlert).filter(
        func.lower(SecurityAlert.threat_level) == "critical"
    ).count()

    open_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.status == "open"
    ).count()

    resolved_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.status == "resolved"
    ).count()

    return {
        "total_alerts": total_alerts,
        "high_threats": high_threats,
        "critical_threats": critical_threats,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts
    }
@app.put("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    alert_update: SecurityAlertUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    alert = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.id == alert_id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    allowed_statuses = [
        "open",
        "investigating",
        "resolved"
    ]

    if alert_update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    old_status = alert.status
    alert.status = alert_update.status

    history = AlertStatusHistory(
        alert_id=alert.id,
        old_status=old_status,
        new_status=alert_update.status
    )

    db.add(history)
    db.commit()
    db.refresh(alert)

    return {
        "message": "Alert status updated successfully",
        "alert_id": alert.id,
        "old_status": old_status,
        "status": alert.status
    }
@app.get("/alerts/{alert_id}/history")
def get_alert_history(
    alert_id: int,
    db: Session = Depends(get_db)
):
    # Check whether alert exists
    alert = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.id == alert_id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    history = (
        db.query(AlertStatusHistory)
        .filter(AlertStatusHistory.alert_id == alert_id)
        .order_by(AlertStatusHistory.changed_at.asc())
        .all()
    )

    return [
        {
            "id": item.id,
            "alert_id": item.alert_id,
            "old_status": item.old_status,
            "new_status": item.new_status,
            "changed_at": item.changed_at
        }
        for item in history

    ]
@app.post("/register", response_model=UserResponse)
def register_user(
    user: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"

    if is_rate_limited(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later."
        )

    if not user.username.strip():
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty"
        )

    if len(user.username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters long"
        )

    if len(user.username) > 30:
        raise HTTPException(
            status_code=400,
            detail="Username must not exceed 30 characters"
        )

    if not re.match(r"^[a-zA-Z0-9_]+$", user.username):
        raise HTTPException(
            status_code=400,
            detail="Username can contain only letters, numbers and underscore"
        )

    password = user.password

    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )

    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one uppercase letter"
        )

    if not re.search(r"[a-z]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one lowercase letter"
        )

    if not re.search(r"[0-9]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one number"
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one special character"
        )

    existing_username = (
        db.query(User)
        .filter(User.username == user.username)
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    existing_email = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    hashed_password = hash_password(user.password)

    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role="analyst"
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        ) from exc

    return new_user
@app.post("/login", response_model=Token)
def login_user(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"

    if is_ip_blocked(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
        )

    user = (
        db.query(User)
        .filter(User.username == form_data.username)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )

    if not verify_password(
        form_data.password,
        user.hashed_password
    ):
        record_failed_attempt(client_ip)

        failed_log = SecurityLog(
            username=user.username,
            ip_address=client_ip,
            event_type="login",
            status="failed",
            severity="medium",
        )
        db.add(failed_log)
        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    clear_failed_attempts(client_ip)

    successful_log = SecurityLog(
        username=user.username,
        ip_address=client_ip,
        event_type="login",
        status="success",
        severity="low",
    )
    db.add(successful_log)
    db.commit()

    access_token = create_access_token(user.username, role=user.role)
    refresh_token = create_refresh_token({
        "sub": user.username,
        "role": user.role,
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh")
def refresh_access_token(
    refresh_token: str,
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(
            refresh_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        if payload.get("token_type") != "refresh":
            raise HTTPException(
                status_code=401,
                detail="Invalid refresh token",
            )

        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=401,
                detail="Invalid refresh token",
            )

        user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="User account is inactive",
            )

        new_access_token = create_access_token(
            username,
            role=payload.get("role"),
        )

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
        }

    except JWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token",
        ) from exc


@app.get("/admin/users")
def get_all_users(
    current_user: dict = Depends(
        require_role("admin")
    ),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()

    return [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
        for user in users
    ]


@app.put("/admin/users/{user_id}/role")
def update_user_role(
    user_id: int,
    role_data: RoleUpdate,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    allowed_roles = {"admin", "analyst"}
    if role_data.role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail="Invalid role. Use admin or analyst.",
        )

    user.role = role_data.role

    audit = AuditLog(
        username=current_user.get("username"),
        action="update_user_role",
        target=f"user_id:{user.id}",
        ip_address=None,
    )

    db.add(audit)
    db.commit()
    db.refresh(user)

    return {
        "message": "User role updated successfully",
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
    }
@app.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Prevent admin from deleting their own account
    if user.username == current_user.get("username"):
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own admin account"
        )

    audit = AuditLog(
        username=current_user.get("username"),
        action="delete_user",
        target=f"user_id:{user.id}",
        ip_address=None,
    )

    db.add(audit)
    db.delete(user)
    db.commit()

    return {
        "message": "User deleted successfully",
        "user_id": user_id
    }
@app.put("/admin/users/{user_id}")
def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if user_data.username is not None:
        user.username = user_data.username

    if user_data.email is not None:
        user.email = user_data.email

    db.commit()
    db.refresh(user)

    return {
        "message": "User updated successfully",
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    }
from backend.app.schemas.user import (
    RoleUpdate,
    Token,
    UserCreate,
    UserResponse,
    UserUpdate,
    AdminPasswordUpdate,
)
@app.put("/admin/users/{user_id}/password")
def update_user_password(
    user_id: int,
    password_data: AdminPasswordUpdate,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if len(password_data.new_password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )

    user.hashed_password = hash_password(
        password_data.new_password
    )

    audit = AuditLog(
        username=current_user.get("username"),
        action="change_user_password",
        target=f"user_id:{user.id}",
        ip_address=None,
    )

    db.add(audit)
    db.commit()

    return {
        "message": "User password updated successfully",
        "user_id": user.id
    }
@app.put("/admin/users/{user_id}/status")
def update_user_status(
    user_id: int,
    is_active: bool,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if user.username == current_user.get("username") and not is_active:
        raise HTTPException(
            status_code=400,
            detail="You cannot deactivate your own admin account"
        )

    old_status = user.is_active
    user.is_active = is_active

    action = "activate_user" if is_active else "deactivate_user"

    audit = AuditLog(
        username=current_user.get("username"),
        action=action,
        target=f"user_id:{user.id}",
        ip_address=None,
    )

    db.add(audit)
    db.commit()
    db.refresh(user)

    return {
        "message": "User status updated successfully",
        "user_id": user.id,
        "username": user.username,
        "old_status": old_status,
        "is_active": user.is_active
    }
@app.get("/admin/security/login-status")
def login_security_status(
    ip_address: str,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    failed_count = (
        db.query(SecurityLog)
        .filter(
            SecurityLog.ip_address == ip_address,
            SecurityLog.event_type == "login",
            SecurityLog.status == "failed"
        )
        .count()
    )

    if failed_count >= 5:
        risk_level = "HIGH"
    elif failed_count >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "ip_address": ip_address,
        "failed_login_attempts": failed_count,
        "risk_level": risk_level
    }


@app.get("/admin/audit-logs")
def get_audit_logs(
    username: str | None = None,
    action: str | None = None,
    page: int = 1,
    limit: int = 20,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if page < 1:
        raise HTTPException(
            status_code=400,
            detail="Page must be greater than 0"
        )

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100"
        )

    query = db.query(AuditLog)

    if username:
        query = query.filter(AuditLog.username == username)

    if action:
        query = query.filter(AuditLog.action == action)

    total = query.count()
    offset = (page - 1) * limit
    logs = (
        query
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    total_pages = (total + limit - 1) // limit

    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "logs": [
            {
                "id": log.id,
                "username": log.username,
                "action": log.action,
                "target": log.target,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp,
            }
            for log in logs
        ]
    }
@app.post("/alerts/test")
def create_test_alert(
    db: Session = Depends(get_db)
):
    test_alert = SecurityAlert(
        ip_address="192.168.1.100",
        username="testuser",
        threat_type="Brute Force Attack",
        threat_level="high",
        confidence=95.0,
        risk_score=90.0,
        ml_anomaly=True,
        recommended_action="Block IP address and investigate login attempts",
        status="open"
    )

    db.add(test_alert)
    db.commit()
    db.refresh(test_alert)

    return {
        "message": "Test threat alert created successfully",
        "alert": {
            "id": test_alert.id,
            "ip_address": test_alert.ip_address,
            "username": test_alert.username,
            "threat_type": test_alert.threat_type,
            "threat_level": test_alert.threat_level,
            "confidence": test_alert.confidence,
            "risk_score": test_alert.risk_score,
            "ml_anomaly": test_alert.ml_anomaly,
            "recommended_action": test_alert.recommended_action,
            "status": test_alert.status
        }
    }