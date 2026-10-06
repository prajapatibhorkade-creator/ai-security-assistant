from pydantic import BaseModel


class SecurityAlertResponse(BaseModel):
    id: int
    ip_address: str
    username: str
    threat_type: str
    threat_level: str
    confidence: float
    risk_score: float
    ml_anomaly: bool
    recommended_action: str
    status: str = "open"

    class Config:
        from_attributes = True


class SecurityAlertUpdate(BaseModel):
    status: str