from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from datetime import datetime

from backend.app.database import Base


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    ip_address = Column(String, nullable=False)
    username = Column(String, nullable=True)

    threat_type = Column(String, nullable=False)
    threat_level = Column(String, nullable=False)

    confidence = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=False)

    ml_anomaly = Column(Boolean, default=False)

    recommended_action = Column(String, nullable=False)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
    status = Column(String, default="open")
