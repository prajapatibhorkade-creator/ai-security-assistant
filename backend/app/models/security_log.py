from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from backend.app.database import Base


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    username = Column(String, nullable=False)

    ip_address = Column(String, nullable=False)

    event_type = Column(String, nullable=False)

    status = Column(String, nullable=False)

    severity = Column(String, default="low")