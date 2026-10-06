from pydantic import BaseModel


class SecurityLogCreate(BaseModel):
    username: str
    ip_address: str
    event_type: str
    status: str
    severity: str = "low"


class SecurityLogResponse(SecurityLogCreate):
    id: int
    timestamp: str
