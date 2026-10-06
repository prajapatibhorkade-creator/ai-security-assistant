from pydantic import BaseModel, ConfigDict, EmailStr


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str | None = None
    role: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RoleUpdate(BaseModel):
    role: str


class UserUpdate(BaseModel):
    username: str | None = None
    email: EmailStr | None = None


class AdminPasswordUpdate(BaseModel):
    new_password: str