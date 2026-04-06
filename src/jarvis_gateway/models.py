from pydantic import BaseModel, Field

__all__ = ["LoginRequest", "LoginResponse"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str


class TokenValidationResponse(BaseModel):
    user_id: str
    active: bool = True


class SignupRequest(BaseModel):
    email: str = Field(min_length=1)
    name: str | None = Field(default=None, min_length=1)
    password: str = Field(min_length=1)


class SignupResponse(BaseModel):
    access_token: str
    user_id: str
    email: str
    name: str | None = None


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=1)


class TenantResponse(BaseModel):
    id: str
    name: str
    created_at: str


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class UserResponse(BaseModel):
    id: str
    username: str
    created_at: str


class SessionCreateRequest(BaseModel):
    title: str = Field(default="new session")


class SessionResponse(BaseModel):
    id: str
    user_id: str
    title: str
    status: str
    created_at: str
    updated_at: str


class SessionTerminateResponse(BaseModel):
    id: str
    status: str
    updated_at: str


class AuditLogItem(BaseModel):
    id: int
    action: str
    resource: str
    status: str
    detail: str
    request_id: str
    actor_user_id: str
    created_at: str
