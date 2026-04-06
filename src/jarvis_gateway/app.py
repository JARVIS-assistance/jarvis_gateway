from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from jarvis_contracts import ErrorResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import (
    Principal,
    TokenStore,
    extract_authorization,
    get_principal,
)
from .db import (
    DBClient,
    DEFAULT_TENANT_ID,
    add_audit_log,
    connect,
    create_session,
    create_tenant,
    create_user_admin,
    find_user_by_credentials,
    get_session,
    get_tenant,
    get_user,
    init_db,
    list_audit_logs,
    register_user,
    seed_admin,
    terminate_session,
)
from .models import (
    AuditLogItem,
    LoginRequest,
    LoginResponse,
    SessionCreateRequest,
    SessionResponse,
    SessionTerminateResponse,
    SignupRequest,
    SignupResponse,
    TenantCreateRequest,
    TenantResponse,
    TokenValidationResponse,
    UserCreateRequest,
    UserResponse,
)
from .rate_limit import RateLimitMiddleware, limiter_from_env


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("x-request-id") or str(uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response


def create_error(status_code: int, code: str, message: str, request: Request, details: dict | None = None):
    err = ErrorResponse(
        error_code=code,
        message=message,
        request_id=getattr(request.state, "request_id", None),
        details=details or {},
    )
    return JSONResponse(status_code=status_code, content=err.model_dump())


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="jarvis-gateway", version="0.1.0")
    app.state.token_store = TokenStore()
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=limiter_from_env())

    @app.on_event("startup")
    def startup() -> None:
        app.state.db = connect(db_path)
        init_db(app.state.db)
        seed_admin(app.state.db)

    @app.on_event("shutdown")
    def shutdown() -> None:
        db: DBClient | None = getattr(app.state, "db", None)
        if db is not None:
            db.conn.close()

    def principal_from_header(
        authorization: str | None = Depends(extract_authorization),
    ) -> Principal:
        try:
            return get_principal(app.state.token_store, authorization)
        except HTTPException as exc:
            raise exc

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return create_error(exc.status_code, "HTTP_ERROR", str(exc.detail), request)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "jarvis-gateway"}

    @app.post("/auth/login", response_model=LoginResponse)
    def login(body: LoginRequest, request: Request):
        user = find_user_by_credentials(app.state.db, body.username, body.password)
        if user is None:
            return create_error(401, "AUTH_INVALID", "invalid credentials", request)

        token = app.state.token_store.issue(user["id"], user["tenant_id"])
        add_audit_log(
            app.state.db,
            request.state.request_id,
            user["id"],
            user["tenant_id"],
            "auth.login",
            "token",
            "success",
            "login succeeded",
        )
        return LoginResponse(
            access_token=token,
            user_id=user["id"],
        )

    @app.post("/auth/signup", response_model=SignupResponse)
    def signup(body: SignupRequest, request: Request):
        try:
            user = register_user(app.state.db, body.email, body.name, body.password)
        except ValueError:
            return create_error(409, "USER_EXISTS", "user already exists", request)

        token = app.state.token_store.issue(user["id"], "tenant-default")
        add_audit_log(
            app.state.db,
            request.state.request_id,
            user["id"],
            "tenant-default",
            "auth.signup",
            user["id"],
            "success",
            "signup succeeded",
        )
        return SignupResponse(
            access_token=token,
            user_id=user["id"],
            email=user["email"],
            name=user["name"],
        )

    @app.post("/auth/logout")
    def logout(request: Request, principal: Principal = Depends(principal_from_header)):
        app.state.token_store.revoke(principal.token)
        add_audit_log(
            app.state.db,
            request.state.request_id,
            principal.user_id,
            principal.tenant_id,
            "auth.logout",
            "token",
            "success",
            "logout succeeded",
        )
        return {"ok": True}

    @app.get("/auth/validate", response_model=TokenValidationResponse)
    def validate_token(principal: Principal = Depends(principal_from_header)):
        return TokenValidationResponse(
            user_id=principal.user_id,
            active=True,
        )

    @app.post("/tenants", response_model=TenantResponse)
    def create_tenant_endpoint(
        body: TenantCreateRequest,
        request: Request,
        principal: Principal = Depends(principal_from_header),
    ):
        tenant = create_tenant(app.state.db, body.name)
        add_audit_log(
            app.state.db,
            request.state.request_id,
            principal.user_id,
            principal.tenant_id,
            "tenant.create",
            tenant["id"],
            "success",
            "tenant created",
        )
        return tenant

    @app.get("/tenants/{tenant_id}", response_model=TenantResponse)
    def get_tenant_endpoint(tenant_id: str, principal: Principal = Depends(principal_from_header)):
        if principal.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="forbidden")
        tenant = get_tenant(app.state.db, tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        return tenant

    @app.post("/users", response_model=UserResponse)
    def create_user_endpoint(
        body: UserCreateRequest,
        request: Request,
        principal: Principal = Depends(principal_from_header),
    ):
        if principal.tenant_id != DEFAULT_TENANT_ID:
            raise HTTPException(status_code=403, detail="forbidden")
        tenant = get_tenant(app.state.db, DEFAULT_TENANT_ID)
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        try:
            user = create_user_admin(app.state.db, DEFAULT_TENANT_ID, body.username, body.password)
        except ValueError:
            return create_error(409, "USER_EXISTS", "user already exists", request)
        add_audit_log(
            app.state.db,
            request.state.request_id,
            principal.user_id,
            principal.tenant_id,
            "user.create",
            user["id"],
            "success",
            "user created",
        )
        return user

    @app.get("/users/{user_id}", response_model=UserResponse)
    def get_user_endpoint(user_id: str, principal: Principal = Depends(principal_from_header)):
        user = get_user(app.state.db, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")
        if user["tenant_id"] != principal.tenant_id:
            raise HTTPException(status_code=403, detail="forbidden")
        if user["id"] != principal.user_id:
            raise HTTPException(status_code=403, detail="forbidden")
        return user

    @app.post("/sessions", response_model=SessionResponse)
    def create_session_endpoint(
        body: SessionCreateRequest,
        request: Request,
        principal: Principal = Depends(principal_from_header),
    ):
        session = create_session(app.state.db, principal.tenant_id, principal.user_id, body.title)
        add_audit_log(
            app.state.db,
            request.state.request_id,
            principal.user_id,
            principal.tenant_id,
            "session.create",
            session["id"],
            "success",
            "session created",
        )
        return session

    @app.get("/sessions/{session_id}", response_model=SessionResponse)
    def get_session_endpoint(session_id: str, principal: Principal = Depends(principal_from_header)):
        session = get_session(app.state.db, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if session["tenant_id"] != principal.tenant_id:
            raise HTTPException(status_code=403, detail="forbidden")
        if session["user_id"] != principal.user_id:
            raise HTTPException(status_code=403, detail="forbidden")
        return session

    @app.post("/sessions/{session_id}/terminate", response_model=SessionTerminateResponse)
    def terminate_session_endpoint(
        session_id: str,
        request: Request,
        principal: Principal = Depends(principal_from_header),
    ):
        session = get_session(app.state.db, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if session["tenant_id"] != principal.tenant_id:
            raise HTTPException(status_code=403, detail="forbidden")
        if session["user_id"] != principal.user_id:
            raise HTTPException(status_code=403, detail="forbidden")

        result = terminate_session(app.state.db, session_id)
        if result is None:
            raise HTTPException(status_code=404, detail="session not found")

        add_audit_log(
            app.state.db,
            request.state.request_id,
            principal.user_id,
            principal.tenant_id,
            "session.terminate",
            session_id,
            "success",
            "session terminated",
        )
        return result

    @app.get("/audit-logs", response_model=list[AuditLogItem])
    def get_audit_logs(
        limit: int = 20,
        principal: Principal = Depends(principal_from_header),
    ):
        return list_audit_logs(app.state.db, principal.tenant_id, principal.user_id, min(limit, 100))

    return app


app = create_app()
