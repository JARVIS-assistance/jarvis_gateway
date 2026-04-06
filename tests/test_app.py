import os
from pathlib import Path

from fastapi.testclient import TestClient

from jarvis_gateway.app import create_app


def make_client(tmp_path: Path, rate_limit: int = 50) -> TestClient:
    os.environ["JARVIS_GATEWAY_RATE_LIMIT"] = str(rate_limit)
    os.environ["JARVIS_GATEWAY_RATE_WINDOW"] = "60"
    app = create_app(str(tmp_path / "gateway.db"))
    return TestClient(app)


def login_admin(client: TestClient) -> str:
    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "x-client-id": "test-client"}


def test_health(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "jarvis-gateway"


def test_auth_and_session_lifecycle(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        token = login_admin(client)
        validated = client.get("/auth/validate", headers=auth_headers(token))
        assert validated.status_code == 200
        assert validated.json()["active"] is True
        created = client.post("/sessions", json={"title": "demo"}, headers=auth_headers(token))
        assert created.status_code == 200
        session_id = created.json()["id"]

        fetched = client.get(f"/sessions/{session_id}", headers=auth_headers(token))
        assert fetched.status_code == 200

        terminated = client.post(f"/sessions/{session_id}/terminate", headers=auth_headers(token))
        assert terminated.status_code == 200
        assert terminated.json()["status"] == "terminated"


def test_signup_creates_user_and_token(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        response = client.post(
            "/auth/signup",
            json={
                "email": "alice@example.com",
                "name": "Alice",
                "password": "pw1234",
            },
            headers={"x-client-id": "signup-client"},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["email"] == "alice@example.com"
        assert payload["name"] == "Alice"
        assert "role" not in payload

        headers = auth_headers(payload["access_token"])
        validated = client.get("/auth/validate", headers=headers)
        assert validated.status_code == 200
        assert "role" not in validated.json()
        assert "tenant_id" not in validated.json()


def test_create_user_without_role_field(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        token = login_admin(client)
        created = client.post(
            "/users",
            json={
                "username": "member1",
                "password": "pw1234",
            },
            headers=auth_headers(token),
        )

    assert created.status_code == 200
    payload = created.json()
    assert payload["username"] == "member1"
    assert "role" not in payload
    assert "tenant_id" not in payload


def test_signup_rejects_duplicate_email(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        first = client.post(
            "/auth/signup",
            json={
                "email": "alice@example.com",
                "name": "Alice",
                "password": "pw1234",
            },
            headers={"x-client-id": "signup-client-1"},
        )
        second = client.post(
            "/auth/signup",
            json={
                "email": "alice@example.com",
                "name": "Alice Two",
                "password": "pw5678",
            },
            headers={"x-client-id": "signup-client-2"},
        )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error_code"] == "USER_EXISTS"


def test_rate_limit_block(tmp_path: Path) -> None:
    with make_client(tmp_path, rate_limit=2) as client:
        headers = {"x-client-id": "same-client"}
        first = client.post("/auth/login", json={"username": "admin", "password": "admin123"}, headers=headers)
        second = client.post("/auth/login", json={"username": "admin", "password": "admin123"}, headers=headers)
        third = client.post("/auth/login", json={"username": "admin", "password": "admin123"}, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["error_code"] == "RATE_LIMIT_EXCEEDED"


def test_audit_logs(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        token = login_admin(client)
        _ = client.post("/sessions", json={"title": "audit-demo"}, headers=auth_headers(token))
        logs = client.get("/audit-logs", headers=auth_headers(token))

    assert logs.status_code == 200
    payload = logs.json()
    assert len(payload) >= 2
    actions = {item["action"] for item in payload}
    assert "auth.login" in actions
    assert "session.create" in actions
