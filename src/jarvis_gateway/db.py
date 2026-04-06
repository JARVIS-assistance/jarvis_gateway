from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4


REPO_ROOT = Path(__file__).resolve().parents[3]
CORE_SRC = REPO_ROOT / "jarvis_core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from core.db.db import (  # noqa: E402
    DBClient,
    connect as connect_core,
    create_user,
    find_user_by_email,
    find_user_by_id,
    init_db as init_core_db,
)
from core.db.db_operations.common import now_iso  # noqa: E402


DEFAULT_TENANT_ID = "tenant-default"
DEFAULT_TENANT_NAME = "Default Tenant"
DEFAULT_ADMIN_EMAIL = "admin@jarvis.local"


# ── password hashing (gateway 전용) ────────────────────────


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt_bytes = salt or secrets.token_bytes(16)
    try:
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=2**14, r=8, p=1, dklen=32)
    except AttributeError:
        # Python < 3.12 or OpenSSL without scrypt — fallback to pbkdf2
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations=100_000, dklen=32)
    return f"{base64.urlsafe_b64encode(salt_bytes).decode()}${base64.urlsafe_b64encode(dk).decode()}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        salt_b64, digest_b64 = password_hash.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
    except Exception:
        return False
    try:
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    except AttributeError:
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=100_000, dklen=32)
    return hmac.compare_digest(actual, expected)


# ── helpers ─────────────────────────────────────────────────


def _placeholder(db: DBClient) -> str:
    return "%s" if db.backend == "postgres" else "?"


def _username_to_email(username: str) -> str:
    normalized = username.strip()
    if "@" in normalized:
        return normalized.lower()
    return f"{normalized.lower()}@jarvis.local"


def _email_to_username(email: str) -> str:
    return email.split("@", 1)[0]


def _fetchone_as_dict(cursor: Any) -> dict[str, Any] | None:
    row = cursor.fetchone()
    if row is None:
        return None
    if hasattr(row, "keys"):
        return dict(row)
    return dict(zip([column[0] for column in cursor.description], row))


# ── DB init ─────────────────────────────────────────────────


def _ensure_gateway_tables(db: DBClient) -> None:
    if db.backend == "postgres":
        db.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_credentials (
                user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                password_hash text NOT NULL,
                is_active boolean NOT NULL DEFAULT true,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        db.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_tenants (
                id text PRIMARY KEY,
                name text NOT NULL,
                created_at timestamptz NOT NULL
            )
            """
        )
        db.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_user_tenants (
                user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                tenant_id text NOT NULL REFERENCES gateway_tenants(id) ON DELETE CASCADE,
                created_at timestamptz NOT NULL
            )
            """
        )
        db.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_chat_meta (
                chat_id uuid PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE,
                tenant_id text NOT NULL REFERENCES gateway_tenants(id) ON DELETE CASCADE,
                title text NOT NULL,
                created_at timestamptz NOT NULL,
                updated_at timestamptz NOT NULL
            )
            """
        )
        db.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_audit_logs (
                id bigserial PRIMARY KEY,
                request_id text NOT NULL,
                actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tenant_id text NOT NULL REFERENCES gateway_tenants(id) ON DELETE CASCADE,
                action text NOT NULL,
                resource text NOT NULL,
                status text NOT NULL,
                detail text NOT NULL,
                created_at timestamptz NOT NULL
            )
            """
        )
    else:
        db.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS gateway_credentials (
                user_id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS gateway_tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS gateway_user_tenants (
                user_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(tenant_id) REFERENCES gateway_tenants(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS gateway_chat_meta (
                chat_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
                FOREIGN KEY(tenant_id) REFERENCES gateway_tenants(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS gateway_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                actor_user_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(tenant_id) REFERENCES gateway_tenants(id) ON DELETE CASCADE
            );
            """
        )
    db.conn.commit()


def _ensure_default_tenant(db: DBClient) -> None:
    placeholder = _placeholder(db)
    query = f"SELECT id, name, created_at FROM gateway_tenants WHERE id = {placeholder}"
    if _fetchone_as_dict(db.conn.execute(query, (DEFAULT_TENANT_ID,))) is not None:
        return
    now = now_iso()
    insert = (
        "INSERT INTO gateway_tenants (id, name, created_at) VALUES "
        f"({placeholder}, {placeholder}, {placeholder})"
    )
    db.conn.execute(insert, (DEFAULT_TENANT_ID, DEFAULT_TENANT_NAME, now))
    db.conn.commit()


def _ensure_user_tenant(db: DBClient, user_id: str, tenant_id: str = DEFAULT_TENANT_ID) -> None:
    placeholder = _placeholder(db)
    lookup = f"SELECT user_id FROM gateway_user_tenants WHERE user_id = {placeholder}"
    if _fetchone_as_dict(db.conn.execute(lookup, (user_id,))) is not None:
        return
    now = now_iso()
    insert = (
        "INSERT INTO gateway_user_tenants (user_id, tenant_id, created_at) VALUES "
        f"({placeholder}, {placeholder}, {placeholder})"
    )
    db.conn.execute(insert, (user_id, tenant_id, now))
    db.conn.commit()


def _store_credentials(db: DBClient, user_id: str, password: str) -> None:
    """gateway_credentials 테이블에 비밀번호 해시 저장."""
    password_hash = _hash_password(password)
    now = now_iso()
    placeholder = _placeholder(db)
    is_active = True if db.backend == "postgres" else 1
    db.conn.execute(
        f"""
        INSERT INTO gateway_credentials (user_id, password_hash, is_active, created_at, updated_at)
        VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
        """,
        (user_id, password_hash, is_active, now, now),
    )
    db.conn.commit()


def _get_credentials(db: DBClient, user_id: str) -> dict[str, Any] | None:
    """gateway_credentials에서 인증 정보 조회."""
    placeholder = _placeholder(db)
    cursor = db.conn.execute(
        f"SELECT password_hash, is_active FROM gateway_credentials WHERE user_id = {placeholder}",
        (user_id,),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    return {
        "password_hash": row[0],
        "is_active": bool(row[1]),
    }


# ── public API ──────────────────────────────────────────────


def connect(db_path: str | None = None) -> DBClient:
    return connect_core(db_path)


def init_db(db: DBClient) -> None:
    init_core_db(db)
    _ensure_gateway_tables(db)
    _ensure_default_tenant(db)


def seed_admin(db: DBClient) -> None:
    _ensure_default_tenant(db)
    user = find_user_by_email(db, DEFAULT_ADMIN_EMAIL)
    if user is None:
        created = create_user(db, email=DEFAULT_ADMIN_EMAIL, name="Admin")
        user_id = created["id"]
        _store_credentials(db, user_id, "admin123")
    else:
        user_id = user["id"]
        # credentials가 없으면 추가
        if _get_credentials(db, user_id) is None:
            _store_credentials(db, user_id, "admin123")
    _ensure_user_tenant(db, user_id, DEFAULT_TENANT_ID)


# ── tenant ──────────────────────────────────────────────────


def create_tenant(db: DBClient, name: str) -> dict[str, Any]:
    tenant_id = f"tenant-{uuid4()}"
    created_at = now_iso()
    placeholder = _placeholder(db)
    query = (
        "INSERT INTO gateway_tenants (id, name, created_at) VALUES "
        f"({placeholder}, {placeholder}, {placeholder})"
    )
    db.conn.execute(query, (tenant_id, name, created_at))
    db.conn.commit()
    return {"id": tenant_id, "name": name, "created_at": created_at}


def get_tenant(db: DBClient, tenant_id: str) -> dict[str, Any] | None:
    placeholder = _placeholder(db)
    cursor = db.conn.execute(
        f"SELECT id, name, created_at FROM gateway_tenants WHERE id = {placeholder}",
        (tenant_id,),
    )
    return _fetchone_as_dict(cursor)


# ── user (gateway 레벨) ────────────────────────────────────


def register_user(
    db: DBClient,
    email: str,
    name: str | None,
    password: str,
) -> dict[str, Any]:
    """회원가입: core에 사용자 생성 + gateway에 credentials 저장."""
    normalized_email = email.strip().lower()
    existing = find_user_by_email(db, normalized_email)
    if existing is not None:
        raise ValueError("user already exists")

    created = create_user(
        db,
        email=normalized_email,
        name=name.strip() if name else None,
    )
    _store_credentials(db, created["id"], password)
    _ensure_user_tenant(db, created["id"], DEFAULT_TENANT_ID)
    return {
        "id": created["id"],
        "email": normalized_email,
        "name": created["name"],
    }


def create_user_admin(db: DBClient, tenant_id: str, username: str, password: str) -> dict[str, Any]:
    """테넌트 내 사용자 생성."""
    email = _username_to_email(username)
    existing = find_user_by_email(db, email)
    if existing is not None:
        raise ValueError("user already exists")

    created = create_user(db, email=email, name=username)
    _store_credentials(db, created["id"], password)
    _ensure_user_tenant(db, created["id"], tenant_id)
    return {
        "id": created["id"],
        "tenant_id": tenant_id,
        "username": username,
        "created_at": now_iso(),
    }


def find_user_by_credentials(
    db: DBClient, username: str, password: str
) -> dict[str, Any] | None:
    """로그인: email로 사용자 찾고, gateway_credentials에서 비밀번호 검증."""
    email = _username_to_email(username)
    user = find_user_by_email(db, email)
    if user is None:
        return None
    if user["status"] != "ACTIVE":
        return None

    creds = _get_credentials(db, user["id"])
    if creds is None or not creds["is_active"]:
        return None
    if not _verify_password(password, creds["password_hash"]):
        return None

    _ensure_user_tenant(db, user["id"], DEFAULT_TENANT_ID)
    placeholder = _placeholder(db)
    cursor = db.conn.execute(
        f"SELECT tenant_id FROM gateway_user_tenants WHERE user_id = {placeholder}",
        (user["id"],),
    )
    tenant = _fetchone_as_dict(cursor)
    return {
        "id": user["id"],
        "tenant_id": (tenant or {}).get("tenant_id", DEFAULT_TENANT_ID),
        "username": _email_to_username(user["email"]),
    }


def get_user(db: DBClient, user_id: str) -> dict[str, Any] | None:
    user = find_user_by_id(db, user_id)
    if user is None:
        return None
    placeholder = _placeholder(db)
    cursor = db.conn.execute(
        f"SELECT tenant_id FROM gateway_user_tenants WHERE user_id = {placeholder}",
        (user_id,),
    )
    tenant = _fetchone_as_dict(cursor)
    return {
        "id": str(user["id"]),
        "tenant_id": (tenant or {}).get("tenant_id", DEFAULT_TENANT_ID),
        "username": _email_to_username(str(user["email"])),
        "created_at": str(user.get("created_at", "")),
    }


# ── session ─────────────────────────────────────────────────


def create_session(db: DBClient, tenant_id: str, user_id: str, title: str) -> dict[str, Any]:
    session_id = str(uuid4())
    now = now_iso()
    placeholder = _placeholder(db)

    if db.backend == "postgres":
        db.conn.execute(
            """
            INSERT INTO chats (id, user_id, status, created_at, last_message_at)
            VALUES (%s, %s, 'ACTIVE', %s, %s)
            """,
            (session_id, user_id, now, now),
        )
        db.conn.execute(
            """
            INSERT INTO gateway_chat_meta (chat_id, tenant_id, title, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (session_id, tenant_id, title, now, now),
        )
    else:
        db.conn.execute(
            """
            INSERT INTO chats (id, user_id, status, created_at, last_message_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, user_id, "ACTIVE", now, now),
        )
        db.conn.execute(
            """
            INSERT INTO gateway_chat_meta (chat_id, tenant_id, title, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, tenant_id, title, now, now),
        )
    db.conn.commit()
    return {
        "id": session_id,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "title": title,
        "status": "active",
        "created_at": now,
        "updated_at": now,
    }


def get_session(db: DBClient, session_id: str) -> dict[str, Any] | None:
    placeholder = _placeholder(db)
    cursor = db.conn.execute(
        f"""
        SELECT c.id, c.user_id, c.status, c.created_at, c.last_message_at, gcm.tenant_id, gcm.title
        FROM chats c
        LEFT JOIN gateway_chat_meta gcm ON gcm.chat_id = c.id
        WHERE c.id = {placeholder}
        """,
        (session_id,),
    )
    row = _fetchone_as_dict(cursor)
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "tenant_id": row["tenant_id"] or DEFAULT_TENANT_ID,
        "user_id": str(row["user_id"]),
        "title": row["title"] or "new session",
        "status": "terminated" if row["status"] != "ACTIVE" else "active",
        "created_at": str(row["created_at"]),
        "updated_at": str(row["last_message_at"]),
    }


def terminate_session(db: DBClient, session_id: str) -> dict[str, Any] | None:
    current = get_session(db, session_id)
    if current is None:
        return None

    now = now_iso()
    placeholder = _placeholder(db)
    if db.backend == "postgres":
        db.conn.execute(
            "UPDATE chats SET status = 'ARCHIVED', last_message_at = %s WHERE id = %s",
            (now, session_id),
        )
        db.conn.execute(
            "UPDATE gateway_chat_meta SET updated_at = %s WHERE chat_id = %s",
            (now, session_id),
        )
    else:
        db.conn.execute(
            "UPDATE chats SET status = ?, last_message_at = ? WHERE id = ?",
            ("ARCHIVED", now, session_id),
        )
        db.conn.execute(
            f"UPDATE gateway_chat_meta SET updated_at = {placeholder} WHERE chat_id = {placeholder}",
            (now, session_id),
        )
    db.conn.commit()
    return {"id": session_id, "status": "terminated", "updated_at": now}


# ── audit log ───────────────────────────────────────────────


def add_audit_log(
    db: DBClient,
    request_id: str,
    actor_user_id: str,
    tenant_id: str,
    action: str,
    resource: str,
    status: str,
    detail: str,
) -> None:
    now = now_iso()
    if db.backend == "postgres":
        db.conn.execute(
            """
            INSERT INTO gateway_audit_logs (
                request_id, actor_user_id, tenant_id, action, resource, status, detail, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (request_id, actor_user_id, tenant_id, action, resource, status, detail, now),
        )
    else:
        db.conn.execute(
            """
            INSERT INTO gateway_audit_logs (
                request_id, actor_user_id, tenant_id, action, resource, status, detail, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (request_id, actor_user_id, tenant_id, action, resource, status, detail, now),
        )
    db.conn.commit()


def list_audit_logs(db: DBClient, tenant_id: str, actor_user_id: str, limit: int) -> list[dict[str, Any]]:
    placeholder = _placeholder(db)
    cursor = db.conn.execute(
        f"""
        SELECT id, action, resource, status, detail, request_id, actor_user_id, tenant_id, created_at
        FROM gateway_audit_logs
        WHERE tenant_id = {placeholder} AND actor_user_id = {placeholder}
        ORDER BY id DESC
        LIMIT {placeholder}
        """,
        (tenant_id, actor_user_id, limit),
    )
    rows = cursor.fetchall()
    if not rows:
        return []
    if hasattr(rows[0], "keys"):
        return [dict(row) for row in rows]
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in rows]
