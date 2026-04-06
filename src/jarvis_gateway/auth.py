import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException


@dataclass
class Principal:
    user_id: str
    tenant_id: str
    token: str


class TokenStore:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl_seconds = ttl_seconds
        self.secret = os.getenv("JARVIS_AUTH_SECRET", "").encode("utf-8")
        self._revoked_tokens: set[str] = set()

    def issue(self, user_id: str, tenant_id: str) -> str:
        expires_at = int(time.time() + self.ttl_seconds)
        payload = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "exp": expires_at,
            "nonce": secrets.token_urlsafe(8),
        }
        payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_raw).rstrip(b"=")
        signature = hmac.new(self.secret, payload_b64, hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
        return f"{payload_b64.decode()}.{signature_b64.decode()}"

    def revoke(self, token: str) -> None:
        self._revoked_tokens.add(token)

    def get(self, token: str) -> dict[str, Any] | None:
        if not self.secret or token in self._revoked_tokens:
            return None
        try:
            payload_b64, signature_b64 = token.split(".", 1)
            payload_bytes = payload_b64.encode("utf-8")
            expected_signature = hmac.new(self.secret, payload_bytes, hashlib.sha256).digest()
            actual_signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
            if not hmac.compare_digest(actual_signature, expected_signature):
                return None
            payload_raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
            payload = json.loads(payload_raw.decode("utf-8"))
        except Exception:
            return None
        if time.time() > float(payload.get("exp", 0)):
            return None
        return payload


def parse_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing authorization header")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="invalid authorization header")
    return parts[1]


def get_principal(token_store: TokenStore, authorization: str | None) -> Principal:
    token = parse_bearer_token(authorization)
    payload = token_store.get(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return Principal(
        user_id=payload["user_id"],
        tenant_id=payload["tenant_id"],
        token=token,
    )


def extract_authorization(authorization: str | None = Header(default=None)) -> str | None:
    return authorization
