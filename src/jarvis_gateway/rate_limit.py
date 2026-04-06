import os
import time
from collections import deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimiter:
    def __init__(self, limit: int = 60, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        queue = self._events.setdefault(key, deque())
        while queue and now - queue[0] >= self.window_seconds:
            queue.popleft()
        if len(queue) >= self.limit:
            return False
        queue.append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.url.path == "/health":
            return await call_next(request)

        client_key = (
            request.headers.get("x-api-key")
            or request.headers.get("x-client-id")
            or (request.client.host if request.client else "unknown")
        )
        if not self.limiter.allow(client_key):
            return JSONResponse(
                status_code=429,
                content={
                    "contract_version": "1.0",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "too many requests",
                    "request_id": getattr(request.state, "request_id", None),
                    "details": {
                        "limit": self.limiter.limit,
                        "window_seconds": self.limiter.window_seconds,
                    },
                },
            )
        return await call_next(request)


def limiter_from_env() -> RateLimiter:
    limit = int(os.getenv("JARVIS_GATEWAY_RATE_LIMIT", "60"))
    window = int(os.getenv("JARVIS_GATEWAY_RATE_WINDOW", "60"))
    return RateLimiter(limit=limit, window_seconds=window)
