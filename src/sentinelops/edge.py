"""Fail-closed API edge policy for the local SentinelOps service."""

from __future__ import annotations

import ipaddress
import math
import os
import re
import threading
import time
from collections import deque
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
_EDGE_EXEMPT_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})


def _parse_int(
    environment: Mapping[str, str],
    name: str,
    default: int,
) -> int:
    raw = environment.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _split_csv(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _valid_host(value: str) -> bool:
    if value == "*" or "*" in value or "://" in value or "/" in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME.fullmatch(value))


def _valid_cors_origin(value: str) -> bool:
    if "*" in value:
        return False
    parts = urlsplit(value)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path
        or parts.query
        or parts.fragment
    ):
        return False
    if parts.scheme == "https":
        return True
    return parts.hostname in {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class EdgePolicy:
    """Validated process-local edge controls with conservative defaults."""

    max_request_bytes: int = 1_000_000
    rate_limit_requests: int = 60
    rate_window_seconds: float = 60.0
    max_inflight: int = 16
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    cors_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 1_024 <= self.max_request_bytes <= 5_000_000:
            raise ValueError("max_request_bytes must be between 1024 and 5000000")
        if not 1 <= self.rate_limit_requests <= 6_000:
            raise ValueError("rate_limit_requests must be between 1 and 6000")
        if not 1.0 <= self.rate_window_seconds <= 3_600.0:
            raise ValueError("rate_window_seconds must be between 1 and 3600 seconds")
        if not 1 <= self.max_inflight <= 256:
            raise ValueError("max_inflight must be between 1 and 256")
        if not self.trusted_hosts or any(not _valid_host(host) for host in self.trusted_hosts):
            raise ValueError("trusted_hosts must contain explicit host names or IP addresses")
        if any(not _valid_cors_origin(origin) for origin in self.cors_origins):
            raise ValueError("cors_origins must contain exact HTTPS or loopback HTTP origins")


def edge_policy_from_env(environment: Mapping[str, str] | None = None) -> EdgePolicy:
    source = os.environ if environment is None else environment
    return EdgePolicy(
        max_request_bytes=_parse_int(source, "SENTINELOPS_MAX_REQUEST_BYTES", 1_000_000),
        rate_limit_requests=_parse_int(source, "SENTINELOPS_RATE_LIMIT_RPM", 60),
        max_inflight=_parse_int(source, "SENTINELOPS_MAX_INFLIGHT", 16),
        trusted_hosts=_split_csv(
            source.get("SENTINELOPS_TRUSTED_HOSTS"),
            ("127.0.0.1", "localhost", "testserver"),
        ),
        cors_origins=_split_csv(source.get("SENTINELOPS_CORS_ORIGINS"), ()),
    )


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int | None = None


class SlidingWindowLimiter:
    """Thread-safe, process-local sliding-window request limiter."""

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        clock=time.monotonic,
    ) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._clock = clock
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> RateLimitResult:
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._limit:
                retry_after = max(
                    1,
                    math.ceil(self._timestamps[0] + self._window_seconds - now),
                )
                return RateLimitResult(False, retry_after)
            self._timestamps.append(now)
            return RateLimitResult(True)


class InflightLimiter:
    """Non-blocking process-local concurrency guard."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._active = 0
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self._active >= self._limit:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("inflight limiter released without an acquisition")
            self._active -= 1


@dataclass(frozen=True)
class EdgeAdmission:
    allowed: bool
    status_code: int | None = None
    detail: str | None = None
    retry_after_seconds: int | None = None
    inflight_acquired: bool = False


class EdgeController:
    """Combines global rate and concurrency controls for business endpoints."""

    def __init__(self, policy: EdgePolicy) -> None:
        self._rate = SlidingWindowLimiter(
            limit=policy.rate_limit_requests,
            window_seconds=policy.rate_window_seconds,
        )
        self._inflight = InflightLimiter(policy.max_inflight)

    def admit(self, path: str) -> EdgeAdmission:
        if path in _EDGE_EXEMPT_PATHS:
            return EdgeAdmission(True)
        if not self._inflight.acquire():
            return EdgeAdmission(
                False,
                status_code=503,
                detail="server concurrency limit reached",
                retry_after_seconds=1,
            )
        rate = self._rate.allow()
        if not rate.allowed:
            self._inflight.release()
            return EdgeAdmission(
                False,
                status_code=429,
                detail="request rate limit reached",
                retry_after_seconds=rate.retry_after_seconds,
            )
        return EdgeAdmission(True, inflight_acquired=True)

    def release(self, admission: EdgeAdmission) -> None:
        if admission.inflight_acquired:
            self._inflight.release()


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP bodies before they reach request parsing."""

    def __init__(self, app: ASGIApp, *, max_request_bytes: int) -> None:
        self.app = app
        self.max_request_bytes = max_request_bytes

    async def _reject(self, scope: Scope, receive: Receive, send: Send, status_code: int) -> None:
        detail = "request body too large" if status_code == 413 else "invalid content-length"
        response = JSONResponse({"detail": detail}, status_code=status_code)
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]
        if len(content_lengths) > 1:
            await self._reject(scope, receive, send, 400)
            return
        if content_lengths:
            try:
                content_length = int(content_lengths[0].decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                await self._reject(scope, receive, send, 400)
                return
            if content_length < 0:
                await self._reject(scope, receive, send, 400)
                return
            if content_length > self.max_request_bytes:
                await self._reject(scope, receive, send, 413)
                return

        if scope.get("method", "").upper() not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_request_bytes:
                await self._reject(scope, receive, send, 413)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


def apply_security_headers(scope: Scope, response_headers: MutableMapping[str, str]) -> None:
    """Mutate a response header mapping using a fixed safe policy."""

    response_headers["X-Content-Type-Options"] = "nosniff"
    response_headers["X-Frame-Options"] = "DENY"
    response_headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response_headers["Referrer-Policy"] = "no-referrer"
    response_headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response_headers["Cache-Control"] = "no-store"
    if scope.get("scheme") == "https":
        response_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
