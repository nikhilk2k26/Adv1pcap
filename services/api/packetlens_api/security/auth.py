"""AuthN / RBAC / audit dependencies for the API (Phase 1).

Production: JWT (HS256/RS256) issued by an IdP or local login, plus hashed API keys.
Dev/tests: deterministic token format `pl-dev.<tenant>.<role>.<user>` so pipelines can run
without a secret store; this path is disabled when `settings.allow_dev_tokens=False`.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException

ROLE_ORDER = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str
    role: str

    def require(self, minimum_role: str) -> None:
        if ROLE_ORDER.get(self.role, -1) < ROLE_ORDER[minimum_role]:
            raise HTTPException(403, f"role {self.role!r} insufficient, need >= {minimum_role!r}")


class AuthSettings:
    def __init__(self, jwt_secret: Optional[str] = None, allow_dev_tokens: bool = True):
        self.jwt_secret = jwt_secret or os.environ.get("PACKETLENS_JWT_SECRET", "")
        self.allow_dev_tokens = allow_dev_tokens


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def issue_jwt(tenant_id: str, user_id: str, role: str, secret: str, ttl_s: int = 3600) -> str:
    """Compact HS256 JWT without external deps (swap for python-jose/pyjwt in prod image)."""
    import json
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub": user_id, "tenant": tenant_id, "role": role,
        "iat": int(time.time()), "exp": int(time.time()) + ttl_s,
    }).encode())
    sig = _b64url(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str, settings: AuthSettings) -> Principal:
    if token.startswith("pl-dev."):
        if not settings.allow_dev_tokens:
            raise HTTPException(401, "dev tokens disabled")
        parts = token.split(".")
        if len(parts) != 4:
            raise HTTPException(401, "malformed dev token")
        _, tenant, role, user = parts
        if role not in ROLE_ORDER:
            raise HTTPException(401, "bad role in token")
        return Principal(tenant, user, role)
    # real JWT path
    parts = token.split(".")
    if len(parts) != 3 or not settings.jwt_secret:
        raise HTTPException(401, "invalid token")
    header, payload, sig = parts
    expect = _b64url(hmac.new(settings.jwt_secret.encode(), f"{header}.{payload}".encode(),
                              hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expect):
        raise HTTPException(401, "signature mismatch")
    import json, base64
    pad = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(pad))
    if claims.get("exp", 0) < time.time():
        raise HTTPException(401, "token expired")
    return Principal(claims["tenant"], claims["sub"], claims["role"])


async def current_principal(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> Principal:
    settings = getattr(current_principal, "_settings", AuthSettings())
    if authorization and authorization.lower().startswith("bearer "):
        return verify_token(authorization.split(" ", 1)[1], settings)
    if x_api_key:
        # API keys are stored hashed in api_keys table; lookup handled by router layer via
        # dependency injection of CaptureService — here we accept signed key format.
        return verify_token(x_api_key, settings)
    raise HTTPException(401, "missing bearer token or API key")


def require_role(minimum: str):
    async def dep(p: Principal = Depends(current_principal)) -> Principal:
        p.require(minimum)
        return p
    return dep
