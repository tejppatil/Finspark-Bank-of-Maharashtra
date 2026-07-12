"""Authentication: password hashing + signed session tokens (stdlib only).

Deliberately dependency-free (PBKDF2-HMAC for passwords, HMAC-SHA256 for tokens)
so it builds cleanly everywhere, including Python 3.14. Not a substitute for a
production IdP — it's a self-contained auth layer for the demo.
"""
import base64
import hashlib
import hmac
import json
import os
import time

from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session as OrmSession

from app.config import settings
from app.models.db import SessionLocal
from app.models.entities import User

_PBKDF2_ROUNDS = 200_000


# --- password hashing (PBKDF2-HMAC-SHA256) ---

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        _, rounds, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


# --- tokens (compact HMAC-signed, JWT-like) ---

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def create_token(user: User) -> str:
    payload = {"sub": user.username, "role": user.role, "type": user.account_type,
               "name": user.name, "exp": int(time.time()) + settings.token_ttl_minutes * 60}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(settings.secret_key.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def decode_token(token: str) -> dict:
    try:
        body, sig = token.split(".")
    except ValueError:
        raise _unauth("malformed token")
    expected = _b64(hmac.new(settings.secret_key.encode(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise _unauth("bad signature")
    payload = json.loads(_unb64(body))
    if payload.get("exp", 0) < time.time():
        raise _unauth("token expired")
    return payload


def _unauth(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail,
                        headers={"WWW-Authenticate": "Bearer"})


# --- FastAPI dependencies ---

_bearer = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer),
                 db: OrmSession = Depends(get_db)) -> User:
    if creds is None:
        raise _unauth("not authenticated")
    payload = decode_token(creds.credentials)
    user = db.query(User).filter_by(username=payload["sub"]).first()
    if user is None:
        raise _unauth("unknown user")
    return user


def require_analyst(user: User = Depends(current_user)) -> User:
    if user.account_type != "ANALYST":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "SOC analyst access required")
    return user


def user_from_token(token: str | None, db: OrmSession) -> User | None:
    """Resolve a user from a raw token string (for WebSocket query-param auth)."""
    if not token:
        return None
    try:
        payload = decode_token(token)
    except HTTPException:
        return None
    return db.query(User).filter_by(username=payload["sub"]).first()
