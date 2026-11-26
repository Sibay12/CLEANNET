import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi import Cookie, HTTPException

from app.config import settings


def new_claim_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_text, digest_text = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_session(subject: str, role: str, hours: int = 12) -> str:
    if not settings.session_secret:
        raise RuntimeError("SESSION_SECRET is not configured")
    payload = _b64(json.dumps({"sub": subject, "role": role, "exp": int(time.time()) + hours * 3600}, separators=(",", ":")).encode())
    signature = _b64(hmac.new(settings.session_secret.encode(), payload.encode(), hashlib.sha256).digest())
    return payload + "." + signature


def read_session(token: str | None, role: str) -> str:
    if not token or not settings.session_secret:
        raise HTTPException(status_code=401, detail="Please sign in")
    try:
        payload, signature = token.split(".", 1)
        expected = _b64(hmac.new(settings.session_secret.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if data.get("role") != role or int(data.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return str(data["sub"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Session expired. Please sign in")


def require_admin(admin_session: str | None = Cookie(default=None)) -> str:
    return read_session(admin_session, "admin")


def require_customer(customer_session: str | None = Cookie(default=None)) -> str:
    return read_session(customer_session, "customer")
