import hashlib
import hmac
import secrets

from fastapi import Header, HTTPException

from app.config import settings


def new_claim_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
    expected = settings.admin_api_key
    if not expected or not x_admin_key or not hmac.compare_digest(x_admin_key, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
