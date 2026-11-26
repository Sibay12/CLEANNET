from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import re

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.database import check_database, close_database, get_db, initialize_indexes
from app.models import DeviceCreate
from app.security import create_session, hash_password, hash_token, new_claim_token, require_admin, require_customer, verify_password

STATIC_DIR = Path(__file__).parent / "static"


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)


class CustomerRegister(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class ClaimInput(BaseModel):
    device_id: str = Field(min_length=4, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    claim_token: str = Field(min_length=20, max_length=200)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.mongodb_uri:
        try:
            initialize_indexes()
            db = get_db()
            db.customers.create_index("email", unique=True)
            db.devices.create_index("claimed_by")
        except Exception:
            pass
    yield
    close_database()


app = FastAPI(title="CLEANNET API", version="0.3.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


def set_session(response: Response, name: str, token: str, hours: int = 12):
    response.set_cookie(name, token, max_age=hours * 3600, httponly=True,
                        secure=settings.app_env == "production", samesite="strict", path="/")


@app.get("/", include_in_schema=False)
def portal_home():
    return FileResponse(STATIC_DIR / "customer.html")


@app.get("/admin", include_in_schema=False)
def admin_portal():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/customer", include_in_schema=False)
def customer_portal():
    return FileResponse(STATIC_DIR / "customer.html")


@app.get("/health")
def health():
    return {"status": "ok", "service": "cleannet-api", "version": "0.3.0"}


@app.get("/ready")
def ready():
    if not check_database():
        raise HTTPException(status_code=503, detail="Database unavailable or not configured")
    return {"status": "ready", "database": "connected"}


@app.post("/api/admin/login")
def admin_login(payload: LoginInput, response: Response):
    if not settings.admin_username or not settings.admin_password or not settings.session_secret:
        raise HTTPException(status_code=503, detail="Admin login is not configured. Set ADMIN_USERNAME, ADMIN_PASSWORD and SESSION_SECRET in Render.")
    valid_user = payload.username.strip() == settings.admin_username
    valid_password = hmac_compare(payload.password, settings.admin_password)
    if not (valid_user and valid_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    set_session(response, "admin_session", create_session(settings.admin_username, "admin"))
    return {"ok": True, "username": settings.admin_username}


def hmac_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


@app.post("/api/customer/register", status_code=201)
def customer_register(payload: CustomerRegister, response: Response):
    db = get_db()
    email = str(payload.email).lower().strip()
    doc = {"name": payload.name.strip(), "email": email, "password_hash": hash_password(payload.password),
           "created_at": datetime.now(timezone.utc).isoformat()}
    try:
        db.customers.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    set_session(response, "customer_session", create_session(email, "customer"))
    return {"ok": True, "name": doc["name"], "email": email}


@app.post("/api/customer/login")
def customer_login(payload: LoginInput, response: Response):
    email = payload.username.lower().strip()
    customer = get_db().customers.find_one({"email": email})
    if not customer or not verify_password(payload.password, customer.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    set_session(response, "customer_session", create_session(email, "customer"))
    return {"ok": True, "name": customer["name"], "email": email}


@app.post("/api/logout")
def logout(response: Response):
    for name in ("admin_session", "customer_session"):
        response.delete_cookie(name, path="/", secure=settings.app_env == "production", httponly=True, samesite="strict")
    return {"ok": True}


@app.get("/api/customer/me")
def customer_me(email: str = Depends(require_customer)):
    customer = get_db().customers.find_one({"email": email}, {"_id": 0, "password_hash": 0})
    if not customer:
        raise HTTPException(status_code=404, detail="Customer account not found")
    devices = list(get_db().devices.find({"claimed_by": email}, {"_id": 0, "claim_token_hash": 0}).sort("created_at", -1))
    return {"customer": customer, "devices": devices}


@app.post("/api/customer/claim")
def claim_device(payload: ClaimInput, email: str = Depends(require_customer)):
    db = get_db()
    token_hash = hash_token(payload.claim_token)
    now = datetime.now(timezone.utc).isoformat()
    result = db.devices.update_one(
        {"device_id": payload.device_id, "status": "inventory", "claim_token_hash": token_hash, "claimed_by": None},
        {"$set": {"status": "claimed", "claimed_by": email, "claimed_at": now, "updated_at": now},
         "$unset": {"claim_token_hash": ""}},
    )
    if result.modified_count != 1:
        raise HTTPException(status_code=409, detail="Device/token invalid, already claimed, or unavailable")
    return {"ok": True, "device_id": payload.device_id, "status": "claimed"}


@app.post("/api/admin/devices", dependencies=[Depends(require_admin)], status_code=201)
def create_device(payload: DeviceCreate):
    db = get_db()
    token = new_claim_token()
    now = datetime.now(timezone.utc).isoformat()
    doc = {"device_id": payload.device_id, "hardware_model": payload.hardware_model, "notes": payload.notes,
           "status": "inventory", "claim_token_hash": hash_token(token), "claimed_by": None,
           "created_at": now, "updated_at": now}
    try:
        db.devices.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Device ID already exists")
    return {"device_id": payload.device_id, "status": "inventory", "claim_token": token,
            "warning": "Save this token now. It is shown only once; only its hash is stored."}


@app.get("/api/admin/devices", dependencies=[Depends(require_admin)])
def list_devices(limit: int = Query(default=50, ge=1, le=200)):
    cursor = get_db().devices.find({}, {"_id": 0, "claim_token_hash": 0}).sort("created_at", -1).limit(limit)
    devices = list(cursor)
    return {"devices": devices, "count": len(devices)}


@app.get("/api/admin/session")
def admin_session_status(admin: str = Depends(require_admin)):
    return {"ok": True, "username": admin}
