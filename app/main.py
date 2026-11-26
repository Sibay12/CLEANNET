from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.database import check_database, close_database, get_db, initialize_indexes
from app.models import DeviceCreate
from app.security import hash_token, new_claim_token, require_admin


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.mongodb_uri:
        try:
            initialize_indexes()
        except Exception:
            # Keep process health available; /ready reports database state.
            pass
    yield
    close_database()


app = FastAPI(title="CLEANNET API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Key"],
)


@app.get("/")
def root():
    return {"service": "CLEANNET API", "version": "0.1.0", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "cleannet-api", "version": "0.1.0"}


@app.get("/ready")
def ready():
    if not check_database():
        raise HTTPException(status_code=503, detail="Database unavailable or not configured")
    return {"status": "ready", "database": "connected"}


@app.post("/api/admin/devices", dependencies=[Depends(require_admin)], status_code=201)
def create_device(payload: DeviceCreate):
    db = get_db()
    token = new_claim_token()
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "device_id": payload.device_id,
        "hardware_model": payload.hardware_model,
        "notes": payload.notes,
        "status": "inventory",
        "claim_token_hash": hash_token(token),
        "claimed_by": None,
        "created_at": now,
        "updated_at": now,
    }
    try:
        db.devices.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Device ID already exists")
    return {
        "device_id": payload.device_id,
        "status": "inventory",
        "claim_token": token,
        "warning": "Save this token now. It is shown only once; only its hash is stored.",
    }


@app.get("/api/admin/devices", dependencies=[Depends(require_admin)])
def list_devices(limit: int = Query(default=50, ge=1, le=200)):
    db = get_db()
    cursor = db.devices.find(
        {},
        {"_id": 0, "claim_token_hash": 0},
    ).sort("created_at", -1).limit(limit)
    devices = list(cursor)
    return {"devices": devices, "count": len(devices)}
