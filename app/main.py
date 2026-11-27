from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import re
import json
import ipaddress
import urllib.request
import urllib.error

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator
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
    device_id: str = Field(min_length=4, max_length=64, pattern=r"^(?:[A-Za-z0-9_-]{4,64}|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})$")
    claim_token: str = Field(min_length=20, max_length=200)

class DeviceHeartbeat(BaseModel):
    device_id: str = Field(min_length=17, max_length=17, pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    firmware: str = Field(default="unknown", max_length=32)
    wifi: str = Field(default="unknown", max_length=24)
    lan_ip: str = Field(default="", max_length=45)
    dns_total: int = Field(default=0, ge=0)
    dns_blocked: int = Field(default=0, ge=0)


class BlocklistUpdate(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=1000)


class DomainReviewInput(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=50)

    @field_validator("domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            domain = value.strip().lower().rstrip(".")
            if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
                raise ValueError(f"Invalid domain name: {value}")
            normalized.append(domain)
        return normalized


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


app = FastAPI(title="CLEANNET API", version="0.4.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
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
    return {"status": "ok", "service": "cleannet-api", "version": "0.4.0"}


@app.get("/api/firmware/manifest")
def firmware_manifest(channel: str = Query(default="stable", min_length=1, max_length=24)):
    """Public OTA metadata. Firmware binaries are hosted as immutable HTTPS release assets."""
    from re import fullmatch

    if not settings.firmware_enabled:
        return {"enabled": False, "channel": channel, "message": "No firmware release is currently published"}
    if channel != settings.firmware_channel:
        return {"enabled": False, "channel": channel, "message": "No release for this channel"}
    if not settings.firmware_url or not settings.firmware_sha256:
        raise HTTPException(status_code=503, detail="Firmware release metadata is incomplete")
    if not settings.firmware_url.startswith("https://"):
        raise HTTPException(status_code=503, detail="Firmware URL must use HTTPS")
    if not fullmatch(r"[0-9a-fA-F]{64}", settings.firmware_sha256):
        raise HTTPException(status_code=503, detail="Firmware SHA-256 must be 64 hexadecimal characters")
    return {
        "enabled": True,
        "product": "CLEANNET",
        "board": "esp32c3",
        "channel": settings.firmware_channel,
        "version": settings.firmware_version,
        "url": settings.firmware_url,
        "sha256": settings.firmware_sha256.lower(),
        "minimum_battery_percent": settings.firmware_min_battery,
    }


@app.get("/api/firmware/download", include_in_schema=False)
def firmware_download():
    """Serve the immutable ESP32-C3 OTA application image from this deployment."""
    firmware_path = Path(__file__).resolve().parents[1] / "firmware" / "releases" / "cleannet_esp32c3_dns.bin"
    if not firmware_path.is_file():
        raise HTTPException(status_code=404, detail="Firmware image is not published")
    return FileResponse(
        firmware_path,
        media_type="application/octet-stream",
        filename="cleannet_esp32c3_dns.bin",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/api/blocklist")
def get_blocklist(since: int = Query(default=0, ge=0)):
    """Return the current shared domain blocklist for ESP32 devices."""
    doc = get_db().blocklists.find_one({"_id": "global"}, {"_id": 0})
    if not doc:
        return {"version": 0, "domains": [], "updated_at": None}
    version = int(doc.get("version", 0))
    if since >= version:
        return {"version": version, "not_modified": True, "domains": []}
    return {"version": version, "not_modified": False,
            "updated_at": doc.get("updated_at"), "domains": doc.get("domains", [])[:64]}


@app.put("/api/admin/blocklist", dependencies=[Depends(require_admin)])
def replace_blocklist(payload: BlocklistUpdate):
    """Replace the shared blocklist atomically; admin-only."""
    domains = sorted(set(payload.domains))
    now = datetime.now(timezone.utc).isoformat()
    current = get_db().blocklists.find_one({"_id": "global"}, {"version": 1})
    version = int(current.get("version", 0)) + 1 if current else 1
    get_db().blocklists.replace_one(
        {"_id": "global"},
        {"_id": "global", "version": version, "domains": domains, "updated_at": now},
        upsert=True,
    )
    return {"ok": True, "version": version, "domain_count": len(domains), "updated_at": now}



@app.get("/api/admin/blocklist", dependencies=[Depends(require_admin)])
def admin_get_blocklist():
    doc = get_db().blocklists.find_one({"_id": "global"}, {"_id": 0})
    return {"version": int((doc or {}).get("version", 0)),
            "domains": (doc or {}).get("domains", []),
            "updated_at": (doc or {}).get("updated_at")}


@app.post("/api/admin/domain-review", dependencies=[Depends(require_admin)])
def review_domains(payload: DomainReviewInput):
    """Ask Gemini to classify candidate domains; never auto-publish its decisions."""
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="Gemini is not configured. Add GEMINI_API_KEY in Render environment.")
    domains = sorted({d.strip().lower().rstrip(".") for d in payload.domains})
    if not domains or any(not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", d) for d in domains):
        raise HTTPException(status_code=422, detail="One or more domain names are invalid")
    prompt = (
        "Classify each domain for DNS ad/tracker blocking. Return ONLY a JSON array "
        "of objects with keys domain, decision, confidence, reason. decision must be "
        "block only when strongly associated with advertising, tracking, telemetry, "
        "or ad measurement; otherwise allow. Protect content/CDN, login, API, video "
        "streaming, and core app domains. Never infer that a domain is an ad domain "
        "from its name alone. confidence is 0 to 1. Domains: " + json.dumps(domains)
    )
    body = json.dumps({"contents":[{"parts":[{"text":prompt}]}],
                       "generationConfig":{"temperature":0.1,"responseMimeType":"application/json"}}).encode()
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"
    req = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json", "x-goog-api-key": settings.gemini_api_key}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
        raw = result["candidates"][0]["content"]["parts"][0]["text"]
        decisions = json.loads(raw)
        if not isinstance(decisions, list):
            raise ValueError("Gemini response is not a JSON array")
        safe = []
        for item in decisions:
            if not isinstance(item, dict) or item.get("domain") not in domains:
                continue
            decision = item.get("decision")
            if decision not in ("block", "allow"):
                decision = "allow"
            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0))))
            except (TypeError, ValueError):
                confidence = 0.0
            safe.append({"domain": item["domain"], "decision": decision,
                         "confidence": confidence, "reason": str(item.get("reason", ""))[:240]})
        return {"results": safe, "note": "Review the suggestions before saving the blocklist."}
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail="Gemini review failed: " + str(exc)[:180])


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
    devices = list(get_db().devices.find({"claimed_by": email}, {"_id": 0, "claim_token_hash": 0, "device_token_hash": 0}).sort("created_at", -1))
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


def _public_client_ip(request: Request) -> str | None:
    # Render's Cloudflare edge supplies CF-Connecting-IP. Do not trust arbitrary
    # left-most X-Forwarded-For values because clients can spoof that header.
    candidates = [request.headers.get("cf-connecting-ip"), request.client.host if request.client else None]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate.strip())
            if address.is_global:
                return str(address)
        except ValueError:
            continue
    return None


def _lookup_ip_location(public_ip: str) -> dict | None:
    """Approximate public-IP geolocation. Private/reserved IPs are never queried."""
    try:
        request = urllib.request.Request(
            "https://ipdata.free/" + public_ip,
            headers={"Accept": "application/json", "User-Agent": "CLEANNET/0.2"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        if latitude is None or longitude is None:
            return None
        latitude, longitude = float(latitude), float(longitude)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            return None
        return {
            "latitude": latitude,
            "longitude": longitude,
            "city": str(data.get("city") or "")[:100],
            "region": str(data.get("region") or "")[:100],
            "country": str(data.get("country") or "")[:100],
            "postal": str(data.get("postal") or "")[:24],
            "timezone": str(data.get("timezone") or "")[:80],
            "location_source": "IP geolocation (approximate)",
            "location_provider": "ipdata.co",
        }
    except (urllib.error.URLError, TimeoutError, ValueError, TypeError, KeyError):
        return None


@app.post("/api/device/heartbeat")
def device_heartbeat(
    payload: DeviceHeartbeat,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Authenticated ESP32-C3 heartbeat; token is stored hashed and sent only over HTTPS."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Device authorization required")
    raw_token = authorization[7:].strip()
    if len(raw_token) < 20 or len(raw_token) > 200:
        raise HTTPException(status_code=401, detail="Invalid device authorization")
    db = get_db()
    device = db.devices.find_one({"device_id": payload.device_id})
    if not device or not hmac_compare(hash_token(raw_token), device.get("device_token_hash", "")):
        raise HTTPException(status_code=401, detail="Unknown device or invalid device token")
    if device.get("status") == "blocked":
        raise HTTPException(status_code=403, detail="Device is blocked")
    now = datetime.now(timezone.utc).isoformat()
    public_ip = _public_client_ip(request)
    updates = {
        "last_seen": now,
        "firmware": payload.firmware,
        "wifi_status": payload.wifi,
        "lan_ip": payload.lan_ip,
        "dns_total": payload.dns_total,
        "dns_blocked": payload.dns_blocked,
        "heartbeat_interval_seconds": 900,
        "updated_at": now,
    }
    previous_ip = device.get("public_ip")
    unset_fields = {}
    if public_ip:
        updates["public_ip"] = public_ip
        last_attempt = device.get("geo_lookup_attempted_at")
        retry_geo = not last_attempt
        if last_attempt:
            try:
                attempted_at = datetime.fromisoformat(str(last_attempt).replace("Z", "+00:00"))
                retry_geo = (datetime.now(timezone.utc) - attempted_at).total_seconds() >= 21600
            except ValueError:
                retry_geo = True
        if public_ip != previous_ip or (device.get("latitude") is None and retry_geo):
            updates["geo_lookup_attempted_at"] = now
            location = _lookup_ip_location(public_ip)
            if location:
                updates.update(location)
                updates["location_updated_at"] = now
                updates["location_status"] = "approximate"
            else:
                updates["location_status"] = "IP location unavailable"
                if public_ip != previous_ip:
                    unset_fields = {"latitude": "", "longitude": "", "city": "", "region": "",
                                    "country": "", "postal": "", "timezone": "",
                                    "location_source": "", "location_provider": ""}
    update_doc = {"$set": updates}
    if unset_fields:
        update_doc["$unset"] = unset_fields
    result = db.devices.update_one(
        {"device_id": payload.device_id, "device_token_hash": device["device_token_hash"], "status": {"$ne": "blocked"}},
        update_doc,
    )
    if result.modified_count != 1:
        raise HTTPException(status_code=409, detail="Device record changed; retry heartbeat")
    return {"ok": True, "device_id": payload.device_id, "last_seen": now,
            "location_source": updates.get("location_source", device.get("location_source", "pending"))}


@app.post("/api/admin/devices", dependencies=[Depends(require_admin)], status_code=201)
def create_device(payload: DeviceCreate):
    db = get_db()
    token = new_claim_token()
    device_token = new_claim_token()
    now = datetime.now(timezone.utc).isoformat()
    doc = {"device_id": payload.device_id, "hardware_model": payload.hardware_model, "notes": payload.notes,
           "status": "inventory", "claim_token_hash": hash_token(token),
           "device_token_hash": hash_token(device_token), "claimed_by": None,
           "created_at": now, "updated_at": now}
    try:
        db.devices.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Device ID already exists")
    return {"device_id": payload.device_id, "status": "inventory", "claim_token": token,
            "device_token": device_token,
            "warning": "Save both tokens now. They are shown only once; only their hashes are stored. Enter the device token in the local CLEANNET setup page."}


@app.post("/api/admin/devices/{device_id}/token", dependencies=[Depends(require_admin)])
def rotate_device_token(device_id: str):
    """Rotate the device heartbeat credential; the new raw token is returned once."""
    db = get_db()
    if not db.devices.find_one({"device_id": device_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Device not found")
    token = new_claim_token()
    now = datetime.now(timezone.utc).isoformat()
    db.devices.update_one(
        {"device_id": device_id},
        {"$set": {"device_token_hash": hash_token(token), "updated_at": now}},
    )
    return {"ok": True, "device_id": device_id, "device_token": token,
            "warning": "The previous device token is now invalid. Save this new token; it is shown only once."}


@app.get("/api/admin/devices", dependencies=[Depends(require_admin)])
def list_devices(limit: int = Query(default=50, ge=1, le=200)):
    cursor = get_db().devices.find({}, {"_id": 0, "claim_token_hash": 0, "device_token_hash": 0}).sort("created_at", -1).limit(limit)
    devices = list(cursor)
    return {"devices": devices, "count": len(devices)}


@app.get("/api/admin/session")
def admin_session_status(admin: str = Depends(require_admin)):
    return {"ok": True, "username": admin}
