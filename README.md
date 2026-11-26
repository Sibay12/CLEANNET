# CLEANNET

DNS-based network ad-filtering platform built by TAKNA TECHNOLOGY and owned by SIBAYAN ENTERPRISE.

## Phase 1 — Backend foundation

This phase provides a FastAPI service, MongoDB Atlas connectivity, health checks, and protected device-inventory APIs.

### Stack
- Python 3.11+
- FastAPI + Uvicorn
- MongoDB Atlas via PyMongo
- Render deployment blueprint

### Run locally
1. Create a Python 3.11+ virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and set real values.
4. Start: `uvicorn app.main:app --reload`
5. Open `/docs` for interactive API documentation.

### Environment variables
- `MONGODB_URI` — MongoDB Atlas connection string. The database name is read from the URI when present; otherwise CLEANNET uses the default database name `cleannet`.
- `ADMIN_API_KEY` — long random secret for admin API
- `CORS_ORIGINS` — comma-separated allowed browser origins
- `APP_ENV` — development or production

A separate `MONGODB_DB` variable is not required. Never commit real credentials, device secrets, payment credentials, or customer Wi-Fi passwords. Configure secrets in Render Environment settings.

### API
- `GET /health` — process health
- `GET /ready` — MongoDB readiness
- `POST /api/admin/devices` — register a device and generate a one-time claim token
- `GET /api/admin/devices` — list device inventory

Admin endpoints require header `X-Admin-Key`. The claim token is displayed once; only its SHA-256 hash is stored. Device claiming, customer accounts, QR workflow, subscriptions, TAKNAPAY integration, and ESP32 firmware are later phases.

### Deployment
Render can deploy this service from this repository using `render.yaml`. Set `MONGODB_URI` and `ADMIN_API_KEY` in the Render service environment before using protected endpoints.

### Product limitation
DNS filtering cannot guarantee removal of every advertisement. YouTube, in-app, and first-party HTTPS ads may bypass DNS-level filtering.

## Ownership
Created by **TAKNA TECHNOLOGY**  
Owned by **SIBAYAN ENTERPRISE**  
Owner: **Sibaditya Pal**  
GSTIN: **19GSFPP8608L1ZW** (provided by project owner)
