# CLEANNET

DNS-based network ad-filtering platform built by TAKNA TECHNOLOGY and owned by SIBAYAN ENTERPRISE.

## Current implementation — Phases 1 and 2
- FastAPI + MongoDB Atlas backend
- Admin username/password login using a signed HttpOnly session cookie
- Customer email/password registration and login
- PBKDF2-HMAC-SHA256 password hashing
- Admin device inventory and one-time claim-token creation
- Customer device claim with atomic database update; claim token is consumed
- Customer dashboard API for owned devices

## Environment variables
- `MONGODB_URI` — MongoDB Atlas URI; database name is read from URI or defaults to `cleannet`.
- `ADMIN_USERNAME` — admin login name (default: admin)
- `ADMIN_PASSWORD` — strong admin password; configure only in Render secret environment
- `SESSION_SECRET` — long random secret used to sign sessions; configure only in Render
- `CORS_ORIGINS` — allowed browser origins
- `APP_ENV` — use production on Render

Never commit real credentials, session secrets, payment credentials, device secrets, or customer Wi-Fi passwords. Never put admin credentials in frontend JavaScript.

## Routes
- `GET /health`, `GET /ready`
- `POST /api/admin/login`, `GET /api/admin/session`
- `GET/POST /api/admin/devices` (admin session required)
- `POST /api/customer/register`, `POST /api/customer/login`
- `GET /api/customer/me`, `POST /api/customer/claim`
- `POST /api/logout`

Admin and customer sessions are signed, time-limited, HttpOnly, SameSite=Strict cookies. Customer passwords are hashed; plaintext passwords are never stored. QR claim data must contain only device ID and one-time claim token. Wi-Fi credentials are not collected by these web endpoints.

Camera QR scanning, email verification, password reset, subscriptions, TAKNAPAY verification, and ESP32 firmware are not yet implemented.

## Run locally
1. Install dependencies: `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and set real values.
3. Start: `uvicorn app.main:app --reload`
4. Open `/admin` or `/customer`.

DNS filtering cannot guarantee removal of every advertisement. YouTube, in-app, and first-party HTTPS ads may bypass DNS-level filtering.

## Ownership
Created by **TAKNA TECHNOLOGY**  
Owned by **SIBAYAN ENTERPRISE**  
Owner: **Sibaditya Pal**  
GSTIN: **19GSFPP8608L1ZW** (provided by project owner)
