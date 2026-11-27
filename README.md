# CLEANNET

DNS-based network ad-filtering platform built by TAKNA TECHNOLOGY and owned by SIBAYAN ENTERPRISE.

## Current implementation — Backend and ESP32-C3 development track
- FastAPI + MongoDB Atlas backend
- Admin username/password login using a signed HttpOnly session cookie
- Customer email/password registration and login
- PBKDF2-HMAC-SHA256 password hashing
- Admin device inventory with one-time customer claim token and separate one-time device heartbeat token
- Factory STA MAC from ESP32-C3 eFuse is the permanent CLEANNET Device ID; router-facing MAC is not overridden
- Authenticated ESP32-C3 cloud heartbeat every 15 minutes over HTTPS; device token is stored hashed in MongoDB and locally in NVS
- Approximate public-IP geolocation (city/region/country/latitude/longitude) with an Admin Panel map and online/offline status
- Customer device claim with atomic database update; claim token is consumed
- Customer dashboard API for owned devices
- Public OTA manifest endpoint at `GET /api/firmware/manifest`; disabled until a tested release is published
- Render environment configuration for controlled firmware releases
- ESP32-C3 firmware source includes local Wi-Fi setup AP, nearby 2.4 GHz scan page, NVS credential storage, DNS prototype and HTTPS OTA download/hash-check foundation

## Render environment variables — Admin credentials
Admin login credentials are controlled only by the Render service environment. They are not hardcoded in the admin page or frontend JavaScript.

Set these keys in Render Dashboard → CLEANNET service → Environment:
- `ADMIN_USERNAME` — the exact username used on the Admin Login page
- `ADMIN_PASSWORD` — the exact password used on the Admin Login page
- `SESSION_SECRET` — a long random signing secret; do not use this as the login password

To change the admin login, edit `ADMIN_USERNAME` and/or `ADMIN_PASSWORD` in Render and save. Render will restart/redeploy the service to load the new values. Existing admin sessions may need to sign in again. Keep a private record of the new username/password before saving. Render may mask secret values after saving; if you cannot view an old password, set a new one and use that new value.

For local development, use the same variable names in a private `.env` file. Never commit `.env` or real credentials to GitHub.

## Firmware OTA release settings

The Render service supports these additional variables:
- `FIRMWARE_ENABLED` — keep `false` until a tested firmware release asset is available
- `FIRMWARE_VERSION` — semantic firmware version
- `FIRMWARE_CHANNEL` — release channel, currently `stable`
- `FIRMWARE_URL` — direct HTTPS URL to an immutable GitHub Release binary asset
- `FIRMWARE_SHA256` — SHA-256 digest of that exact binary
- `FIRMWARE_MIN_BATTERY` — reserved metadata field

The ESP32-C3 polls `GET /api/firmware/manifest`. See `firmware/esp32c3/README.md` for the exact release procedure. Do not enable OTA until the matching binary has been built, tested and uploaded. OTA uses HTTPS certificate verification plus SHA-256 integrity verification and ESP-IDF rollback support; a separate public-key signature scheme is not included yet.

## Other environment variables
- `MONGODB_URI` — MongoDB Atlas URI; database name is read from URI or defaults to `cleannet`.
- `CORS_ORIGINS` — allowed browser origins
- `APP_ENV` — use production on Render

Never commit real credentials, session secrets, payment credentials, device secrets, or customer Wi-Fi passwords. Never put admin credentials in frontend JavaScript.

## Routes
- `GET /health`, `GET /ready`
- `POST /api/admin/login`, `GET /api/admin/session`
- `GET/POST /api/admin/devices` (admin session required)
- `POST /api/device/heartbeat` (device Bearer token required; HTTPS only in production)
- `POST /api/customer/register`, `POST /api/customer/login`
- `GET /api/customer/me`, `POST /api/customer/claim`
- `POST /api/logout`

Admin and customer sessions are signed, time-limited, HttpOnly, SameSite=Strict cookies. Customer passwords are hashed; plaintext passwords are never stored. QR claim data must contain only device ID and one-time claim token. Wi-Fi credentials are not collected by these web endpoints.

Camera QR scanning, email verification, password reset, subscriptions, TAKNAPAY verification, and production-grade DNS hardening are not yet implemented. ESP32-C3 Wi-Fi provisioning, the new heartbeat firmware, and OTA source still require an ESP-IDF build and physical hardware validation.

## Factory MAC identity, device heartbeat, and approximate location

1. Open the local CLEANNET setup page and copy the read-only **Factory MAC Device ID**. It is read from the ESP32-C3 eFuse with `esp_read_mac(..., ESP_MAC_WIFI_STA)`; the firmware does not call `esp_wifi_set_mac()`.
2. In Admin → Device registration, register that exact MAC address. The API returns a one-time customer claim token and a separate one-time device heartbeat token. Save both; the backend stores only their hashes.
3. Paste the **device heartbeat token** into the optional Cloud Device Token field on the local setup page and save/connect. The firmware stores it in NVS and sends it as a Bearer token over HTTPS. Do not share it.
4. Once connected to the router and internet, firmware 0.2.9 sends a heartbeat every 15 minutes to `POST /api/device/heartbeat`. The heartbeat contains Factory MAC Device ID, firmware version, Wi-Fi state, LAN IP and DNS counters.
5. The backend records Last Seen and the public client IP. It uses the Render/Cloudflare `CF-Connecting-IP` header when available and does not trust arbitrary left-most `X-Forwarded-For` values. Private/reserved IP addresses are not sent to the geolocation provider.
6. Public IP geolocation uses [ipdata.co](https://ipdata.co) via `https://ipdata.free/{ip}`. The free city-level tier currently advertises 1,000 city lookups/day and commercial use with attribution; the Admin Panel displays the required provider attribution. Provider limits and terms can change.
7. Admin → Device Location Map shows approximate markers for devices with coordinates. The table shows public IP, city/region/country, coordinates and Last Seen. Devices with a heartbeat in the last 30 minutes are shown as Online.

**Location limitations:** IP geolocation is an estimate of the internet connection's network exit, not GPS. Mobile carrier CGNAT, ISP routing, VPNs and corporate networks can place a marker far from the physical device. It cannot identify a home, building or street address. Offline devices cannot send new heartbeats. No GPS hardware or exact live tracking is included.

**Provisioning/security notes:** Device heartbeat is disabled until a device token is entered locally. A MAC address alone is not authentication. Keep the device token private. If a device is blocked in Admin inventory, the heartbeat endpoint rejects it. Rotate/reissue a token only through a future explicit admin workflow; the current create flow displays each token once.

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
