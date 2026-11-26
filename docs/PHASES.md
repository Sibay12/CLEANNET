# CLEANNET Development Roadmap

## Phase 1 — Backend foundation
- [x] FastAPI application skeleton
- [x] MongoDB Atlas connection through environment variables
- [x] Health and readiness endpoints
- [x] Device inventory API
- [x] Unique device ID index
- [x] One-time claim token generation; store only token hash
- [x] Admin username/password login with signed HttpOnly session cookie
- [x] Public firmware OTA manifest endpoint (release disabled until configured)

## Phase 2 — Customer identity and device claiming
- [x] Customer registration with email and password
- [x] Customer login/logout session
- [x] Password hashing with PBKDF2-HMAC-SHA256
- [x] QR payload fields supported: device_id + one-time claim_token
- [x] Atomic device claim; token consumed after successful claim
- [x] Customer dashboard API listing owned devices
- [ ] Camera-based QR scanner and QR label generation
- [ ] Email verification and password reset

## Phase 3 — Subscription and payments
- [ ] Monthly subscription lifecycle
- [ ] TAKNAPAY server-to-server verification/webhooks
- [ ] Payment/order audit records
- [ ] Entitlement checks and grace policy

## Phase 4 — ESP32-C3 firmware (development source; hardware validation pending)
- [x] Local setup Wi-Fi AP and mobile setup page
- [x] Nearby 2.4 GHz Wi-Fi scan endpoint and network selection
- [x] Store selected router credentials in NVS
- [x] DNS filtering prototype and upstream forwarding
- [x] HTTPS OTA manifest polling, HTTPS binary download and SHA-256 integrity check
- [x] Dual OTA partition layout and ESP-IDF rollback configuration
- [ ] Compile and flash this revision on the physical ESP32-C3 board
- [ ] Verify router association, DNS behavior and OTA on hardware
- [ ] Signed firmware manifest/public-key verification
- [ ] Encrypted NVS credential storage
- [ ] Authenticated device identity and heartbeat
- [ ] Remote blocklist delivery, DNS cache/concurrency and IPv6 handling

## Phase 5 — Admin/customer interfaces
- [x] Existing admin and customer portals retained
- [ ] Admin firmware release management UI
- [ ] Admin device/customer/subscription management
- [ ] Customer device setup and status UI
- [ ] Activity and audit logs

## Phase 6 — Security, QA and release
- [ ] Threat model and security review
- [ ] Integration and hardware tests
- [ ] Deployment and recovery documentation
- [ ] Production readiness review

DNS filtering is not a guarantee against all ad types, including many in-app and first-party HTTPS ads. See firmware/esp32c3/README.md and docs/OTA_RELEASES.md for the current test and release requirements.
