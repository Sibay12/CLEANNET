# CLEANNET Development Roadmap

## Phase 1 — Backend foundation
- [x] FastAPI application skeleton
- [x] MongoDB Atlas connection through environment variables
- [x] Health and readiness endpoints
- [x] Device inventory API
- [x] Unique device ID index
- [x] One-time claim token generation; store only token hash
- [x] Admin username/password login with signed HttpOnly session cookie

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
- Monthly subscription lifecycle
- TAKNAPAY server-to-server verification/webhooks
- Payment/order audit records
- Entitlement checks and grace policy

## Phase 4 — ESP32-C3 firmware
- Wi-Fi station and provisioning modes
- DNS filtering engine and configurable blocklists
- Secure device identity and authenticated heartbeat
- Signed OTA updates

## Phase 5 — Admin/customer interfaces
- Admin device/customer/subscription management
- Customer device setup and status UI
- Activity and audit logs

## Phase 6 — Security, QA and release
- Threat model and security review
- Integration and hardware tests
- Deployment and recovery documentation
- Production readiness review

DNS filtering is not a guarantee against all ad types, including many in-app and first-party HTTPS ads.
