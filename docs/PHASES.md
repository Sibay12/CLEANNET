# CLEANNET Development Roadmap

## Phase 1 — Backend foundation
- [x] FastAPI application skeleton
- [x] MongoDB Atlas connection through environment variables
- [x] Health and readiness endpoints
- [x] Admin-key protected device inventory API
- [x] Unique device ID index
- [x] One-time claim token generation; store only token hash

## Phase 2 — Customer identity and device claiming
- Customer registration/login
- QR payload and one-time claim flow
- Atomic device claim and ownership validation
- Customer dashboard

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
