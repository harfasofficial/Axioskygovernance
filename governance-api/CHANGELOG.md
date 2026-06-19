# Changelog

## [0.3.0] - 2026-06-19

### Security
- **CRITICAL FIX**: Removed hardcoded secret fallbacks from docker-compose.yml
- Added `startup_validator.py` -- crashes fast on insecure config in production
- Removed `python-jose` (CVE-2024-33664, CVE-2024-33663) -- was unused
- Removed `passlib[bcrypt]` -- was unused, dead attack surface
- Added `SecurityHeadersMiddleware` -- X-Frame-Options, X-Content-Type-Options, HSTS in production
- Gated `/docs`, `/redoc`, `/openapi.json` behind auth in production environment
- Added signed audit receipts (`receipt_signature`, `payload_hash`) on every decision response

### Bug Fixes
- **CRITICAL FIX**: Unknown `action_type` now defaults to BLOCK (was: APPROVE -- fail-open security hole)
- **FIX**: `status_filter` in `GET /v1/escalations` was silently ignored -- now properly applied
- **FIX**: `tenant_id` removed from `ActionRequest` body -- always derived from authenticated API key
- **FIX**: Latency calculated at single point -- response and audit log now use same value
- **FIX**: Escalation approve/reject now idempotency-key aware
- **FIX**: `get_audit_log_count()` now accepts date range filters (was: full table scan on every paginated request)

### Features
- Added `POST /v1/evaluate/batch` -- evaluate up to 100 actions in one round-trip
- Added `POST /v1/policies/simulate` -- test policy rules without writing to audit log
- Added `POST /v1/tenants` -- tenant provisioning API
- Added `POST /v1/tenants/{id}/api-keys` -- API key generation
- Added `DELETE /v1/tenants/{id}/api-keys/{key_id}` -- API key revocation
- Added `GET /v1/audit-logs/chain-status` -- real-time chain integrity status
- Added `shadow_would_escalate` field to decision responses (shadow mode)
- Added `payload_hash` and `receipt_signature` to all decision responses
- Added `any_of` (OR logic) support to policy engine rules
- Added `contains`, `starts_with`, `ends_with` operators to policy engine
- Added hourly audit chain integrity background monitor
- Added Prometheus metrics via `/metrics` (prometheus-fastapi-instrumentator)
- Added `gunicorn` + uvicorn workers (replaces `uvicorn --workers` -- proper process management)

### Architecture
- Standardized all list endpoint response envelopes: `{data, pagination, meta}`
- Separated migration from app startup (use `docker-compose run --rm migrate`)
- Upgraded PostgreSQL 14 → 16 in docker-compose
- Added `.gitignore` to prevent `__pycache__` and `.env` from being committed
- Added `.env.example` with all required variables documented
- Added date range filtering to `GET /v1/audit-logs`

## [0.2.0] - 2026-06-19

### Initial MVP
- Governor core: POST /v1/evaluate with shadow/production modes
- Policy engine with deterministic rule evaluation
- SHA-256 hash chain audit trail with verification
- Human-in-the-loop escalation workflow with HMAC-signed webhooks
- Multi-tenant isolation via TenantScopedRepo
- Redis-backed rate limiting with in-memory fallback
- Idempotency key support
- SSRF-protected context hooks resolver
- Per-tenant asyncio locks for audit chain writes
- Non-root Docker user, resource limits
- RBI Free AI v1 and DPDP v1 policy templates
