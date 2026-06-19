# governor/service.py
import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from audit.models import AuditEntry
from audit.service import audit_service
from context.resolver import context_resolver
from database.base_repo import TenantScopedRepo
from database.models import AuditLog, Escalation, Tenant, ApiKey
from database.session import AsyncSessionLocal
from escalations.service import escalation_service
from governor.middleware import TenantMiddleware, RequestIDMiddleware, SecurityHeadersMiddleware
from metrics import setup_metrics
from policy_engine.engine import policy_engine
from policy_engine.loader import policy_loader
from reports.shadow_report import shadow_report
from startup_validator import validate_secrets

# -- Run startup secret validation immediately -----------------------------------
validate_secrets()

# -- Logging configuration -------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


# -- Structured JSON logging for SIEM integration --------------------------------
class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        })


_json_handler = logging.StreamHandler()
_json_handler.setFormatter(JSONFormatter())
logging.getLogger().addHandler(_json_handler)


def get_request_logger(request_id: Optional[str]) -> logging.LoggerAdapter:
    return logging.LoggerAdapter(
        logger,
        extra={"request_id": request_id or ""},
    )


# -- Background task tracking for audit logging ----------------------------------
_background_tasks: set = set()


def _audit_error_handler(task: asyncio.Task):
    _background_tasks.discard(task)
    exc = task.exception()
    if exc:
        logger.critical(
            "AUDIT WRITE FAILED -- decision may be unlogged: %s", exc,
            extra={"request_id": getattr(task, "_request_id", None)}
        )


def schedule_audit_log(entry: AuditEntry, payload: dict, request_id: str = None):
    task = asyncio.create_task(audit_service.log(entry, payload))
    task._request_id = request_id
    _background_tasks.add(task)
    task.add_done_callback(_audit_error_handler)
    return task


# -- Receipt signing -------------------------------------------------------------
def _sign_receipt(decision_id: str, tenant_id: str, status: str,
                  timestamp: str, payload_hash: str) -> str:
    secret = os.getenv("SECRET_KEY", "")
    data = f"{decision_id}:{tenant_id}:{status}:{timestamp}:{payload_hash}"
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()


# -- Admin authentication --------------------------------------------------------
def _require_admin(request: Request) -> None:
    admin_secret = os.getenv("ADMIN_SECRET", "")
    if not admin_secret:
        raise HTTPException(
            status_code=503,
            detail="Admin operations are not configured on this instance.",
        )
    provided = request.headers.get("X-Admin-Secret", "")
    if not hmac.compare_digest(admin_secret.encode(), provided.encode()):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing admin secret.",
        )


# -- Redis client ----------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client: Optional[aioredis.Redis] = None

# -- Rate limiting ---------------------------------------------------------------
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))
RATE_WINDOW = 60
MAX_RATE_LIMIT_KEYS = 10_000

_rate_limit_store: OrderedDict = OrderedDict()
_rate_limit_lock: asyncio.Lock = asyncio.Lock()


def _get_client_ip(request: Request) -> str:
    """Extract real client IP from X-Forwarded-For when behind a reverse proxy."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def check_rate_limit(request: Request, batch_size: int = 1):
    """
    Rate-limit by tenant_id (preferred) or real client IP (fallback).
    batch_size > 1 counts the batch as multiple requests so batch
    callers cannot bypass the per-minute limit.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    key = f"tenant:{tenant_id}" if tenant_id else f"ip:{_get_client_ip(request)}"
    now = time.time()

    if redis_client:
        try:
            window_key = f"rl:{key}:{int(now // RATE_WINDOW)}"
            pipe = redis_client.pipeline()
            pipe.incrby(window_key, batch_size)
            pipe.expire(window_key, RATE_WINDOW * 2)
            results = await pipe.execute()
            if results[0] > RATE_LIMIT:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s",
                    headers={"Retry-After": str(RATE_WINDOW)},
                )
            return
        except aioredis.ConnectionError:
            pass

    async with _rate_limit_lock:
        if key not in _rate_limit_store:
            if len(_rate_limit_store) >= MAX_RATE_LIMIT_KEYS:
                _rate_limit_store.popitem(last=False)
            _rate_limit_store[key] = []

        timestamps = [t for t in _rate_limit_store[key] if t > now - RATE_WINDOW]
        if len(timestamps) + batch_size - 1 >= RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s",
                headers={"Retry-After": str(RATE_WINDOW)},
            )
        timestamps.extend([now] * batch_size)
        _rate_limit_store[key] = timestamps


# -- Idempotency -----------------------------------------------------------------
async def check_idempotency(key: str) -> Optional[dict]:
    if not redis_client or not key:
        return None
    try:
        cached = await redis_client.get(f"idempotency:{key}")
        if cached:
            return json.loads(cached)
    except aioredis.ConnectionError:
        pass
    return None


async def cache_idempotency(key: str, response: dict, ttl: int = 60):
    if not redis_client or not key:
        return
    try:
        await redis_client.setex(f"idempotency:{key}", ttl, json.dumps(response, default=str))
    except aioredis.ConnectionError:
        pass


# -- Payload validation ----------------------------------------------------------
MAX_PAYLOAD_KEYS = 50
MAX_STRING_LENGTH = 1000
MAX_PAYLOAD_BYTES = 65536
MAX_CONTEXT_HOOKS = 5


def validate_payload(payload: dict) -> None:
    raw = json.dumps(payload)
    if len(raw.encode()) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=422, detail=f"Payload exceeds {MAX_PAYLOAD_BYTES} byte limit")
    if len(payload) > MAX_PAYLOAD_KEYS:
        raise HTTPException(status_code=422, detail=f"Payload has too many keys (max {MAX_PAYLOAD_KEYS})")
    for key, value in payload.items():
        if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
            raise HTTPException(status_code=422, detail=f"Field '{key}' exceeds {MAX_STRING_LENGTH} character limit")


def parse_iso_date(value: Optional[str], param_name: str) -> Optional[str]:
    if value is None:
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"{param_name} must be ISO 8601 format (e.g., 2026-01-01T00:00:00Z)"
        )


# -- Standard error envelope -----------------------------------------------------
class APIError(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None


class APIErrorResponse(BaseModel):
    error: APIError


# -- Lifespan --------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client

    logger.info("Axiosky Governor starting up...", extra={"request_id": ""})

    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        logger.info("Redis connection established", extra={"request_id": ""})
    except Exception as e:
        logger.warning("Redis unavailable, using in-memory fallbacks: %s", e, extra={"request_id": ""})
        redis_client = None

    policy_loader.load_all_templates()
    logger.info("Policy templates loaded", extra={"request_id": ""})

    expiry_task = asyncio.create_task(_expire_pending_escalations())
    chain_monitor_task = asyncio.create_task(_chain_integrity_monitor())

    yield

    logger.info("Axiosky Governor shutting down...", extra={"request_id": ""})
    expiry_task.cancel()
    chain_monitor_task.cancel()
    for t in (expiry_task, chain_monitor_task):
        try:
            await t
        except asyncio.CancelledError:
            pass

    if _background_tasks:
        pending = list(_background_tasks)
        logger.info("Waiting for %d pending audit tasks...", len(pending), extra={"request_id": ""})
        await asyncio.gather(*pending, return_exceptions=True)

    if redis_client:
        await redis_client.close()


async def _expire_pending_escalations():
    while True:
        await asyncio.sleep(60)
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.now(timezone.utc)
                stmt = select(Escalation).where(
                    Escalation.status == "pending",
                    Escalation.expires_at <= now,
                )
                result = await db.execute(stmt)
                expired = result.scalars().all()

                for esc in expired:
                    esc.status = esc.action_on_expiry or "BLOCK"
                    esc.resolved_at = now
                    esc.resolved_by = "system_expiry"
                    logger.info(
                        "Escalation %s auto-resolved to %s (expired)",
                        esc.escalation_id, esc.status,
                        extra={"request_id": ""},
                    )

                if expired:
                    await db.commit()
                    logger.info(
                        "Expired %d pending escalations", len(expired),
                        extra={"request_id": ""},
                    )
        except Exception as e:
            logger.error("Escalation expiry worker error: %s", e, extra={"request_id": ""})


async def _chain_integrity_monitor():
    """Background job: verify audit chain every hour."""
    while True:
        await asyncio.sleep(3600)
        try:
            async with AsyncSessionLocal() as db:
                stmt = select(AuditLog.tenant_id).distinct()
                result = await db.execute(stmt)
                tenant_ids = [row[0] for row in result.fetchall()]

            for tenant_id in tenant_ids:
                result = await audit_service.verify_chain(tenant_id)
                if not result.get("chain_intact", True):
                    logger.critical(
                        "AUDIT CHAIN BROKEN for tenant=%s broken_at=%s detail=%s",
                        tenant_id,
                        result.get("broken_at_time"),
                        result.get("detail"),
                        extra={"request_id": ""},
                    )
                else:
                    logger.info(
                        "Chain OK for tenant=%s entries_checked=%s",
                        tenant_id,
                        result.get("entries_checked", 0),
                        extra={"request_id": ""},
                    )
                # Yield control so other coroutines are not starved
                await asyncio.sleep(0)
        except Exception as e:
            logger.error("Chain integrity monitor error: %s", e, extra={"request_id": ""})


# -- App -------------------------------------------------------------------------
app = FastAPI(
    title="Axiosky Governor",
    version="0.3.0",
    description="AI Governance Control Plane -- Policy enforcement and audit for regulated AI deployments",
    lifespan=lifespan,
    responses={
        401: {"description": "Unauthorized -- missing or invalid API key"},
        403: {"description": "Forbidden -- tenant mismatch or invalid admin secret"},
        422: {"description": "Validation error"},
        429: {"description": "Rate limit exceeded"},
    },
)

setup_metrics(app)

# -- CORS -- X-Admin-Secret intentionally excluded from allow_headers -----------
# Admin endpoints are server-to-server only; browsers must never carry the
# admin secret. Removing it from CORS prevents XSS-based admin secret theft.
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
if os.getenv("ENVIRONMENT") == "production" and "*" in CORS_ORIGINS:
    CORS_ORIGINS.remove("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Idempotency-Key"],
    expose_headers=["X-Request-ID", "X-Decision-ID", "X-Request-Latency"],
    max_age=600,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(TenantMiddleware)


# -- Global HTTP exception handler: standard error envelope ----------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": str(exc.status_code),
                "message": exc.detail,
                "request_id": request_id,
            }
        },
        headers=getattr(exc, "headers", None),
    )


# -- Request / Response models ---------------------------------------------------
class ActionRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255)
    action_type: str = Field(..., min_length=1, max_length=255)
    timestamp: str = Field(..., min_length=1, max_length=50)
    environment: str = Field(default="shadow")
    payload: Dict[str, Any]
    context_hooks: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        if v not in ("shadow", "production"):
            raise ValueError("environment must be shadow or production")
        return v


class BatchActionRequest(BaseModel):
    actions: List[ActionRequest] = Field(..., min_length=1, max_length=100)


class DecisionResponse(BaseModel):
    decision_id: str
    status: str
    timestamp: str
    latency_ms: int
    reason: str
    reason_code: str
    payload_hash: str
    receipt_signature: str
    shadow_result: Optional[str] = None
    shadow_result_reason: Optional[str] = None
    shadow_would_escalate: Optional[bool] = None
    escalation_id: Optional[str] = None
    escalation_expires_minutes: Optional[int] = None
    rule_triggered: Optional[str] = None
    policy_version: Optional[str] = None


class VerifyChainRequest(BaseModel):
    tenant_id: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class EscalationResolutionBody(BaseModel):
    resolved_by: str = Field(..., min_length=1, max_length=255)


class PolicySimulateRequest(BaseModel):
    action_type: str = Field(..., min_length=1, max_length=255)
    payload: Dict[str, Any]
    context_hooks: Optional[Dict[str, str]] = None


class TenantCreateRequest(BaseModel):
    org_name: str = Field(..., min_length=1, max_length=255)
    plan_tier: str = Field(default="pilot")


class ApiKeyCreateRequest(BaseModel):
    expires_days: Optional[int] = Field(default=None, ge=1, le=3650)


# -- Helper: build a single decision ---------------------------------------------
async def _make_decision(
    req: ActionRequest,
    tenant_id: str,
    request_id: Optional[str] = None,
) -> dict:
    log = get_request_logger(request_id)
    start_ms = time.time() * 1000

    validate_payload(req.payload)

    if req.context_hooks and len(req.context_hooks) > MAX_CONTEXT_HOOKS:
        raise HTTPException(status_code=422, detail=f"Too many context hooks: max {MAX_CONTEXT_HOOKS}")

    decision_id = str(uuid.uuid4())

    log.debug(
        "Evaluating: agent_id=%s action_type=%s environment=%s",
        req.agent_id, req.action_type, req.environment,
    )

    evaluation_payload = await context_resolver.resolve(
        context_hooks=req.context_hooks or {},
        payload=req.payload,
    )
    validate_payload(evaluation_payload)

    templates = policy_loader.load_all_templates()
    rules = policy_loader.get_rules_for_action(req.action_type, templates)

    if not rules:
        log.warning(
            "No rules found for action_type=%s -- BLOCKING (fail-closed)",
            req.action_type,
        )
        from policy_engine.models import PolicyResult
        eval_result = PolicyResult(
            status="BLOCK",
            rule_triggered=None,
            rules_evaluated=[],
            reason="No policy defined for this action type",
            reason_code="NO_POLICY_DEFINED",
            policy_version="none",
        )
    else:
        eval_result = policy_engine.evaluate(
            action_type=req.action_type,
            payload=evaluation_payload,
            rules=rules,
        )

    escalation_id = None
    escalation_expires_minutes = None
    shadow_would_escalate = None

    if req.environment == "shadow":
        shadow_would_escalate = (eval_result.status == "ESCALATE")

    if (
        eval_result.status == "ESCALATE"
        and req.environment == "production"
        and getattr(eval_result, "escalation", None)
    ):
        webhook_url = req.metadata.get("escalation_webhook") if req.metadata else None
        escalation_id = await escalation_service.create(
            tenant_id=tenant_id,
            decision_id=decision_id,
            agent_id=req.agent_id,
            action_type=req.action_type,
            reason=eval_result.reason,
            reason_code=eval_result.reason_code,
            rule_triggered=eval_result.rule_triggered,
            config=eval_result.escalation,
            webhook_url=webhook_url,
            action_on_expiry=eval_result.escalation.action_on_expiry,
        )
        escalation_expires_minutes = eval_result.escalation.expires_minutes

    latency_ms = int(time.time() * 1000 - start_ms)

    payload_hash = hashlib.sha256(
        json.dumps(req.payload, sort_keys=True, default=str).encode()
    ).hexdigest()
    now_ts = datetime.now(timezone.utc).isoformat()
    receipt_signature = _sign_receipt(decision_id, tenant_id, eval_result.status, now_ts, payload_hash)

    log.info(
        "Decision: action_type=%s status=%s latency_ms=%d decision_id=%s",
        req.action_type, eval_result.status, latency_ms, decision_id,
    )

    response = DecisionResponse(
        decision_id=decision_id,
        status="APPROVE" if req.environment == "shadow" else eval_result.status,
        timestamp=now_ts,
        latency_ms=latency_ms,
        reason=eval_result.reason,
        reason_code=eval_result.reason_code,
        payload_hash=payload_hash,
        receipt_signature=receipt_signature,
        shadow_result=eval_result.status if req.environment == "shadow" else None,
        shadow_result_reason=(
            f"In shadow mode, this would have been {eval_result.status}"
            if req.environment == "shadow" else None
        ),
        shadow_would_escalate=shadow_would_escalate,
        escalation_id=escalation_id,
        escalation_expires_minutes=escalation_expires_minutes,
        rule_triggered=eval_result.rule_triggered,
        policy_version=eval_result.policy_version,
    )

    audit_entry = AuditEntry(
        decision_id=decision_id,
        tenant_id=tenant_id,
        agent_id=req.agent_id,
        action_type=req.action_type,
        status=eval_result.status,
        environment=req.environment,
        reason=eval_result.reason,
        reason_code=eval_result.reason_code,
        rule_triggered=eval_result.rule_triggered,
        policy_version=eval_result.policy_version,
        latency_ms=latency_ms,
    )

    schedule_audit_log(audit_entry, req.payload, request_id)

    return response.model_dump(), decision_id


# -- Routes ----------------------------------------------------------------------
@app.get("/health")
async def health():
    redis_status = "ok"
    if redis_client:
        try:
            await redis_client.ping()
        except Exception:
            redis_status = "unavailable"

    db_status = "ok"
    try:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import text
            await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    overall = "ok" if redis_status == "ok" and db_status == "ok" else "degraded"
    return {
        "status": overall,
        "service": "axiosky-governor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "redis": redis_status,
        "database": db_status,
    }


@app.post("/v1/evaluate", response_model=DecisionResponse)
async def evaluate(request: Request, req: ActionRequest):
    await check_rate_limit(request)
    tenant_id = request.state.tenant_id
    request_id = getattr(request.state, "request_id", None)

    idempotency_key = request.headers.get("X-Idempotency-Key")
    if idempotency_key:
        cached = await check_idempotency(idempotency_key)
        if cached:
            return JSONResponse(content=cached)

    response_data, decision_id = await _make_decision(req, tenant_id, request_id)

    if idempotency_key:
        await cache_idempotency(idempotency_key, response_data)

    return JSONResponse(
        content=response_data,
        headers={"X-Decision-ID": decision_id},
    )


@app.post("/v1/evaluate/batch")
async def evaluate_batch(request: Request, req: BatchActionRequest):
    """Evaluate up to 100 actions in a single request."""
    batch_size = len(req.actions)
    await check_rate_limit(request, batch_size=batch_size)
    tenant_id = request.state.tenant_id
    request_id = getattr(request.state, "request_id", None)
    log = get_request_logger(request_id)

    results = []
    for action in req.actions:
        try:
            response_data, decision_id = await _make_decision(action, tenant_id, request_id)
            results.append({"success": True, "decision": response_data})
        except HTTPException as e:
            results.append({"success": False, "error": e.detail, "agent_id": action.agent_id})
        except Exception as e:
            log.error("Batch decision error for agent=%s: %s", action.agent_id, e)
            results.append({"success": False, "error": "Internal evaluation error", "agent_id": action.agent_id})

    return {
        "batch_size": batch_size,
        "processed": len(results),
        "results": results,
    }


@app.post("/v1/policies/simulate")
async def simulate_policy(request: Request, req: PolicySimulateRequest):
    """
    Simulate a policy evaluation without writing to the audit log.
    Optionally resolves context_hooks to mirror production evaluation.
    """
    await check_rate_limit(request)
    validate_payload(req.payload)

    simulation_payload = req.payload
    if req.context_hooks:
        simulation_payload = await context_resolver.resolve(
            context_hooks=req.context_hooks,
            payload=req.payload,
        )

    templates = policy_loader.load_all_templates()
    rules = policy_loader.get_rules_for_action(req.action_type, templates)

    if not rules:
        return {
            "simulated": True,
            "action_type": req.action_type,
            "result": {
                "status": "BLOCK",
                "reason": "No policy defined for this action type",
                "reason_code": "NO_POLICY_DEFINED",
                "rule_triggered": None,
                "policy_version": "none",
            },
            "rules_evaluated": 0,
            "warning": "No rules found for this action type. Would be BLOCKED in production.",
        }

    eval_result = policy_engine.evaluate(
        action_type=req.action_type,
        payload=simulation_payload,
        rules=rules,
    )

    return {
        "simulated": True,
        "action_type": req.action_type,
        "result": {
            "status": eval_result.status,
            "reason": eval_result.reason,
            "reason_code": eval_result.reason_code,
            "rule_triggered": eval_result.rule_triggered,
            "policy_version": eval_result.policy_version,
        },
        "rules_evaluated": len(eval_result.rules_evaluated),
    }


@app.get("/v1/audit-logs/verify")
async def verify_audit_chain(
    request: Request,
    tenant_id: str = Query(...),
    start_date: Optional[str] = Query(default=None),
    end_date: Optional[str] = Query(default=None),
):
    """Verify the integrity of the audit chain. GET with query params."""
    await check_rate_limit(request)
    if tenant_id != request.state.tenant_id:
        raise HTTPException(status_code=403, detail="Cannot verify another tenant chain")

    start_date = parse_iso_date(start_date, "start_date")
    end_date = parse_iso_date(end_date, "end_date")

    return await audit_service.verify_chain(
        tenant_id=tenant_id,
        start_date=start_date,
        end_date=end_date,
    )


@app.get("/v1/audit-logs/chain-status")
async def audit_chain_status(request: Request):
    """Returns the current chain integrity status and last verified timestamp."""
    await check_rate_limit(request)
    tenant_id = request.state.tenant_id

    result = await audit_service.verify_chain(tenant_id)
    return {
        "tenant_id": tenant_id,
        "chain_intact": result.get("chain_intact", True),
        "entries_checked": result.get("entries_checked", 0),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "detail": result.get("detail"),
    }


@app.get("/v1/audit-logs")
async def get_audit_logs(
    request: Request,
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    await check_rate_limit(request)
    tenant_id = request.state.tenant_id

    start_date = parse_iso_date(start_date, "start_date")
    end_date = parse_iso_date(end_date, "end_date")

    async with AsyncSessionLocal() as db:
        repo = TenantScopedRepo(tenant_id, db)
        entries = await repo.get_audit_log(
            limit=limit, offset=offset, status_filter=status, agent_id=agent_id,
            start_date=start_date, end_date=end_date,
        )
        total = await repo.get_audit_log_count(start_date=start_date, end_date=end_date)

    return {
        "data": [
            {
                "decision_id": e.decision_id,
                "agent_id": e.agent_id,
                "action_type": e.action_type,
                "status": e.status,
                "environment": e.environment,
                "reason": e.reason,
                "reason_code": e.reason_code,
                "rule_triggered": e.rule_triggered,
                "latency_ms": e.latency_ms,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "decision_hash": e.decision_hash,
                "previous_hash": e.previous_hash,
                "payload_hash": e.payload_hash,
            }
            for e in entries
        ],
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total,
        },
        "meta": {"tenant_id": tenant_id},
    }


@app.get("/v1/reports/shadow")
async def get_shadow_report(
    request: Request,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    await check_rate_limit(request)
    start_date = parse_iso_date(start_date, "start_date")
    end_date = parse_iso_date(end_date, "end_date")

    return await shadow_report.generate(
        tenant_id=request.state.tenant_id,
        start_date=start_date,
        end_date=end_date,
    )


@app.get("/v1/escalations")
async def list_escalations(
    request: Request,
    status_filter: Optional[str] = Query(default="pending"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    await check_rate_limit(request)
    tenant_id = request.state.tenant_id

    async with AsyncSessionLocal() as db:
        repo = TenantScopedRepo(tenant_id, db)
        escalations = await repo.get_escalations(
            limit=limit, offset=offset, status_filter=status_filter
        )
        total = await repo.get_escalations_count(status_filter=status_filter)

    return {
        "data": [
            {
                "escalation_id": e.escalation_id,
                "decision_id": e.decision_id,
                "agent_id": e.agent_id,
                "action_type": e.action_type,
                "reason": e.reason,
                "reason_code": e.reason_code,
                "status": e.status,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in escalations
        ],
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total,
        },
        "meta": {"tenant_id": tenant_id, "status_filter": status_filter},
    }


@app.post("/v1/escalations/{escalation_id}/approve")
async def approve_escalation(escalation_id: str, request: Request, body: EscalationResolutionBody):
    await check_rate_limit(request)

    idempotency_key = request.headers.get("X-Idempotency-Key")
    if idempotency_key:
        cached = await check_idempotency(f"esc:{idempotency_key}")
        if cached:
            return JSONResponse(content=cached)

    result = await escalation_service.resolve(
        escalation_id=escalation_id,
        tenant_id=request.state.tenant_id,
        human_decision="approved",
        resolved_by=body.resolved_by,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    human_entry = AuditEntry(
        decision_id=str(uuid.uuid4()),
        tenant_id=request.state.tenant_id,
        agent_id="human_reviewer",
        action_type="escalation_resolution",
        status="APPROVE",
        environment="production",
        reason=f"Escalation {escalation_id} approved by {body.resolved_by}",
        reason_code="HUMAN_APPROVED",
        rule_triggered=None,
        policy_version="human",
        latency_ms=0,
    )
    schedule_audit_log(
        human_entry,
        {"escalation_id": escalation_id, "resolved_by": body.resolved_by},
        getattr(request.state, "request_id", None),
    )

    if idempotency_key:
        await cache_idempotency(f"esc:{idempotency_key}", result)

    return result


@app.post("/v1/escalations/{escalation_id}/reject")
async def reject_escalation(escalation_id: str, request: Request, body: EscalationResolutionBody):
    await check_rate_limit(request)

    idempotency_key = request.headers.get("X-Idempotency-Key")
    if idempotency_key:
        cached = await check_idempotency(f"esc:{idempotency_key}")
        if cached:
            return JSONResponse(content=cached)

    result = await escalation_service.resolve(
        escalation_id=escalation_id,
        tenant_id=request.state.tenant_id,
        human_decision="rejected",
        resolved_by=body.resolved_by,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    human_entry = AuditEntry(
        decision_id=str(uuid.uuid4()),
        tenant_id=request.state.tenant_id,
        agent_id="human_reviewer",
        action_type="escalation_resolution",
        status="BLOCK",
        environment="production",
        reason=f"Escalation {escalation_id} rejected by {body.resolved_by}",
        reason_code="HUMAN_REJECTED",
        rule_triggered=None,
        policy_version="human",
        latency_ms=0,
    )
    schedule_audit_log(
        human_entry,
        {"escalation_id": escalation_id, "resolved_by": body.resolved_by},
        getattr(request.state, "request_id", None),
    )

    if idempotency_key:
        await cache_idempotency(f"esc:{idempotency_key}", result)

    return result


# -- Admin-Only: Tenant Provisioning ---------------------------------------------
@app.post("/v1/tenants", status_code=201)
async def create_tenant(request: Request, body: TenantCreateRequest):
    _require_admin(request)
    await check_rate_limit(request)
    log = get_request_logger(getattr(request.state, "request_id", None))

    async with AsyncSessionLocal() as db:
        tenant = Tenant(
            org_name=body.org_name,
            plan_tier=body.plan_tier,
            status="trial",
        )
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)

    log.info("Tenant created: org=%s id=%s", tenant.org_name, tenant.id)

    return {
        "tenant_id": str(tenant.id),
        "org_name": tenant.org_name,
        "plan_tier": tenant.plan_tier,
        "status": tenant.status,
        "created_at": tenant.created_at.isoformat(),
    }


@app.post("/v1/tenants/{tenant_id}/api-keys", status_code=201)
async def create_api_key(tenant_id: str, request: Request, body: ApiKeyCreateRequest):
    from datetime import timedelta
    from auth.service import auth_service as _auth

    _require_admin(request)
    await check_rate_limit(request)
    log = get_request_logger(getattr(request.state, "request_id", None))

    raw_key = _auth.generate_api_key()
    key_hash = _auth.hash_key(raw_key)

    expires_at = None
    if body.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    async with AsyncSessionLocal() as db:
        stmt = select(Tenant).where(Tenant.id == int(tenant_id))
        result = await db.execute(stmt)
        tenant = result.scalar_one_or_none()
        if not tenant:
            # Return 400 not 404 to avoid tenant ID enumeration
            raise HTTPException(status_code=400, detail="Invalid tenant ID")

        api_key = ApiKey(
            tenant_id=int(tenant_id),
            key_hash=key_hash,
            expires_at=expires_at,
        )
        db.add(api_key)
        await db.commit()
        await db.refresh(api_key)

    log.info("API key created for tenant_id=%s key_id=%s", tenant_id, api_key.id)

    return {
        "key_id": api_key.id,
        "api_key": raw_key,
        "tenant_id": tenant_id,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "warning": "This API key will not be shown again. Store it securely.",
    }


@app.delete("/v1/tenants/{tenant_id}/api-keys/{key_id}", status_code=200)
async def revoke_api_key(tenant_id: str, key_id: int, request: Request):
    _require_admin(request)
    await check_rate_limit(request)
    log = get_request_logger(getattr(request.state, "request_id", None))

    async with AsyncSessionLocal() as db:
        stmt = select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.tenant_id == int(tenant_id),
        )
        result = await db.execute(stmt)
        key = result.scalar_one_or_none()

        if not key:
            raise HTTPException(status_code=404, detail="API key not found")

        await db.delete(key)
        await db.commit()

    log.info("API key revoked: key_id=%s tenant_id=%s", key_id, tenant_id)
    return {"revoked": True, "key_id": key_id, "tenant_id": tenant_id}
