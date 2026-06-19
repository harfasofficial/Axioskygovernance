# governor/service.py
import asyncio
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, func

from audit.models import AuditEntry
from audit.service import audit_service
from context.resolver import context_resolver
from database.base_repo import TenantScopedRepo
from database.models import AuditLog, Escalation
from database.session import AsyncSessionLocal
from escalations.service import escalation_service
from governor.middleware import TenantMiddleware, RequestIDMiddleware
from policy_engine.engine import policy_engine
from policy_engine.loader import policy_loader
from reports.shadow_report import shadow_report

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
        import json
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        })


# Add JSON handler for production
_json_handler = logging.StreamHandler()
_json_handler.setFormatter(JSONFormatter())
logging.getLogger().addHandler(_json_handler)


# -- Background task tracking for audit logging ----------------------------------
_background_tasks: set = set()


def _audit_error_handler(task: asyncio.Task):
    """Callback that fires when an audit background task completes."""
    _background_tasks.discard(task)
    exc = task.exception()
    if exc:
        logger.critical(
            "AUDIT WRITE FAILED -- decision may be unlogged: %s", exc,
            extra={"request_id": getattr(task, "_request_id", None)}
        )


def schedule_audit_log(entry: AuditEntry, payload: dict, request_id: str = None):
    """Schedule audit logging as a tracked background task."""
    task = asyncio.create_task(audit_service.log(entry, payload))
    task._request_id = request_id
    _background_tasks.add(task)
    task.add_done_callback(_audit_error_handler)
    return task


# -- Redis client for rate limiting and idempotency ------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client: Optional[aioredis.Redis] = None

# -- Rate limiting configuration -------------------------------------------------
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))
RATE_WINDOW = 60
MAX_RATE_LIMIT_KEYS = 10_000

# In-memory fallback when Redis is unavailable
_rate_limit_store: OrderedDict = OrderedDict()


async def check_rate_limit(request: Request):
    """
    Check rate limit keyed by tenant_id (after auth) with Redis,
    falling back to in-memory OrderedDict if Redis is unavailable.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    auth = request.headers.get("authorization", "")

    # Extract key: prefer tenant_id, fall back to Bearer token or IP
    if tenant_id:
        key = f"tenant:{tenant_id}"
    elif auth:
        # Case-insensitive Bearer extraction
        auth = auth.strip()
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
        else:
            key = auth
    else:
        key = f"ip:{request.client.host if request.client else 'unknown'}"

    now = time.time()

    # Try Redis first
    if redis_client:
        try:
            window_key = f"rl:{key}:{int(now // RATE_WINDOW)}"
            pipe = redis_client.pipeline()
            pipe.incr(window_key)
            pipe.expire(window_key, RATE_WINDOW * 2)
            results = await pipe.execute()
            count = results[0]
            if count > RATE_LIMIT:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s",
                    headers={"Retry-After": str(RATE_WINDOW)},
                )
            return
        except aioredis.ConnectionError:
            pass  # Fall through to in-memory

    # In-memory fallback with LRU eviction
    global _rate_limit_store
    if key not in _rate_limit_store:
        if len(_rate_limit_store) >= MAX_RATE_LIMIT_KEYS:
            _rate_limit_store.popitem(last=False)
        _rate_limit_store[key] = []

    timestamps = _rate_limit_store[key]
    # Remove old entries
    timestamps = [t for t in timestamps if t > now - RATE_WINDOW]
    if len(timestamps) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s",
            headers={"Retry-After": str(RATE_WINDOW)},
        )
    timestamps.append(now)
    _rate_limit_store[key] = timestamps


# -- Idempotency key support via Redis -------------------------------------------
async def check_idempotency(key: str) -> Optional[dict]:
    """Check if an idempotency key has been seen recently. Returns cached response."""
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
    """Cache a response for idempotency key."""
    if not redis_client or not key:
        return
    try:
        await redis_client.setex(
            f"idempotency:{key}", ttl, json.dumps(response, default=str)
        )
    except aioredis.ConnectionError:
        pass


# -- Payload validation ----------------------------------------------------------
MAX_PAYLOAD_KEYS = 50
MAX_STRING_LENGTH = 1000
MAX_PAYLOAD_BYTES = 65536
MAX_CONTEXT_HOOKS = 5


def validate_payload(payload: dict) -> None:
    """Validate payload size and structure."""
    raw = json.dumps(payload)
    if len(raw.encode()) > MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=422,
            detail=f"Payload exceeds {MAX_PAYLOAD_BYTES} byte limit",
        )
    if len(payload) > MAX_PAYLOAD_KEYS:
        raise HTTPException(
            status_code=422,
            detail=f"Payload has too many keys (max {MAX_PAYLOAD_KEYS})",
        )
    for key, value in payload.items():
        if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
            raise HTTPException(
                status_code=422,
                detail=f"Field '{key}' exceeds {MAX_STRING_LENGTH} character limit",
            )


def parse_iso_date(value: Optional[str], param_name: str) -> Optional[str]:
    """Validate date parameter is ISO 8601 format."""
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


# -- Lifespan (startup/shutdown) -------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan: startup and shutdown events."""
    global redis_client

    # Startup
    logger.info("Axiosky Governor starting up...", extra={"version": "0.2.0"})

    # Initialize Redis connection
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning("Redis unavailable, using in-memory fallbacks: %s", e)
        redis_client = None

    # Pre-load policy templates into cache
    policy_loader.load_all_templates()
    logger.info("Policy templates loaded")

    # Start escalation expiry background worker
    expiry_task = asyncio.create_task(_expire_pending_escalations())

    yield

    # Shutdown
    logger.info("Axiosky Governor shutting down...")
    expiry_task.cancel()
    try:
        await expiry_task
    except asyncio.CancelledError:
        pass

    # Wait for background audit tasks
    if _background_tasks:
        pending = list(_background_tasks)
        logger.info("Waiting for %d pending audit tasks...", len(pending))
        await asyncio.gather(*pending, return_exceptions=True)

    if redis_client:
        await redis_client.close()


async def _expire_pending_escalations():
    """Background worker that periodically expires old escalations."""
    while True:
        await asyncio.sleep(60)  # Run every minute
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.now(timezone.utc)
                stmt = (
                    select(Escalation)
                    .where(
                        Escalation.status == "pending",
                        Escalation.expires_at <= now,
                    )
                )
                result = await db.execute(stmt)
                expired = result.scalars().all()

                for esc in expired:
                    esc.status = esc.action_on_expiry or "BLOCK"
                    esc.resolved_at = now
                    esc.resolved_by = "system_expiry"
                    logger.info(
                        "Escalation %s auto-resolved to %s (expired)",
                        esc.escalation_id, esc.status
                    )

                if expired:
                    await db.commit()
                    logger.info("Expired %d pending escalations", len(expired))
        except Exception as e:
            logger.error("Escalation expiry worker error: %s", e)


# -- App -------------------------------------------------------------------------
app = FastAPI(
    title="Axiosky Governor",
    version="0.2.0",
    description="AI Governance Control Plane -- Policy enforcement and audit for regulated AI deployments",
    lifespan=lifespan,
)

# -- CORS (environment-controlled) -----------------------------------------------
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
if os.getenv("ENVIRONMENT") == "production":
    # In production, don't allow wildcard
    if "*" in CORS_ORIGINS:
        CORS_ORIGINS.remove("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Idempotency-Key"],
    expose_headers=["X-Request-ID", "X-Decision-ID", "X-Request-Latency"],
    max_age=600,
)

# -- Middleware (order matters: RequestID first, then Tenant auth) ---------------
app.add_middleware(RequestIDMiddleware)
app.add_middleware(TenantMiddleware)


# -- Request / Response models ---------------------------------------------------
class ActionRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255)
    action_type: str = Field(..., min_length=1, max_length=255)
    timestamp: str = Field(..., min_length=1, max_length=50)
    tenant_id: str = Field(..., min_length=1, max_length=255)
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


class DecisionResponse(BaseModel):
    decision_id: str
    status: str
    timestamp: str
    latency_ms: int
    reason: str
    reason_code: str
    shadow_result: Optional[str] = None
    shadow_result_reason: Optional[str] = None
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


# -- Routes ----------------------------------------------------------------------
@app.get("/health")
async def health():
    """Health check endpoint."""
    redis_status = "ok"
    if redis_client:
        try:
            await redis_client.ping()
        except Exception:
            redis_status = "unavailable"

    return {
        "status": "ok",
        "service": "axiosky-governor",
        "version": "0.2.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "redis": redis_status,
    }


@app.post("/v1/evaluate", response_model=DecisionResponse)
async def evaluate(request: Request, req: ActionRequest):
    await check_rate_limit(request)
    start_ms = time.time() * 1000
    validated_tenant = request.state.tenant_id
    request_id = getattr(request.state, "request_id", None)

    if req.tenant_id != validated_tenant:
        raise HTTPException(
            status_code=403,
            detail="Payload tenant_id does not match API key tenant",
        )

    # Check idempotency key
    idempotency_key = request.headers.get("X-Idempotency-Key")
    if idempotency_key:
        cached = await check_idempotency(idempotency_key)
        if cached:
            return JSONResponse(content=cached)

    validate_payload(req.payload)

    # Validate context hooks count
    if req.context_hooks and len(req.context_hooks) > MAX_CONTEXT_HOOKS:
        raise HTTPException(
            status_code=422,
            detail=f"Too many context hooks: max {MAX_CONTEXT_HOOKS}",
        )

    decision_id = str(uuid.uuid4())

    # Resolve context hooks
    evaluation_payload = await context_resolver.resolve(
        context_hooks=req.context_hooks or {},
        payload=req.payload,
    )

    # Validate enriched payload hasn't exceeded limits
    validate_payload(evaluation_payload)

    # Load and evaluate policies
    templates = policy_loader.load_all_templates()
    rules = policy_loader.get_rules_for_action(req.action_type, templates)

    # Log warning if no rules found
    if not rules:
        logger.warning(
            "No rules found for action_type=%s -- defaulting to APPROVE",
            req.action_type,
            extra={"request_id": request_id}
        )

    eval_result = policy_engine.evaluate(
        action_type=req.action_type,
        payload=evaluation_payload,
        rules=rules,
    )

    # Handle escalation in production mode only
    escalation_id = None
    escalation_expires_minutes = None

    if (
        eval_result.status == "ESCALATE"
        and req.environment == "production"
        and getattr(eval_result, "escalation", None)
    ):
        webhook_url = req.metadata.get("escalation_webhook") if req.metadata else None

        escalation_id = await escalation_service.create(
            tenant_id=request.state.tenant_id,
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

    # Build response
    response = DecisionResponse(
        decision_id=decision_id,
        status="APPROVE" if req.environment == "shadow" else eval_result.status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        latency_ms=int(time.time() * 1000 - start_ms),
        reason=eval_result.reason,
        reason_code=eval_result.reason_code,
        shadow_result=eval_result.status if req.environment == "shadow" else None,
        shadow_result_reason=(
            f"In shadow mode, this would have been {eval_result.status}"
            if req.environment == "shadow" else None
        ),
        escalation_id=escalation_id,
        escalation_expires_minutes=escalation_expires_minutes,
        rule_triggered=eval_result.rule_triggered,
        policy_version=eval_result.policy_version,
    )

    # Build audit entry
    audit_entry = AuditEntry(
        decision_id=decision_id,
        tenant_id=request.state.tenant_id,
        agent_id=req.agent_id,
        action_type=req.action_type,
        status=eval_result.status,
        environment=req.environment,
        reason=eval_result.reason,
        reason_code=eval_result.reason_code,
        rule_triggered=eval_result.rule_triggered,
        policy_version=eval_result.policy_version,
        latency_ms=int(time.time() * 1000 - start_ms),
    )

    # Schedule tracked background audit log
    schedule_audit_log(audit_entry, req.payload, request_id)

    # Cache idempotency response
    if idempotency_key:
        await cache_idempotency(idempotency_key, response.model_dump())

    return JSONResponse(
        content=response.model_dump(),
        headers={"X-Decision-ID": decision_id},
    )


@app.post("/v1/audit-logs/verify")
async def verify_audit_chain(req: VerifyChainRequest, request: Request):
    await check_rate_limit(request)
    if req.tenant_id != request.state.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot verify another tenant chain",
        )

    start_date = parse_iso_date(req.start_date, "start_date")
    end_date = parse_iso_date(req.end_date, "end_date")

    return await audit_service.verify_chain(
        tenant_id=req.tenant_id,
        start_date=start_date,
        end_date=end_date,
    )


@app.get("/v1/audit-logs")
async def get_audit_logs(
    request: Request,
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    await check_rate_limit(request)
    tenant_id = request.state.tenant_id

    async with AsyncSessionLocal() as db:
        repo = TenantScopedRepo(tenant_id, db)
        entries = await repo.get_audit_log(
            limit=limit, offset=offset, status_filter=status, agent_id=agent_id
        )
        total = await repo.get_audit_log_count()

    return {
        "tenant_id": tenant_id,
        "total": total,
        "count": len(entries),
        "limit": limit,
        "offset": offset,
        "entries": [
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
            }
            for e in entries
        ],
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
async def list_pending_escalations(
    request: Request,
    status_filter: Optional[str] = Query(default="pending"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    await check_rate_limit(request)
    tenant_id = request.state.tenant_id

    async with AsyncSessionLocal() as db:
        repo = TenantScopedRepo(tenant_id, db)
        escalations = await repo.get_pending_escalations(limit=limit, offset=offset)

    return {
        "tenant_id": tenant_id,
        "pending_count": len(escalations),
        "limit": limit,
        "offset": offset,
        "escalations": [
            {
                "escalation_id": e.escalation_id,
                "decision_id": e.decision_id,
                "agent_id": e.agent_id,
                "action_type": e.action_type,
                "reason": e.reason,
                "reason_code": e.reason_code,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in escalations
        ],
    }


@app.post("/v1/escalations/{escalation_id}/approve")
async def approve_escalation(
    escalation_id: str,
    request: Request,
    body: EscalationResolutionBody,
):
    await check_rate_limit(request)

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

    return result


@app.post("/v1/escalations/{escalation_id}/reject")
async def reject_escalation(
    escalation_id: str,
    request: Request,
    body: EscalationResolutionBody,
):
    await check_rate_limit(request)

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

    return result
