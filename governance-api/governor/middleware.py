# governor/middleware.py
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth.service import auth_service
from database.session import AsyncSessionLocal

logger = logging.getLogger(__name__)

# Paths that do NOT require authentication
PUBLIC_PATHS = {'/health', '/docs', '/openapi.json', '/redoc'}


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Runs on every request.
    1. Skips public paths (health, docs) and CORS preflight OPTIONS.
    2. Extracts and validates the Bearer token.
    3. Injects tenant context into request.state.
    4. Returns 401 immediately if token is missing or invalid.
    """

    async def dispatch(self, request: Request, call_next):
        # Allow CORS preflight and exempt paths through without auth
        if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Extract Authorization header
        auth_header = request.headers.get('authorization') or \
                      request.headers.get('Authorization')

        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={'detail': 'Authorization header required'}
            )

        # Validate key and get tenant context
        try:
            async with AsyncSessionLocal() as db:
                tenant_ctx = await auth_service.validate(auth_header, db)
        except Exception as e:
            # Log full exception internally, return generic message to client
            logger.error("Auth middleware error: %s", e, exc_info=True)
            detail = getattr(e, 'detail', 'Authentication failed')
            status_code = getattr(e, 'status_code', 401)
            return JSONResponse(
                status_code=status_code,
                content={'detail': detail}
            )

        # Inject tenant context into request state
        request.state.tenant_id = tenant_ctx['tenant_id']
        request.state.org_name = tenant_ctx['org_name']
        request.state.plan_tier = tenant_ctx['plan_tier']

        return await call_next(request)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Adds a unique request ID to every request for traceability.
    Propagates via X-Request-ID header.
    """

    async def dispatch(self, request: Request, call_next):
        import uuid
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
