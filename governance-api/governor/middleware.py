# governor/middleware.py
import logging
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth.service import auth_service
from database.session import AsyncSessionLocal

logger = logging.getLogger(__name__)

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

BASE_PUBLIC_PATHS = {'/health'}
DEV_ONLY_PATHS = {'/docs', '/openapi.json', '/redoc'}

if ENVIRONMENT == "production":
    PUBLIC_PATHS = BASE_PUBLIC_PATHS
else:
    PUBLIC_PATHS = BASE_PUBLIC_PATHS | DEV_ONLY_PATHS


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class TenantMiddleware(BaseHTTPMiddleware):
    """
    Runs on every request.
    1. Skips public paths and CORS preflight OPTIONS.
    2. Extracts and validates the Bearer token.
    3. Injects integer tenant_id into request.state.
    4. Returns 401 with structured error envelope if auth fails.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        auth_header = request.headers.get('authorization') or request.headers.get('Authorization')

        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={
                    'error': {
                        'code': '401',
                        'message': 'Authorization header required',
                        'request_id': getattr(request.state, 'request_id', None),
                    }
                }
            )

        try:
            async with AsyncSessionLocal() as db:
                tenant_ctx = await auth_service.validate(auth_header, db)
        except Exception as e:
            logger.error("Auth middleware error: %s", e, exc_info=True)
            detail = getattr(e, 'detail', 'Authentication failed')
            status_code = getattr(e, 'status_code', 401)
            return JSONResponse(
                status_code=status_code,
                content={
                    'error': {
                        'code': str(status_code),
                        'message': detail,
                        'request_id': getattr(request.state, 'request_id', None),
                    }
                }
            )

        request.state.tenant_id = tenant_ctx['tenant_id']  # int
        request.state.org_name = tenant_ctx['org_name']
        request.state.plan_tier = tenant_ctx['plan_tier']

        return await call_next(request)


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import uuid
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
