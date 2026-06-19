# auth/service.py
import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import ApiKey


class AuthService:
    """
    Handles API key validation and tenant resolution.
    Never stores raw API keys -- only SHA-256 hashes.
    """

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def generate_api_key() -> str:
        return f"axiosky_live_{secrets.token_hex(32)}"

    async def validate(self, raw_key: str, db: AsyncSession) -> dict:
        """
        Validate an API key and return tenant context.
        Returns: {'tenant_id': int, 'org_name': str, 'plan_tier': str}
        Raises HTTPException 401 if invalid or expired.

        All auth failures return the SAME generic message to prevent
        timing oracle attacks that could enumerate valid key hashes.
        """
        if raw_key.lower().startswith('bearer '):
            raw_key = raw_key[7:].strip()

        key_hash = self.hash_key(raw_key)

        stmt = select(ApiKey).where(ApiKey.key_hash == key_hash)
        result = await db.execute(stmt)
        api_key = result.scalar_one_or_none()

        auth_error = HTTPException(
            status_code=401,
            detail="Invalid or expired API key"
        )

        if not api_key:
            raise auth_error

        if api_key.expires_at and datetime.now(timezone.utc) > api_key.expires_at:
            raise auth_error

        if api_key.tenant.status not in ('active', 'trial'):
            raise auth_error

        return {
            'tenant_id': api_key.tenant_id,   # int -- matches Tenant.id
            'org_name': api_key.tenant.org_name,
            'plan_tier': api_key.tenant.plan_tier,
        }


auth_service = AuthService()
