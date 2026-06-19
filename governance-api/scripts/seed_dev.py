# scripts/seed_dev.py
# Run once to seed local dev database with a test tenant and API key.
# NEVER run this in production.
import asyncio
import hashlib
import os
import sys

# Production safety guard
if os.getenv("ENVIRONMENT") == "production":
    print("Cannot run seed script in production")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.session import AsyncSessionLocal
from database.models import Tenant, ApiKey


async def seed():
    raw_key = 'axiosky_live_dev_test_key_do_not_use_in_production'
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    async with AsyncSessionLocal() as db:
        # Create test tenant
        tenant = Tenant(
            org_name='Test Fintech Pvt Ltd',
            status='trial',
            plan_tier='pilot'
        )
        db.add(tenant)
        await db.flush()  # Get the auto-generated ID

        # Create API key for that tenant
        key = ApiKey(
            tenant_id=tenant.id,
            key_hash=key_hash,
            agent_scope=None,
            expires_at=None
        )
        db.add(key)
        await db.commit()

        print(f'Created tenant:  id={tenant.id}, org={tenant.org_name}')
        print(f'API key (raw):   {raw_key}')
        print(f'API key (hash):  {key_hash}')
        print()
        print('Use this in your test headers:')
        print(f'Authorization: Bearer {raw_key}')


asyncio.run(seed())
