# scripts/seed_second_tenant.py
# Seeds a second tenant for cross-tenant isolation testing.
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

RAW_KEY_TENANT_2 = "axiosky_live_tenant2_test_key_do_not_use_in_production"


async def seed():
    async with AsyncSessionLocal() as db:
        t2 = Tenant(org_name="Rival Fintech Pvt Ltd", status="active", plan_tier="pilot")
        db.add(t2)
        await db.flush()
        key2 = ApiKey(
            tenant_id=t2.id,
            key_hash=hashlib.sha256(RAW_KEY_TENANT_2.encode()).hexdigest(),
        )
        db.add(key2)
        await db.commit()
        print(f"Tenant 2 id: {t2.id}")


asyncio.run(seed())
