#!/usr/bin/env python3
"""
provision_tenant.py -- Create a new pilot tenant and API key.

Usage:
    python scripts/provision_tenant.py "Rajagiri Bank Pvt Ltd" [--plan-tier pilot]

Output:
    Tenant ID: 3
    API Key:   axiosky_live_a1b2c3d4...  <- give this to the client

Never share the database directly. Use this script only.
"""
import argparse
import asyncio
import hashlib
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.session import AsyncSessionLocal
from database.models import Tenant, ApiKey


def generate_api_key() -> str:
    """Generate a new cryptographically secure API key."""
    return f"axiosky_live_{secrets.token_hex(32)}"


def hash_key(raw_key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def provision(org_name: str, plan_tier: str = "pilot") -> None:
    raw_key = generate_api_key()
    key_hash = hash_key(raw_key)

    async with AsyncSessionLocal() as db:
        tenant = Tenant(org_name=org_name, status="trial", plan_tier=plan_tier)
        db.add(tenant)
        await db.flush()

        key = ApiKey(tenant_id=tenant.id, key_hash=key_hash, expires_at=None)
        db.add(key)
        await db.commit()

        print(f"\nTenant created")
        print(f"   Org Name:  {tenant.org_name}")
        print(f"   Tenant ID: {tenant.id}")
        print(f"\nAPI Key generated")
        print(f"   Key (give to client): {raw_key}")
        print(f"\n! This key is shown ONCE. Store it securely.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Provision a new tenant and API key")
    parser.add_argument("org_name", help="Organization name")
    parser.add_argument("--plan-tier", default="pilot", help="Plan tier (default: pilot)")
    args = parser.parse_args()

    asyncio.run(provision(args.org_name, args.plan_tier))
