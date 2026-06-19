# tests/test_audit_service.py
import pytest
import pytest_asyncio
from audit.service import AuditService, audit_service
from audit.models import AuditEntry
from database.session import AsyncSessionLocal
from database.models import AuditLog
from sqlalchemy import select, text
import uuid

# -- Helpers ----------------------------------------------------------------------
TEST_TENANT = 'test_audit_tenant'


def make_entry(status='APPROVE', agent_id='test_agent',
               action='loan_approval', env='shadow') -> AuditEntry:
    return AuditEntry(
        decision_id=str(uuid.uuid4()),
        tenant_id=TEST_TENANT,
        agent_id=agent_id,
        action_type=action,
        status=status,
        environment=env,
        reason=f'Test {status}',
        reason_code=f'TEST_{status}',
        rule_triggered=None,
        policy_version='test-v1',
        latency_ms=10,
    )


@pytest_asyncio.fixture(autouse=True)
async def clean_test_data():
    """Bypass immutable trigger using raw SQL to clean test data."""
    async with AsyncSessionLocal() as db:
        await db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_immutable"))
        await db.execute(text("DELETE FROM audit_log WHERE tenant_id = :t"), {"t": TEST_TENANT})
        await db.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_immutable"))
        await db.commit()
    yield
    async with AsyncSessionLocal() as db:
        await db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_immutable"))
        await db.execute(text("DELETE FROM audit_log WHERE tenant_id = :t"), {"t": TEST_TENANT})
        await db.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_immutable"))
        await db.commit()


# -- Hash helper tests ------------------------------------------------------------
@pytest.mark.asyncio
async def test_sha256_is_deterministic():
    svc = AuditService()
    h1 = svc._sha256({'amount': 60000000, 'currency': 'INR'})
    h2 = svc._sha256({'amount': 60000000, 'currency': 'INR'})
    assert h1 == h2
    assert len(h1) == 64


@pytest.mark.asyncio
async def test_sha256_different_inputs_different_hashes():
    svc = AuditService()
    h1 = svc._sha256({'amount': 60000000})
    h2 = svc._sha256({'amount': 70000000})
    assert h1 != h2


@pytest.mark.asyncio
async def test_sha256_key_order_does_not_matter():
    svc = AuditService()
    h1 = svc._sha256({'a': 1, 'b': 2})
    h2 = svc._sha256({'b': 2, 'a': 1})
    assert h1 == h2


# -- Database write tests ---------------------------------------------------------
@pytest.mark.asyncio
async def test_log_writes_entry_to_database():
    svc = AuditService()
    entry = make_entry(status='BLOCK')
    await svc._write_entry(entry, {'amount': 60000000})

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AuditLog).where(AuditLog.decision_id == entry.decision_id)
        )
        row = result.scalar_one_or_none()

    assert row is not None
    assert row.status == 'BLOCK'
    assert row.tenant_id == TEST_TENANT
    assert row.payload_hash != ''
    assert row.decision_hash != ''


@pytest.mark.asyncio
async def test_first_entry_has_no_previous_hash():
    svc = AuditService()
    entry = make_entry()
    await svc._write_entry(entry, {'amount': 1000})

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AuditLog).where(AuditLog.decision_id == entry.decision_id)
        )
        row = result.scalar_one()

    assert row.previous_hash is None


@pytest.mark.asyncio
async def test_second_entry_chains_to_first():
    svc = AuditService()
    entry1 = make_entry(status='BLOCK')
    entry2 = make_entry(status='APPROVE')
    await svc._write_entry(entry1, {'amount': 60000000})
    await svc._write_entry(entry2, {'amount': 1000000})

    async with AsyncSessionLocal() as db:
        r1 = (await db.execute(
            select(AuditLog).where(AuditLog.decision_id == entry1.decision_id)
        )).scalar_one()
        r2 = (await db.execute(
            select(AuditLog).where(AuditLog.decision_id == entry2.decision_id)
        )).scalar_one()

    assert r2.previous_hash == r1.decision_hash


# -- verify_chain tests -----------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_chain_empty_returns_intact():
    result = await audit_service.verify_chain(TEST_TENANT)
    assert result['chain_intact'] is True
    assert result['entries_checked'] == 0


@pytest.mark.asyncio
async def test_verify_chain_single_entry_intact():
    svc = AuditService()
    entry = make_entry()
    await svc._write_entry(entry, {'amount': 5000000})

    result = await audit_service.verify_chain(TEST_TENANT)
    assert result['chain_intact'] is True
    assert result['entries_checked'] == 1


@pytest.mark.asyncio
async def test_verify_chain_multiple_entries_intact():
    svc = AuditService()
    for status, amount in [('BLOCK', 60000000), ('APPROVE', 5000000), ('BLOCK', 70000000)]:
        await svc._write_entry(make_entry(status=status), {'amount': amount})

    result = await audit_service.verify_chain(TEST_TENANT)
    assert result['chain_intact'] is True
    assert result['entries_checked'] == 3


@pytest.mark.asyncio
async def test_verify_chain_detects_tampering():
    svc = AuditService()
    entry1 = make_entry(status='BLOCK')
    entry2 = make_entry(status='APPROVE')
    await svc._write_entry(entry1, {'amount': 60000000})
    await svc._write_entry(entry2, {'amount': 5000000})

    # Tamper: break the chain link directly via raw SQL (bypasses trigger)
    async with AsyncSessionLocal() as db:
        await db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_immutable"))
        await db.execute(
            text("UPDATE audit_log SET previous_hash = 'aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111' WHERE decision_id = :d"),
            {"d": entry2.decision_id}
        )
        await db.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_immutable"))
        await db.commit()

    result = await audit_service.verify_chain(TEST_TENANT)
    assert result['chain_intact'] is False
    assert 'broken_at_id' in result
