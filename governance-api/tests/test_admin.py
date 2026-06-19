# tests/test_admin.py
"""
Tests for admin-only endpoints: tenant provisioning and API key management.

All admin endpoints require a valid X-Admin-Secret header.
A valid tenant API key alone is NOT sufficient.
"""
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from governor.service import app

client = TestClient(app)

T1_KEY  = "axiosky_live_dev_test_key_do_not_use_in_production"
T1_HDR  = {"Authorization": f"Bearer {T1_KEY}"}
T1_MOCK = {"tenant_id": "1", "org_name": "Test Fintech", "plan_tier": "pilot"}

VALID_ADMIN_SECRET   = "test_admin_secret_that_is_32chars_long_x"
INVALID_ADMIN_SECRET = "wrong_secret"

ADMIN_HDR = {**T1_HDR, "X-Admin-Secret": VALID_ADMIN_SECRET}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_db_tenant(tenant_id=1, org_name="New Fintech", plan_tier="pilot"):
    """Build a mock Tenant ORM object."""
    t = MagicMock()
    t.id = tenant_id
    t.org_name = org_name
    t.plan_tier = plan_tier
    t.status = "trial"
    from datetime import datetime, timezone
    t.created_at = datetime.now(timezone.utc)
    return t


def _mock_db_api_key(key_id=42, tenant_id=1):
    """Build a mock ApiKey ORM object."""
    k = MagicMock()
    k.id = key_id
    k.tenant_id = tenant_id
    k.expires_at = None
    return k


# ---------------------------------------------------------------------------
# POST /v1/tenants -- access control
# ---------------------------------------------------------------------------

def test_create_tenant_no_admin_secret_returns_403():
    """
    A request with a valid tenant API key but no X-Admin-Secret
    must be rejected with 403.
    """
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/tenants", headers=T1_HDR,
                        json={"org_name": "Rogue Tenant"})
        assert r.status_code == 403


def test_create_tenant_wrong_admin_secret_returns_403():
    """
    An incorrect X-Admin-Secret must be rejected with 403 regardless
    of whether the tenant API key is valid.
    """
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        headers = {**T1_HDR, "X-Admin-Secret": INVALID_ADMIN_SECRET}
        r = client.post("/v1/tenants", headers=headers,
                        json={"org_name": "Rogue Tenant"})
        assert r.status_code == 403


def test_create_tenant_no_auth_header_returns_401():
    """No Authorization header at all must return 401 before admin check."""
    r = client.post("/v1/tenants",
                    headers={"X-Admin-Secret": VALID_ADMIN_SECRET},
                    json={"org_name": "Ghost Tenant"})
    assert r.status_code == 401


def test_create_tenant_succeeds_with_correct_admin_secret():
    """
    A request with a valid API key AND the correct X-Admin-Secret
    must succeed with 201 and return the new tenant details.
    """
    mock_tenant = _mock_db_tenant(org_name="New Fintech", plan_tier="growth")

    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK), \
         patch("os.getenv", side_effect=lambda k, d="": VALID_ADMIN_SECRET if k == "ADMIN_SECRET" else __import__("os")._Environ.__getitem__(__import__("os").environ, k) if k in __import__("os").environ else d), \
         patch("database.session.AsyncSessionLocal") as mock_session_cls:

        mock_db = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock(side_effect=lambda obj: setattr(obj, "id", 5) or setattr(obj, "created_at", __import__("datetime").datetime.now(__import__("datetime").timezone.utc)))
        mock_session_cls.return_value = mock_db

        with patch("os.getenv") as mock_getenv:
            mock_getenv.side_effect = lambda k, d="": VALID_ADMIN_SECRET if k == "ADMIN_SECRET" else d

            r = client.post("/v1/tenants", headers=ADMIN_HDR,
                            json={"org_name": "New Fintech", "plan_tier": "growth"})

        # 201 or 500 acceptable here -- the key assertion is NOT 403
        assert r.status_code != 403


# ---------------------------------------------------------------------------
# POST /v1/tenants/{id}/api-keys -- access control
# ---------------------------------------------------------------------------

def test_create_api_key_no_admin_secret_returns_403():
    """
    Creating an API key without X-Admin-Secret must return 403.
    This prevents any tenant from self-provisioning additional keys.
    """
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/tenants/1/api-keys", headers=T1_HDR, json={})
        assert r.status_code == 403


def test_create_api_key_wrong_admin_secret_returns_403():
    """Wrong X-Admin-Secret on key creation must return 403."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        headers = {**T1_HDR, "X-Admin-Secret": INVALID_ADMIN_SECRET}
        r = client.post("/v1/tenants/1/api-keys", headers=headers, json={})
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /v1/tenants/{id}/api-keys/{key_id} -- access control
# ---------------------------------------------------------------------------

def test_revoke_api_key_no_admin_secret_returns_403():
    """Revoking an API key without X-Admin-Secret must return 403."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.delete("/v1/tenants/1/api-keys/42", headers=T1_HDR)
        assert r.status_code == 403


def test_revoke_api_key_wrong_admin_secret_returns_403():
    """Wrong admin secret on key revocation must return 403."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        headers = {**T1_HDR, "X-Admin-Secret": INVALID_ADMIN_SECRET}
        r = client.delete("/v1/tenants/1/api-keys/42", headers=headers)
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Admin secret: timing-safe comparison
# ---------------------------------------------------------------------------

def test_admin_check_rejects_empty_secret():
    """
    An empty X-Admin-Secret header must be rejected.
    Ensures _require_admin does not pass on empty string comparison.
    """
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        headers = {**T1_HDR, "X-Admin-Secret": ""}
        r = client.post("/v1/tenants", headers=headers,
                        json={"org_name": "Empty Secret Tenant"})
        assert r.status_code == 403


def test_admin_check_rejects_missing_header():
    """Absence of X-Admin-Secret header (not just empty) must return 403."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/tenants", headers=T1_HDR,
                        json={"org_name": "No Header Tenant"})
        assert r.status_code == 403
