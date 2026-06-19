import asyncio
import time
from unittest.mock import patch

import pytest

from context.resolver import ContextResolver


def test_placeholder_replaced_with_payload_value():
    resolver = ContextResolver()
    url = resolver._resolve_url(
        "https://bank.internal/watchlist/{customer_id}",
        {"customer_id": "CUST001"},
    )
    assert url == "https://bank.internal/watchlist/CUST001"


def test_multiple_placeholders_all_replaced():
    resolver = ContextResolver()
    url = resolver._resolve_url(
        "https://b/{tenant}/{cid}/check",
        {"tenant": "abc", "cid": "CUST002"},
    )
    assert url == "https://b/abc/CUST002/check"


def test_missing_payload_field_becomes_empty_string():
    resolver = ContextResolver()
    url = resolver._resolve_url("https://b/{missing}", {})
    assert url == "https://b/"


def test_no_placeholders_url_unchanged():
    resolver = ContextResolver()
    assert resolver._resolve_url("https://b/static", {}) == "https://b/static"


def test_url_encoding_special_characters():
    resolver = ContextResolver()
    url = resolver._resolve_url(
        "https://b/{customer_id}",
        {"customer_id": "CUST 001"},
    )
    assert "%20" in url
    assert " " not in url


@pytest.mark.asyncio
async def test_hook_response_merged_into_payload():
    resolver = ContextResolver()

    with patch.object(
        resolver,
        "_call_hook",
        return_value={"watchlist_result": True},
    ):
        result = await resolver.resolve(
            {"wl": "https://bank.internal/wl/{customer_id}"},
            {"amount": 5000000, "customer_id": "CUST001"},
        )

    assert result["amount"] == 5000000
    assert result["watchlist_result"] is True


@pytest.mark.asyncio
async def test_empty_hooks_payload_unchanged():
    resolver = ContextResolver()
    payload = {"amount": 5000000}

    result = await resolver.resolve({}, payload)

    assert result == payload


@pytest.mark.asyncio
async def test_failed_hook_does_not_crash_evaluation():
    resolver = ContextResolver()

    with patch.object(resolver, "_call_hook", return_value=None):
        result = await resolver.resolve(
            {"slow": "https://slow"},
            {"amount": 5000000},
        )

    assert result["amount"] == 5000000


@pytest.mark.asyncio
async def test_multiple_hooks_run_in_parallel_not_sequentially():
    resolver = ContextResolver()

    async def mock_hook(name, url, payload):
        await asyncio.sleep(0.1)
        return {f"result_{name}": True}

    with patch.object(resolver, "_call_hook", side_effect=mock_hook):
        start = time.time()
        result = await resolver.resolve(
            {"h1": "https://a", "h2": "https://b"},
            {"amount": 1000},
        )
        elapsed = time.time() - start

    assert elapsed < 0.25, f"Hooks ran sequentially: {elapsed:.2f}s"
    assert "result_h1" in result
    assert "result_h2" in result


def test_ssrf_blocks_private_ips():
    resolver = ContextResolver()
    with pytest.raises(ValueError):
        resolver._validate_hook_url("http://127.0.0.1/internal")


def test_ssrf_blocks_localhost():
    resolver = ContextResolver()
    with pytest.raises(ValueError):
        resolver._validate_hook_url("http://localhost/admin")


def test_ssrf_blocks_bare_ip():
    resolver = ContextResolver()
    with pytest.raises(ValueError):
        resolver._validate_hook_url("http://192.168.1.1/api")


def test_ssrf_allows_public_domain():
    resolver = ContextResolver()
    # This should not raise - validating URL format only
    # (DNS resolution might fail in test, but format should pass)
    try:
        resolver._validate_hook_url("https://api.example.com/data")
    except ValueError:
        pytest.fail("Public domain should be allowed")
