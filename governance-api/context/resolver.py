# context/resolver.py
import asyncio
import logging
import re
import urllib.parse
from typing import Any, Dict, Optional

import httpx

from security.ssrf import validate_url_and_resolve

logger = logging.getLogger(__name__)

HOOK_TIMEOUT = 0.5          # per-hook timeout reduced to 500ms
AGGREGATE_TIMEOUT = 1.0      # all hooks combined must finish within 1s
MAX_CONTEXT_HOOKS = 5


class ContextResolver:
    """
    Resolves context hooks by calling customer-defined external URLs.
    Full SSRF protection including IPv6 and DNS-rebinding mitigation
    is handled by security.ssrf.validate_url_and_resolve.
    """

    def _resolve_url(self, template: str, payload: Dict[str, Any]) -> str:
        """Substitute {placeholders} with payload values, URL-encoding them."""
        def replace_match(match):
            value = str(payload.get(match.group(1), ""))
            return urllib.parse.quote(value, safe="")
        return re.sub(r"\{(\w+)\}", replace_match, template)

    async def _call_hook(
        self,
        hook_name: str,
        url: str,
        payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        resolved = self._resolve_url(url, payload)

        # SSRF validation + DNS resolution (rebinding-safe)
        try:
            validated_url, resolved_ip = validate_url_and_resolve(resolved)
        except ValueError as e:
            logger.warning("Hook %s rejected (SSRF): %s", hook_name, e)
            return None

        try:
            parsed = urllib.parse.urlparse(validated_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            method = query_params.get("method", ["POST"])[0].upper()
            clean_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(
                    {k: v for k, v in query_params.items() if k != "method"},
                    doseq=True
                ))
            ) if "method" in query_params else validated_url

            async with httpx.AsyncClient(timeout=HOOK_TIMEOUT) as client:
                if method == "GET":
                    response = await client.get(clean_url)
                else:
                    response = await client.post(clean_url, json=payload)

            if response.status_code == 200:
                return response.json()

            logger.warning(
                "Hook %s returned HTTP %s from %s",
                hook_name, response.status_code, clean_url,
            )
            return None

        except httpx.TimeoutException:
            logger.warning("Hook %s timed out after %ss", hook_name, HOOK_TIMEOUT)
            return None
        except Exception as exc:
            logger.warning("Hook %s failed: %s", hook_name, exc)
            return None

    async def resolve(
        self,
        context_hooks: Dict[str, str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not context_hooks:
            return payload

        if len(context_hooks) > MAX_CONTEXT_HOOKS:
            logger.warning(
                "Too many context hooks: %d (max %d). Using first %d.",
                len(context_hooks), MAX_CONTEXT_HOOKS, MAX_CONTEXT_HOOKS,
            )
            context_hooks = dict(list(context_hooks.items())[:MAX_CONTEXT_HOOKS])

        names = list(context_hooks.keys())
        urls = list(context_hooks.values())

        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *[self._call_hook(name, url, payload) for name, url in zip(names, urls)],
                    return_exceptions=True,
                ),
                timeout=AGGREGATE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Context hooks aggregate timeout (%ss) exceeded -- skipping all hooks",
                AGGREGATE_TIMEOUT,
            )
            return payload

        enriched = dict(payload)
        for name, result in zip(names, results):
            if isinstance(result, dict):
                enriched.update(result)
                logger.debug("Hook %s merged fields %s", name, list(result.keys()))
            elif isinstance(result, Exception):
                logger.warning("Hook %s raised %s: %s", name, type(result).__name__, result)

        return enriched


context_resolver = ContextResolver()
