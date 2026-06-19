# context/resolver.py
import asyncio
import ipaddress
import logging
import re
import socket
import urllib.parse
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

HOOK_TIMEOUT = 2.0
MAX_CONTEXT_HOOKS = 5  # Prevent excessive concurrent outbound requests

# RFC-1918 and other private IP ranges to block for SSRF prevention
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),   # IPv4-mapped IPv6
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
]


class ContextResolver:
    """
    Resolves context hooks by calling customer-defined external URLs.
    Includes SSRF protection to prevent internal network probing.
    """

    def _resolve_url(self, template: str, payload: Dict[str, Any]) -> str:
        """Substitute {placeholders} with payload values, URL-encoding them."""
        def replace_match(match):
            value = str(payload.get(match.group(1), ""))
            return urllib.parse.quote(value, safe="")

        return re.sub(r"\{(\w+)\}", replace_match, template)

    def _validate_hook_url(self, url: str) -> None:
        """
        Validate that a hook URL is safe to call.
        Raises ValueError if the URL resolves to a private/internal IP.
        Blocks IPv4 bare addresses, IPv6 literals, and DNS rebinding
        by validating the resolved IP directly.
        """
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Context hook URLs must use HTTP or HTTPS. Got: {parsed.scheme}"
            )

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Context hook URL has no hostname")

        # Block internal TLDs
        if hostname.endswith(".local") or hostname.endswith(".internal"):
            raise ValueError(
                f"Context hook URL points to internal domain: {hostname}"
            )

        # Block known internal hostnames
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
            raise ValueError(
                f"Context hook URL points to localhost: {hostname}"
            )

        # Block bare IPv4 addresses
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            raise ValueError(
                f"Context hook URLs must use domain names, not bare IP addresses: {hostname}"
            )

        # Block IPv6 literal addresses (e.g., [::1], [fc00::1], [::ffff:127.0.0.1])
        # urlparse strips the brackets for us in parsed.hostname
        stripped = hostname.strip("[]")
        try:
            addr = ipaddress.ip_address(stripped)
            # If it parses as an IP at all, block it entirely
            raise ValueError(
                f"Context hook URLs must use domain names, not IP addresses: {hostname}"
            )
        except ValueError as e:
            # Re-raise only the SSRF block, not the "not a valid IP" parsing error
            if "must use domain names" in str(e) or "IP addresses" in str(e):
                raise

        # DNS resolution check -- validate the resolved IP is not private
        # This also mitigates basic DNS rebinding by checking at validation time.
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
            for addr_info in addr_infos:
                resolved_ip = addr_info[4][0]
                addr = ipaddress.ip_address(resolved_ip)
                for network in BLOCKED_NETWORKS:
                    if addr in network:
                        raise ValueError(
                            f"Context hook URL '{url}' resolves to private/blocked IP: {resolved_ip}"
                        )
        except socket.gaierror:
            raise ValueError(
                f"Context hook hostname cannot be resolved: {hostname}"
            )

    async def _call_hook(
        self,
        hook_name: str,
        url: str,
        payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        resolved = self._resolve_url(url, payload)

        try:
            self._validate_hook_url(resolved)
        except ValueError as e:
            logger.warning("Hook %s rejected (SSRF check): %s", hook_name, e)
            return None

        try:
            async with httpx.AsyncClient(timeout=HOOK_TIMEOUT) as client:
                parsed = urllib.parse.urlparse(resolved)
                query_params = urllib.parse.parse_qs(parsed.query)
                method = query_params.get("method", ["POST"])[0].upper()
                clean_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(
                        {k: v for k, v in query_params.items() if k != "method"},
                        doseq=True
                    ))
                ) if "method" in query_params else resolved

                if method == "GET":
                    response = await client.get(clean_url)
                else:
                    response = await client.post(clean_url, json=payload)

            if response.status_code == 200:
                return response.json()

            logger.warning(
                "Hook %s returned HTTP %s from %s",
                hook_name, response.status_code, clean_url
            )
            return None

        except httpx.TimeoutException:
            logger.warning(
                "Hook %s timed out after %ss -- skipping",
                hook_name, HOOK_TIMEOUT,
            )
            return None
        except Exception as exc:
            logger.warning("Hook %s failed: %s -- skipping", hook_name, exc)
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
                len(context_hooks), MAX_CONTEXT_HOOKS, MAX_CONTEXT_HOOKS
            )
            context_hooks = dict(list(context_hooks.items())[:MAX_CONTEXT_HOOKS])

        names = list(context_hooks.keys())
        urls = list(context_hooks.values())

        results = await asyncio.gather(
            *[
                self._call_hook(name, url, payload)
                for name, url in zip(names, urls)
            ],
            return_exceptions=True,
        )

        enriched = dict(payload)
        for name, result in zip(names, results):
            if isinstance(result, dict):
                enriched.update(result)
                logger.debug("Hook %s merged fields %s", name, list(result.keys()))
            elif isinstance(result, Exception):
                logger.warning(
                    "Hook %s failed with %s: %s",
                    name, type(result).__name__, result
                )

        return enriched


context_resolver = ContextResolver()
