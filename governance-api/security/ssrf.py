# security/ssrf.py
"""
Shared SSRF prevention utilities.
Use validate_outbound_url() before making any outbound HTTP request
to a customer-supplied URL (context hooks, escalation webhooks, etc).
"""
import ipaddress
import re
import socket
from typing import List
from urllib.parse import urlparse

BLOCKED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),   # IPv4-mapped IPv6
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_INTERNAL_HOSTNAMES = frozenset(["localhost", "127.0.0.1", "0.0.0.0", "::1"])
_INTERNAL_TLDS = (".local", ".internal", ".lan", ".corp", ".home")


def validate_outbound_url(url: str) -> None:
    """
    Validate that a customer-supplied URL is safe to call.
    Raises ValueError with a descriptive message if the URL is blocked.

    Checks:
    - Only http/https schemes
    - No bare IPv4 or IPv6 literal addresses
    - No internal hostnames or TLDs
    - DNS resolution does not map to any private/blocked network
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL must use http or https scheme, got: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    if hostname.lower() in _INTERNAL_HOSTNAMES:
        raise ValueError(f"URL points to a blocked internal hostname: {hostname}")

    if any(hostname.lower().endswith(tld) for tld in _INTERNAL_TLDS):
        raise ValueError(f"URL points to a blocked internal TLD: {hostname}")

    # Block bare IPv4
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        raise ValueError(f"Bare IPv4 addresses are not allowed: {hostname}")

    # Block IPv6 literals (urlparse strips brackets)
    stripped = hostname.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        raise ValueError(f"Bare IP addresses (including IPv6) are not allowed: {hostname}")
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise

    # DNS resolution -- check ALL resolved IPs (not just the first)
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError(f"Hostname cannot be resolved: {hostname}")

    for addr_info in addr_infos:
        resolved_ip = addr_info[4][0]
        try:
            addr = ipaddress.ip_address(resolved_ip)
        except ValueError:
            continue
        for network in BLOCKED_NETWORKS:
            if addr in network:
                raise ValueError(
                    f"URL resolves to private/blocked IP {resolved_ip} (hostname: {hostname})"
                )
