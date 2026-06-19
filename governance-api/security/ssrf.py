# security/ssrf.py
"""
Shared SSRF (Server-Side Request Forgery) protection utilities.
Used by both context/resolver.py and escalations/service.py.

DNS rebinding mitigation: we resolve DNS once here and return the
resolved IP so callers can use it directly in the HTTP request,
preventing an attacker from returning a private IP on the second lookup.
"""
import ipaddress
import re
import socket
from typing import Tuple
from urllib.parse import urlparse

# RFC-1918 and other private/reserved IP ranges
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped IPv6
]


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address falls in any blocked network."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in BLOCKED_NETWORKS)
    except ValueError:
        return True  # unparseable address -> treat as unsafe


def validate_url_and_resolve(url: str) -> Tuple[str, str]:
    """
    Validate a URL for SSRF safety and resolve its hostname to an IP.

    Returns (validated_url, resolved_ip) on success.
    Raises ValueError with a descriptive message on failure.

    DNS rebinding mitigation: the resolved IP is returned so callers
    can pass it directly to httpx instead of relying on a second DNS
    lookup at request time.

    Blocks:
    - non-HTTP/HTTPS schemes
    - bare IPv4 addresses
    - bare IPv6 literal addresses (e.g. http://[::1]/)
    - .local / .internal TLDs
    - known localhost names
    - any hostname that resolves to a private/reserved IP
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL must use http or https. Got: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    # Block bare IPv4 addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        raise ValueError(f"Bare IP addresses are not allowed: {hostname}")

    # Block IPv6 literal addresses (hostname from urlparse strips brackets)
    try:
        ipaddress.ip_address(hostname)  # succeeds only for bare IPs
        raise ValueError(f"Bare IP addresses are not allowed: {hostname}")
    except ValueError as exc:
        # Re-raise our own message; ignore "does not appear to be an IPv4 or IPv6"
        if "Bare IP" in str(exc):
            raise

    # Block internal TLDs
    lower = hostname.lower()
    if lower.endswith(".local") or lower.endswith(".internal"):
        raise ValueError(f"URL points to internal domain: {hostname}")

    # Block known localhost names
    if lower in ("localhost", "0.0.0.0"):
        raise ValueError(f"URL points to localhost: {hostname}")

    # DNS resolution -- single authoritative lookup
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError(f"Hostname cannot be resolved: {hostname}")

    if not addr_infos:
        raise ValueError(f"Hostname returned no addresses: {hostname}")

    # Check every returned IP -- reject if ANY resolves to a private range
    for addr_info in addr_infos:
        resolved_ip = addr_info[4][0]
        if _is_private_ip(resolved_ip):
            raise ValueError(
                f"URL {url!r} resolves to private/reserved IP: {resolved_ip}"
            )

    # Return the first resolved IP (caller should use this directly)
    primary_ip = addr_infos[0][4][0]
    return url, primary_ip
