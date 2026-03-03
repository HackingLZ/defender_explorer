"""Shared rate-limiting utilities."""

import ipaddress

from fastapi import Request
from slowapi.util import get_remote_address

# CIDRs that are allowed to set X-Real-IP (our nginx on Docker bridge).
# Anything outside these ranges has its X-Real-IP header ignored.
_TRUSTED_PROXIES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_trusted_proxy(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _TRUSTED_PROXIES)
    except ValueError:
        return False


def client_key(request: Request) -> str:
    """Extract the real client IP for rate limiting behind nginx + Cloudflare.

    Only trusts X-Real-IP when the direct TCP connection originates from a
    known proxy CIDR (Docker bridge / localhost).  If someone connects
    directly (bypassing nginx), their forged X-Real-IP is ignored and the
    raw socket IP is used instead.
    """
    direct_ip = get_remote_address(request)
    if _is_trusted_proxy(direct_ip):
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return direct_ip
