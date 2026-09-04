"""Shared rate-limiting utilities."""

import ipaddress
import os

from fastapi import Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match

def _proxy_addresses(value: str) -> frozenset:
    """Only individual addresses are accepted; a private subnet is not a proxy."""
    return frozenset(ipaddress.ip_address(part.strip()) for part in value.split(",") if part.strip())


_TRUSTED_PROXIES = _proxy_addresses(os.getenv("TRUSTED_PROXY_IPS", ""))


def _is_trusted_proxy(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr in _TRUSTED_PROXIES
    except ValueError:
        return False


def client_key(request: Request) -> str:
    """Trust valid forwarded addresses only from an explicitly listed proxy."""
    direct_ip = get_remote_address(request)
    if _is_trusted_proxy(direct_ip):
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            try:
                return str(ipaddress.ip_address(real_ip.strip()))
            except ValueError:
                pass
    return direct_ip


limiter = Limiter(
    key_func=client_key,
    key_style="endpoint",
    default_limits=["120/minute"],
    application_limits=["120/minute"],
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply the aggregate budget even to routes with their own decorators.

    The stock middleware skips decorated routes. Middleware-mode checks apply
    application limits, leaving decorated limits to the endpoint wrapper.
    """

    async def dispatch(self, request: Request, call_next):
        handler = None
        for route in request.app.routes:
            match, _ = route.matches(request.scope)
            if match == Match.FULL:
                handler = getattr(route, "endpoint", None)
                break
        try:
            limiter._check_request_limit(request, handler, in_middleware=True)
        except RateLimitExceeded as exc:
            return _rate_limit_exceeded_handler(request, exc)
        return await call_next(request)
