"""Local functional checks for policy and explicit proxy identities."""

import ipaddress
import unittest
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app import rate_limit


class ProxyIdentityTests(unittest.TestCase):
    def request(self, peer, value):
        return Request({"type": "http", "client": (peer, 1234), "headers": [(b"x-real-ip", value.encode())]})

    def test_unconfigured_private_peer_uses_socket_identity(self):
        with patch.object(rate_limit, "_TRUSTED_PROXIES", frozenset()):
            self.assertEqual(rate_limit.client_key(self.request("10.0.0.2", "192.0.2.1")), "10.0.0.2")

    def test_configured_proxy_requires_valid_ip(self):
        with patch.object(rate_limit, "_TRUSTED_PROXIES", frozenset([ipaddress.ip_address("10.0.0.2")])):
            self.assertEqual(rate_limit.client_key(self.request("10.0.0.2", "192.0.2.1")), "192.0.2.1")
            self.assertEqual(rate_limit.client_key(self.request("10.0.0.2", "invalid")), "10.0.0.2")

    def test_proxy_configuration_rejects_network_ranges(self):
        with self.assertRaises(ValueError):
            rate_limit._proxy_addresses("10.0.0.0/8")


class RateLimitTests(unittest.TestCase):
    def make_app(self, application_budget):
        limiter = Limiter(key_func=rate_limit.client_key, key_style="endpoint", default_limits=["10/minute"], application_limits=[application_budget])
        app = FastAPI()
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(rate_limit.RateLimitMiddleware)

        @app.get("/items/{item_id}")
        @limiter.limit("2/minute")
        async def item(request: Request, item_id: int):
            return {"id": item_id}

        @app.get("/other")
        async def other():
            return {"ok": True}

        return app, limiter

    def test_parameterized_route_uses_one_budget(self):
        app, limiter = self.make_app("10/minute")
        with patch.object(rate_limit, "limiter", limiter), TestClient(app) as client:
            self.assertEqual(client.get("/items/1").status_code, 200)
            self.assertEqual(client.get("/items/2").status_code, 200)
            self.assertEqual(client.get("/items/3").status_code, 429)

    def test_application_budget_includes_decorated_and_plain_routes(self):
        app, limiter = self.make_app("2/minute")
        with patch.object(rate_limit, "limiter", limiter), TestClient(app) as client:
            self.assertEqual(client.get("/items/1").status_code, 200)
            self.assertEqual(client.get("/other").status_code, 200)
            self.assertEqual(client.get("/other").status_code, 429)


if __name__ == "__main__":
    unittest.main()
