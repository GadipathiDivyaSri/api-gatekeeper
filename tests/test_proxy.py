"""
Proxy Core Tests (Module M2).
Verifies transparent reverse proxying, hop-by-hop header removal,
X-Request-ID injection, 502 handling on upstream failure, and 413 on oversized bodies.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx
import pytest

from gateway.config import GatewayConfig
from gateway.main import create_app


def run_async(coro: Any) -> Any:
    """Helper to run an async coroutine synchronously in pytest."""
    return asyncio.run(coro)


class MockUpstreamState:
    """Captures requests received by mock upstream for assertion checks."""

    def __init__(self):
        self.received_requests: list[httpx.Request] = []
        self.should_fail: bool = False
        self.response_status: int = 200
        self.response_body: bytes = b'{"status": "upstream_ok"}'
        self.response_headers: dict[str, str] = {"content-type": "application/json"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.received_requests.append(request)
        if self.should_fail:
            raise httpx.ConnectError("Connection refused by mock upstream", request=request)

        # Echo mock products if requested
        if "/api/products" in str(request.url):
            return httpx.Response(
                status_code=200,
                headers={"content-type": "application/json"},
                content=json.dumps([{"id": 1, "name": "Smartphone X"}]).encode(),
            )

        if "/api/health" in str(request.url):
            return httpx.Response(
                status_code=200,
                headers={"content-type": "application/json"},
                content=b'{"status": "healthy"}',
            )

        return httpx.Response(
            status_code=self.response_status,
            headers=self.response_headers,
            content=self.response_body,
        )


def create_test_client(
    config: GatewayConfig | None = None,
    mock_state: MockUpstreamState | None = None,
) -> tuple[httpx.AsyncClient, MockUpstreamState, httpx.AsyncClient]:
    """Create test gateway client and configure mock upstream transport."""
    state = mock_state or MockUpstreamState()
    cfg = config or GatewayConfig(
        upstream_url="http://upstream.test",
        max_body_bytes=1024,  # Small limit for easy 413 testing
    )
    app = create_app(cfg)

    # Attach mock upstream client to app state
    upstream_transport = httpx.MockTransport(state.handler)
    mock_upstream_client = httpx.AsyncClient(
        transport=upstream_transport,
        base_url="http://upstream.test",
        timeout=5.0,
    )
    app.state.http_client = mock_upstream_client

    # Client to invoke the gateway
    gateway_transport = httpx.ASGITransport(app=app)
    gateway_client = httpx.AsyncClient(
        transport=gateway_transport,
        base_url="http://gateway.test",
    )
    return gateway_client, state, mock_upstream_client


def test_proxy_passthrough():
    """Verify that requests pass through to upstream preserving status, body, and query."""

    async def _test():
        client, state, upstream = create_test_client()
        try:
            resp = await client.get("/api/products?search=phone")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["name"] == "Smartphone X"

            assert len(state.received_requests) == 1
            upstream_req = state.received_requests[0]
            assert upstream_req.method == "GET"
            assert "search=phone" in str(upstream_req.url)
        finally:
            await client.aclose()
            await upstream.aclose()

    run_async(_test())


def test_proxy_hop_by_hop_removal():
    """Verify that hop-by-hop headers are removed and custom headers preserved."""

    async def _test():
        client, state, upstream = create_test_client()
        try:
            resp = await client.get(
                "/api/products",
                headers={
                    "connection": "keep-alive",
                    "keep-alive": "timeout=5",
                    "upgrade": "websocket",
                    "x-custom-header": "test-value",
                },
            )
            assert resp.status_code == 200
            assert len(state.received_requests) == 1
            upstream_req = state.received_requests[0]

            # Hop-by-hop headers must be stripped
            assert "connection" not in upstream_req.headers
            assert "keep-alive" not in upstream_req.headers
            assert "upgrade" not in upstream_req.headers

            # Custom headers must pass through
            assert upstream_req.headers.get("x-custom-header") == "test-value"
        finally:
            await client.aclose()
            await upstream.aclose()

    run_async(_test())


def test_proxy_x_request_id_injected():
    """Verify that X-Request-ID is generated and attached to forwarded request."""

    async def _test():
        client, state, upstream = create_test_client()
        try:
            resp = await client.get("/api/products")
            assert resp.status_code == 200
            upstream_req = state.received_requests[0]

            req_id = upstream_req.headers.get("x-request-id")
            assert req_id is not None
            # Format: AG-YYYYMMDD-HHMMSS-xxxx
            pattern = r"^AG-\d{8}-\d{6}-[0-9a-f]{4}$"
            assert re.match(pattern, req_id), f"Invalid incident_id format: {req_id}"

            # X-Forwarded-For should also be present
            assert "x-forwarded-for" in upstream_req.headers
        finally:
            await client.aclose()
            await upstream.aclose()

    run_async(_test())


def test_proxy_upstream_down_502():
    """Verify that upstream network/connection errors return a generic 502 JSON response."""

    async def _test():
        state = MockUpstreamState()
        state.should_fail = True
        client, _, upstream = create_test_client(mock_state=state)
        try:
            resp = await client.get("/api/products")
            assert resp.status_code == 502
            data = resp.json()
            assert "Bad Gateway" in data["error"]
            assert "incident_id" in data
            assert data["incident_id"].startswith("AG-")
        finally:
            await client.aclose()
            await upstream.aclose()

    run_async(_test())


def test_proxy_oversized_body_413():
    """Verify that bodies exceeding max_body_bytes return 413 and never reach upstream."""

    async def _test():
        # max_body_bytes configured to 1024 bytes
        client, state, upstream = create_test_client()
        try:
            oversized_body = b"A" * 2048  # 2 KB > 1024 bytes limit
            resp = await client.post(
                "/api/feedback",
                content=oversized_body,
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 413
            data = resp.json()
            assert data["error"] == "Payload too large"
            assert "incident_id" in data

            # Must NEVER have reached upstream!
            assert len(state.received_requests) == 0
        finally:
            await client.aclose()
            await upstream.aclose()

    run_async(_test())


def test_health_check_endpoint():
    """Verify GET /_gk/health reports gateway ok and detects upstream status."""

    async def _test():
        # Case 1: Upstream healthy
        client, state, upstream = create_test_client()
        try:
            resp = await client.get("/_gk/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["upstream_reachable"] is True
            assert data["mode"] == "block"
        finally:
            await client.aclose()
            await upstream.aclose()

        # Case 2: Upstream down
        state_down = MockUpstreamState()
        state_down.should_fail = True
        client_down, _, upstream_down = create_test_client(mock_state=state_down)
        try:
            resp = await client_down.get("/_gk/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["upstream_reachable"] is False

            # Case 3: Shallow check (?shallow=1) answers immediately without touching upstream
            resp_shallow = await client_down.get("/_gk/health?shallow=1")
            assert resp_shallow.status_code == 200
            data_shallow = resp_shallow.json()
            assert data_shallow["status"] == "ok"
            assert data_shallow["shallow"] is True
            assert "upstream_reachable" not in data_shallow
        finally:
            await client_down.aclose()
            await upstream_down.aclose()

    run_async(_test())


def test_proxy_x_forwarded_for_chaining():
    """Verify that existing X-Forwarded-For headers are preserved and appended."""

    async def _test():
        client, state, upstream = create_test_client()
        try:
            resp = await client.get(
                "/api/products",
                headers={"x-forwarded-for": "203.0.113.195"},
            )
            assert resp.status_code == 200
            assert len(state.received_requests) == 1
            fwd_header = state.received_requests[0].headers.get("x-forwarded-for")
            assert "203.0.113.195" in fwd_header
        finally:
            await client.aclose()
            await upstream.aclose()

    run_async(_test())


def test_proxy_timeout_handling():
    """Verify that upstream timeouts produce a clean 502 Bad Gateway response."""

    class TimeoutUpstream:
        def handler(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Read timed out from backend", request=request)

    async def _test():
        cfg = GatewayConfig(upstream_url="http://timeout-upstream.test")
        app = create_app(cfg)
        timeout_client = httpx.AsyncClient(
            transport=httpx.MockTransport(TimeoutUpstream().handler),
            base_url="http://timeout-upstream.test",
        )
        app.state.http_client = timeout_client

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gateway.test",
        ) as client:
            resp = await client.get("/api/products")
            assert resp.status_code == 502
            data = resp.json()
            assert "Bad Gateway" in data["error"]
            assert "incident_id" in data

        await timeout_client.aclose()

    run_async(_test())

