"""
Response Shield Tests (Module M9).
Verifies:
1. Backend 500 errors never reach the client verbatim; client gets generic JSON + incident ID.
2. Event store logs event action as 'error_masked' with reached_backend=True.
3. Leaking server headers ('Server', 'X-Powered-By') are stripped from proxied responses.
4. Defensive security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
   Cache-Control, Content-Security-Policy) are injected onto proxied responses.
5. Gateway dashboard and control plane routes (/_gk/*) are completely unaffected.
6. Temporary test route in mock upstream returning fake stack traces is properly masked.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from gateway.config import GatewayConfig
from gateway.main import create_app
from gateway.shield import (
    apply_shield_headers,
    create_masked_error_response,
    should_mask_response,
    SECURITY_HEADERS,
    STRIP_HEADERS,
)


def run_async(coro: Any) -> Any:
    """Helper to run an async coroutine synchronously in pytest."""
    return asyncio.run(coro)


class MockShieldUpstream:
    """
    Mock upstream server including a crashing route that emits a fake stack trace,
    and routes with sensitive server / framework headers.
    """

    FAKE_STACK_TRACE = (
        "Traceback (most recent call last):\n"
        '  File "/app/services/checkout.py", line 88, in process_payment\n'
        '    secret_key = os.environ["DATABASE_ADMIN_SECRET_KEY"]\n'
        "KeyError: 'DATABASE_ADMIN_SECRET_KEY'\n"
        "During handling of the above exception, another exception occurred:\n"
        '  File "/app/backend/server.py", line 142, in handle_request\n'
        '    raise InternalDatabaseError("Connection to pgsql://admin:supersecret@10.0.0.5:5432 failed")\n'
        "InternalDatabaseError: Connection to pgsql://admin:supersecret@10.0.0.5:5432 failed\n"
    )

    def __init__(self) -> None:
        self.received_requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.received_requests.append(request)
        url_str = str(request.url)

        # 1. Temporary test route returning a 500 with a fake stack-trace string
        if "/api/test-crash" in url_str:
            return httpx.Response(
                status_code=500,
                headers={
                    "Content-Type": "text/plain; charset=utf-8",
                    "Server": "Werkzeug/3.0.1 Python/3.12.2",
                    "X-Powered-By": "Flask-Restful/0.3.10",
                },
                content=self.FAKE_STACK_TRACE.encode("utf-8"),
            )

        # 2. Route returning 503 Service Unavailable
        if "/api/test-503" in url_str:
            return httpx.Response(
                status_code=503,
                headers={"Server": "Nginx/1.24.0", "Content-Type": "text/html"},
                content=b"<h1>503 Backend Service Unavailable</h1>",
            )

        # 3. Healthy route leaking server banners
        if "/api/products" in url_str:
            return httpx.Response(
                status_code=200,
                headers={
                    "Content-Type": "application/json",
                    "Server": "Apache/2.4.52 (Ubuntu)",
                    "X-Powered-By": "Express-Custom/4.18.2",
                    "X-Custom-App-Header": "ProductCatalog-v1",
                },
                content=b'[{"id": 1, "name": "Smartphone X"}]',
            )

        # 4. Standard upstream health
        if "/api/health" in url_str:
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/json"},
                content=b'{"status": "healthy"}',
            )

        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b'{"status": "ok"}',
        )


def create_shield_test_clients(
    tmp_path: Any = None,
) -> tuple[httpx.AsyncClient, MockShieldUpstream, Any]:
    """Create test gateway client connected to MockShieldUpstream."""
    mock_upstream = MockShieldUpstream()
    data_dir = tmp_path if tmp_path else "data"
    cfg = GatewayConfig(
        upstream_url="http://upstream.test",
        data_dir=str(data_dir),
    )
    app = create_app(cfg)
    app.state.event_store.start_worker()

    # Wire mock upstream transport into app state
    upstream_transport = httpx.MockTransport(mock_upstream.handler)
    mock_upstream_client = httpx.AsyncClient(
        transport=upstream_transport,
        base_url="http://upstream.test",
        timeout=5.0,
    )
    app.state.http_client = mock_upstream_client

    # Gateway client calling the gateway
    gateway_transport = httpx.ASGITransport(app=app)
    gateway_client = httpx.AsyncClient(
        transport=gateway_transport,
        base_url="http://gateway.test",
    )
    return gateway_client, mock_upstream, app


# =============================================================================
# Unit Tests for gateway.shield
# =============================================================================


def test_should_mask_response():
    """Verify threshold for masking status codes."""
    assert should_mask_response(500) is True
    assert should_mask_response(502) is True
    assert should_mask_response(503) is True
    assert should_mask_response(504) is True
    assert should_mask_response(599) is True

    assert should_mask_response(200) is False
    assert should_mask_response(201) is False
    assert should_mask_response(302) is False
    assert should_mask_response(400) is False
    assert should_mask_response(403) is False
    assert should_mask_response(404) is False
    assert should_mask_response(499) is False


def test_apply_shield_headers_strips_sensitive_and_adds_security():
    """Verify header sanitation strips leaking headers and injects defensive headers."""
    raw_headers = {
        "Server": "Apache/2.4.52",
        "SERVER": "Duplicate/1.0",
        "X-Powered-By": "PHP/8.1",
        "x-powered-by": "Express",
        "Content-Type": "application/json",
        "Content-Length": "123",
        "Transfer-Encoding": "chunked",
        "X-App-Data": "SafeHeader",
    }

    shielded = apply_shield_headers(raw_headers)

    # Server and X-Powered-By must be completely stripped
    lower_keys = {k.lower() for k in shielded.keys()}
    assert "server" not in lower_keys
    assert "x-powered-by" not in lower_keys
    assert "content-length" not in lower_keys
    assert "transfer-encoding" not in lower_keys

    # Custom safe headers preserved
    assert shielded.get("X-App-Data") == "SafeHeader"
    assert shielded.get("Content-Type") == "application/json"

    # Defensive security headers must be present
    assert shielded.get("X-Content-Type-Options") == "nosniff"
    assert shielded.get("X-Frame-Options") == "DENY"
    assert shielded.get("Referrer-Policy") == "no-referrer"
    assert shielded.get("Cache-Control") == "no-store"
    assert shielded.get("Content-Security-Policy") == "default-src 'none'"


def test_create_masked_error_response():
    """Verify create_masked_error_response formats generic JSON payload and shielded headers."""
    resp = create_masked_error_response(
        status_code=500,
        incident_id="AG-TEST-001",
        base_headers={"Server": "Vulnerable/1.0", "X-Powered-By": "Django/4.2"},
    )
    assert resp.status_code == 500
    assert resp.headers.get("content-type") == "application/json"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "server" not in {k.lower() for k in resp.headers.keys()}
    assert "x-powered-by" not in {k.lower() for k in resp.headers.keys()}


# =============================================================================
# Integration Tests: Masking Backend 500 & Stack Traces
# =============================================================================


def test_backend_500_stack_trace_masked_and_event_recorded(tmp_path: Any):
    """
    Acceptance check:
    A backend 500 never reaches the client verbatim.
    Client gets generic JSON + incident_id.
    Event store logs action='error_masked' and reached_backend=True.
    """

    async def _test():
        client, mock_upstream, app = create_shield_test_clients(tmp_path)
        try:
            resp = await client.get("/api/test-crash")

            # 1. Status must remain 500
            assert resp.status_code == 500

            # 2. Body must NOT contain any part of the stack trace or leakages
            resp_text = resp.text
            assert "Traceback" not in resp_text
            assert "supersecret" not in resp_text
            assert "DATABASE_ADMIN_SECRET_KEY" not in resp_text
            assert "InternalDatabaseError" not in resp_text

            # 3. Body must be sanitized generic JSON with incident_id
            data = resp.json()
            assert data["error"] == "Internal error"
            assert "incident_id" in data
            assert data["incident_id"].startswith("AG-")

            # 4. Headers must be shielded
            assert "server" not in {k.lower() for k in resp.headers.keys()}
            assert "x-powered-by" not in {k.lower() for k in resp.headers.keys()}
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert resp.headers.get("referrer-policy") == "no-referrer"
            assert resp.headers.get("cache-control") == "no-store"
            assert resp.headers.get("content-security-policy") == "default-src 'none'"

            # 5. Upstream mock was indeed called
            assert len(mock_upstream.received_requests) == 1

            # 6. Verify audit event emission
            # Allow event store queue drain (worker batch timeout is 250ms)
            await asyncio.sleep(0.35)
            events = app.state.event_store.get_events(limit=10)
            assert len(events) >= 1
            masked_event = events[0]
            assert masked_event["incident_id"] == data["incident_id"]
            assert masked_event["action"] == "error_masked"
            assert masked_event["reached_backend"] is True
            assert masked_event["status_code"] == 500

        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_backend_503_masked(tmp_path: Any):
    """Verify upstream 503 is also shielded to generic JSON."""

    async def _test():
        client, mock_upstream, app = create_shield_test_clients(tmp_path)
        try:
            resp = await client.get("/api/test-503")
            assert resp.status_code == 503

            # HTML body from upstream must be masked
            assert "<h1>" not in resp.text
            data = resp.json()
            assert data["error"] == "Internal error"
            assert data["incident_id"].startswith("AG-")

            # Headers shielded
            assert "server" not in {k.lower() for k in resp.headers.keys()}
            assert resp.headers.get("x-content-type-options") == "nosniff"

            # Event action is error_masked
            await asyncio.sleep(0.35)
            events = app.state.event_store.get_events(limit=10)
            assert any(e["action"] == "error_masked" and e["status_code"] == 503 for e in events)

        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_server_and_x_powered_by_stripped_on_healthy_responses(tmp_path: Any):
    """
    Acceptance check:
    Server and X-Powered-By stripped from healthy 200 OK proxied responses,
    security headers added, and custom safe headers retained.
    """

    async def _test():
        client, mock_upstream, app = create_shield_test_clients(tmp_path)
        try:
            resp = await client.get("/api/products")
            assert resp.status_code == 200

            # Valid body passes through
            data = resp.json()
            assert len(data) == 1
            assert data[0]["name"] == "Smartphone X"

            # Sensitive headers stripped
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            assert "server" not in headers_lower
            assert "x-powered-by" not in headers_lower

            # Custom safe application headers preserved
            assert headers_lower.get("x-custom-app-header") == "ProductCatalog-v1"

            # Security headers injected
            assert headers_lower.get("x-content-type-options") == "nosniff"
            assert headers_lower.get("x-frame-options") == "DENY"
            assert headers_lower.get("referrer-policy") == "no-referrer"
            assert headers_lower.get("cache-control") == "no-store"
            assert headers_lower.get("content-security-policy") == "default-src 'none'"

            # Audit event logged as 'allowed'
            await asyncio.sleep(0.35)
            events = app.state.event_store.get_events(limit=10)
            allowed_event = next(e for e in events if e["path"] == "/api/products")
            assert allowed_event["action"] == "allowed"
            assert allowed_event["reached_backend"] is True

        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_dashboard_routes_are_unaffected_by_shield(tmp_path: Any):
    """
    Acceptance check:
    Dashboard and control plane routes (/_gk/*) are unaffected by the response shield
    (e.g., they must not have 'Content-Security-Policy: default-src none' or 'X-Frame-Options: DENY').
    """

    async def _test():
        client, _, app = create_shield_test_clients(tmp_path)
        try:
            # 1. /_gk/health
            resp_health = await client.get("/_gk/health")
            assert resp_health.status_code == 200
            data_health = resp_health.json()
            assert data_health["status"] == "ok"
            # Ensure strict proxied CSP is NOT injected into control plane
            assert "default-src 'none'" not in resp_health.headers.get("content-security-policy", "")
            assert resp_health.headers.get("x-frame-options") != "DENY"

            # 2. /_gk/api/stats
            resp_stats = await client.get("/_gk/api/stats")
            assert resp_stats.status_code == 200
            assert "default-src 'none'" not in resp_stats.headers.get("content-security-policy", "")
            assert resp_stats.headers.get("x-frame-options") != "DENY"

            # 3. /_gk/ (dashboard HTML page)
            resp_ui = await client.get("/_gk/")
            assert resp_ui.status_code == 200
            assert "text/html" in resp_ui.headers.get("content-type", "")
            assert "default-src 'none'" not in resp_ui.headers.get("content-security-policy", "")

        finally:
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())
