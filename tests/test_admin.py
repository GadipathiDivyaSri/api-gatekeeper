"""
Control Plane Admin API & Mode Toggle Tests (Module M10).
Verifies:
1. Mode toggling (block <-> monitor) via GET/POST /_gk/api/mode.
2. Mode comparison 60-second before/after stats via GET /_gk/api/mode-comparison.
3. Rule listing, dynamic enable/disable via PATCH /_gk/api/rules/{id}, and hot-reload.
4. Active ban listing and dynamic unban via DELETE /_gk/api/bans/{ip}.
5. Authentication enforcement with X-Admin-Token and ?token=.
6. Acceptance: In monitor mode, attacks are FLAGGED with reached_backend=True.
   In block mode, attacks are BLOCKED with reached_backend=False.
   Disabling a rule allows the probe through; re-enabling restores blocking.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from gateway.config import GatewayConfig
from gateway.main import create_app


def run_async(coro: Any) -> Any:
    """Helper to run async test coroutine synchronously."""
    return asyncio.run(coro)


class MockAdminUpstream:
    """Mock upstream backend for admin & mode end-to-end tests."""

    def __init__(self) -> None:
        self.received_requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.received_requests.append(request)
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b'{"status": "upstream_ok", "data": [1, 2, 3]}',
        )


def create_admin_test_clients(
    tmp_path: Any,
    admin_token: str | None = None,
    mode: str = "block",
) -> tuple[httpx.AsyncClient, MockAdminUpstream, Any]:
    """Helper to create gateway test client and mock upstream."""
    mock_upstream = MockAdminUpstream()
    cfg = GatewayConfig(
        upstream_url="http://upstream.test",
        data_dir=str(tmp_path),
        admin_token=admin_token,
        mode=mode,
        client_ip_source="xff_first",
    )
    app = create_app(cfg)
    app.state.event_store.start_worker()

    upstream_transport = httpx.MockTransport(mock_upstream.handler)
    app.state.http_client = httpx.AsyncClient(
        transport=upstream_transport,
        base_url="http://upstream.test",
        timeout=5.0,
    )

    gateway_transport = httpx.ASGITransport(app=app)
    gateway_client = httpx.AsyncClient(
        transport=gateway_transport,
        base_url="http://gateway.test",
    )
    return gateway_client, mock_upstream, app


# =============================================================================
# Unit & Integration Tests: Admin Endpoints
# =============================================================================


def test_mode_endpoints(tmp_path: Any):
    """Verify GET and POST /_gk/api/mode toggle between block and monitor."""

    async def _test():
        client, _, app = create_admin_test_clients(tmp_path)
        try:
            # 1. Check default mode
            resp = await client.get("/_gk/api/mode")
            assert resp.status_code == 200
            assert resp.json() == {"mode": "block"}

            # 2. Toggle to monitor mode
            resp = await client.post("/_gk/api/mode", json={"mode": "monitor"})
            assert resp.status_code == 200
            assert resp.json() == {"mode": "monitor"}
            assert app.state.config.mode == "monitor"

            # 3. Confirm GET reflects monitor mode
            resp = await client.get("/_gk/api/mode")
            assert resp.status_code == 200
            assert resp.json() == {"mode": "monitor"}

            # 4. Toggle back to block mode
            resp = await client.post("/_gk/api/mode", json={"mode": "block"})
            assert resp.status_code == 200
            assert resp.json() == {"mode": "block"}
            assert app.state.config.mode == "block"

            # 5. Invalid mode rejected
            resp = await client.post("/_gk/api/mode", json={"mode": "invalid_mode"})
            assert resp.status_code == 422
        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_rules_endpoints(tmp_path: Any):
    """Verify GET /_gk/api/rules, PATCH /_gk/api/rules/{id}, and POST /_gk/api/rules/reload."""

    async def _test():
        client, _, app = create_admin_test_clients(tmp_path)
        try:
            # 1. List rules
            resp = await client.get("/_gk/api/rules")
            assert resp.status_code == 200
            rules = resp.json()
            assert isinstance(rules, list)
            assert len(rules) >= 10
            rule_sqli = next(r for r in rules if r["id"] == "SQLI-001")
            assert rule_sqli["enabled"] is True

            # 2. Disable rule SQLI-001
            resp = await client.patch("/_gk/api/rules/SQLI-001", json={"enabled": False})
            assert resp.status_code == 200
            assert resp.json() == {"rule_id": "SQLI-001", "enabled": False}

            # Check rule is indeed disabled in manager
            rule_obj = app.state.rule_manager.get_rule("SQLI-001")
            assert rule_obj is not None
            assert rule_obj.enabled is False

            # 3. Re-enable rule SQLI-001
            resp = await client.patch("/_gk/api/rules/SQLI-001", json={"enabled": True})
            assert resp.status_code == 200
            assert resp.json() == {"rule_id": "SQLI-001", "enabled": True}
            assert rule_obj.enabled is True

            # 4. Patch non-existent rule -> 404
            resp = await client.patch("/_gk/api/rules/NON-EXISTENT-RULE", json={"enabled": False})
            assert resp.status_code == 404

            # 5. Hot reload rules
            resp = await client.post("/_gk/api/rules/reload")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["loaded_rules_count"] >= 10
        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_bans_endpoints(tmp_path: Any):
    """Verify GET /_gk/api/bans and DELETE /_gk/api/bans/{ip}."""

    async def _test():
        client, _, app = create_admin_test_clients(tmp_path)
        try:
            ban_ip = "203.0.113.42"
            # Ban IP via 3 strikes
            app.state.ban_manager.add_strike(ban_ip, count=3, reason="Test strike ban")
            banned_status, _ = app.state.ban_manager.is_banned(ban_ip)
            assert banned_status is True

            # 1. List bans
            resp = await client.get("/_gk/api/bans")
            assert resp.status_code == 200
            bans = resp.json()
            assert any(b["ip"] == ban_ip for b in bans)

            # 2. Unban IP
            resp = await client.delete(f"/_gk/api/bans/{ban_ip}")
            assert resp.status_code == 200
            assert resp.json() == {"ip": ban_ip, "unbanned": True}
            unbanned_status, _ = app.state.ban_manager.is_banned(ban_ip)
            assert not unbanned_status

            # 3. List bans is now empty
            resp = await client.get("/_gk/api/bans")
            assert resp.status_code == 200
            assert not any(b["ip"] == ban_ip for b in resp.json())
        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_mode_comparison_endpoint(tmp_path: Any):
    """Verify GET /_gk/api/mode-comparison returns rolling 60s window statistics."""

    async def _test():
        client, _, app = create_admin_test_clients(tmp_path)
        try:
            resp = await client.get("/_gk/api/mode-comparison?window=60")
            assert resp.status_code == 200
            comp = resp.json()
            assert "total_60s" in comp
            assert "blocked_60s" in comp
            assert "flagged_60s" in comp
            assert "allowed_60s" in comp
            assert "reached_backend_60s" in comp
            assert "blocked_perimeter_60s" in comp
            assert comp["current_mode"] == "block"
        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


def test_admin_token_guard_on_all_endpoints(tmp_path: Any):
    """Verify 401 Unauthorized when ADMIN_TOKEN is set and token is missing or invalid."""

    async def _test():
        secret_token = "ultra-secure-token-99"
        client, _, app = create_admin_test_clients(tmp_path, admin_token=secret_token)
        try:
            # 1. Missing token -> 401
            resp_mode = await client.get("/_gk/api/mode")
            assert resp_mode.status_code == 401

            resp_rules = await client.get("/_gk/api/rules")
            assert resp_rules.status_code == 401

            resp_bans = await client.get("/_gk/api/bans")
            assert resp_bans.status_code == 401

            # 2. Header authentication (X-Admin-Token)
            resp_auth_header = await client.get(
                "/_gk/api/mode",
                headers={"X-Admin-Token": secret_token},
            )
            assert resp_auth_header.status_code == 200
            assert resp_auth_header.json() == {"mode": "block"}

            # 3. Query param authentication (?token=)
            resp_auth_query = await client.get(f"/_gk/api/mode?token={secret_token}")
            assert resp_auth_query.status_code == 200
            assert resp_auth_query.json() == {"mode": "block"}
        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())


# =============================================================================
# Acceptance Walkthrough: Mode Toggling & Rule Enable/Disable Effects
# =============================================================================


def test_mode_and_rule_acceptance_walkthrough(tmp_path: Any):
    """
    Full Acceptance Test:
    1. In BLOCK mode: attack probe is BLOCKED (403), reached_backend=False.
    2. Toggle to MONITOR mode: same attack is FLAGGED (200), reached_backend=True.
    3. Toggle back to BLOCK mode: same attack is BLOCKED (403), reached_backend=False.
    4. Disable SQLI-UNION rule: probe passes as ALLOWED (200), reached_backend=True.
    5. Re-enable SQLI-UNION rule: probe is BLOCKED (403), reached_backend=False.
    """

    async def _test():
        client, mock_upstream, app = create_admin_test_clients(tmp_path, mode="block")
        try:
            attack_url = "/api/products?search=union select 1,2,3"

            # -------------------------------------------------------------
            # Step 1: BLOCK mode
            # -------------------------------------------------------------
            resp1 = await client.get(attack_url, headers={"X-Forwarded-For": "198.51.100.11"})
            assert resp1.status_code == 403
            data1 = resp1.json()
            assert data1["error"] == "Request blocked"

            # Must NOT reach upstream
            assert len(mock_upstream.received_requests) == 0

            # Drain events
            await asyncio.sleep(0.35)
            events1 = app.state.event_store.get_events(limit=50)
            e1 = next(e for e in events1 if e["incident_id"] == data1["incident_id"])
            assert e1["action"] == "blocked"
            assert e1["reached_backend"] is False

            # -------------------------------------------------------------
            # Step 2: Toggle to MONITOR mode
            # -------------------------------------------------------------
            toggle_resp = await client.post("/_gk/api/mode", json={"mode": "monitor"})
            assert toggle_resp.status_code == 200

            resp2 = await client.get(attack_url, headers={"X-Forwarded-For": "198.51.100.12"})
            assert resp2.status_code == 200
            # Proxied response from upstream
            assert resp2.json()["status"] == "upstream_ok"
            assert len(mock_upstream.received_requests) == 1

            # Drain events
            await asyncio.sleep(0.35)
            events2 = app.state.event_store.get_events(limit=50)
            e2 = next(e for e in events2 if e["client_ip"] == "198.51.100.12")
            assert e2["action"] == "flagged"
            assert e2["reached_backend"] is True

            # -------------------------------------------------------------
            # Step 3: Toggle back to BLOCK mode
            # -------------------------------------------------------------
            toggle_resp2 = await client.post("/_gk/api/mode", json={"mode": "block"})
            assert toggle_resp2.status_code == 200

            resp3 = await client.get(attack_url, headers={"X-Forwarded-For": "198.51.100.13"})
            assert resp3.status_code == 403
            assert len(mock_upstream.received_requests) == 1  # Unchanged

            await asyncio.sleep(0.35)
            events3 = app.state.event_store.get_events(limit=50)
            e3 = next(e for e in events3 if e["client_ip"] == "198.51.100.13")
            assert e3["action"] == "blocked"
            assert e3["reached_backend"] is False

            # -------------------------------------------------------------
            # Step 4: Disable SQLI-001 rule
            # -------------------------------------------------------------
            patch_resp = await client.patch("/_gk/api/rules/SQLI-001", json={"enabled": False})
            assert patch_resp.status_code == 200

            resp4 = await client.get(attack_url, headers={"X-Forwarded-For": "198.51.100.14"})
            assert resp4.status_code == 200  # Allowed now that rule is disabled!
            assert len(mock_upstream.received_requests) == 2

            await asyncio.sleep(0.35)
            events4 = app.state.event_store.get_events(limit=50)
            e4 = next(e for e in events4 if e["client_ip"] == "198.51.100.14")
            assert e4["action"] == "allowed"
            assert e4["reached_backend"] is True

            # -------------------------------------------------------------
            # Step 5: Re-enable SQLI-001 rule
            # -------------------------------------------------------------
            patch_resp2 = await client.patch("/_gk/api/rules/SQLI-001", json={"enabled": True})
            assert patch_resp2.status_code == 200

            resp5 = await client.get(attack_url, headers={"X-Forwarded-For": "198.51.100.15"})
            assert resp5.status_code == 403  # Blocking restored!
            assert len(mock_upstream.received_requests) == 2

            await asyncio.sleep(0.35)
            events5 = app.state.event_store.get_events(limit=50)
            e5 = next(e for e in events5 if e["client_ip"] == "198.51.100.15")
            assert e5["action"] == "blocked"
            assert e5["reached_backend"] is False

        finally:
            await app.state.event_store.stop_worker()
            await client.aclose()
            await app.state.http_client.aclose()

    run_async(_test())
