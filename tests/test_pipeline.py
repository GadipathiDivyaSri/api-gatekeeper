"""
Pipeline Unit Tests (Module M3).
Verifies scoring threshold arithmetic, mode behavior (block vs monitor),
and reverse proxy catch-all blocking integration.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from gateway.config import GatewayConfig
from gateway.main import create_app
from gateway.models import Finding, RequestContext
from gateway.normalizer import Variant
from gateway.pipeline import inspect
from gateway.rules import Rule, RuleManager


def run_async(coro: Any) -> Any:
    return asyncio.run(coro)


class MockCustomRulesManager(RuleManager):
    """RuleManager stub returning predefined findings for threshold arithmetic testing."""

    def __init__(self, stub_findings: list[Finding]):
        self._stub_findings = stub_findings

    def match(self, variants_by_target: dict[str, list[Variant]]) -> list[Finding]:
        return self._stub_findings


def test_threshold_arithmetic_one_critical_blocks():
    """Verify that a single critical finding (score 5) meets threshold 5 and blocks."""
    critical_finding = Finding(
        layer="signatures",
        rule_id="TEST-CRIT-01",
        name="Critical Exploit",
        category="sqli",
        score=5,
        matched="UNION SELECT",
        target="query",
    )
    rules_mgr = MockCustomRulesManager([critical_finding])
    cfg = GatewayConfig(mode="block", block_threshold=5)

    ctx = RequestContext(
        incident_id="AG-TEST-CRIT",
        client_ip="127.0.0.1",
        method="GET",
        path="/api/products",
    )
    decision = inspect(ctx, config=cfg, rules_manager=rules_mgr)

    assert decision.score == 5
    assert decision.action == "blocked"
    assert decision.status_code == 403


def test_threshold_arithmetic_low_plus_low_allowed():
    """Verify that low (2) + low (2) = 4 < 5 does NOT block."""
    low1 = Finding(
        layer="signatures",
        rule_id="TEST-LOW-01",
        name="Low signal 1",
        category="bot",
        score=2,
        matched="ua-short",
        target="ua",
    )
    low2 = Finding(
        layer="signatures",
        rule_id="TEST-LOW-02",
        name="Low signal 2",
        category="bot",
        score=2,
        matched="ua-empty",
        target="ua",
    )
    rules_mgr = MockCustomRulesManager([low1, low2])
    cfg = GatewayConfig(mode="block", block_threshold=5)

    ctx = RequestContext(
        incident_id="AG-TEST-LOWS",
        client_ip="127.0.0.1",
        method="GET",
        path="/api/products",
    )
    decision = inspect(ctx, config=cfg, rules_manager=rules_mgr)

    assert decision.score == 4
    assert decision.action == "allowed"
    assert decision.status_code == 200


def test_threshold_arithmetic_low_plus_medium_blocks():
    """Verify that low (2) + medium (3) = 5 >= 5 blocks."""
    low = Finding(
        layer="signatures",
        rule_id="TEST-LOW-01",
        name="Low signal",
        category="bot",
        score=2,
        matched="ua-short",
        target="ua",
    )
    med = Finding(
        layer="signatures",
        rule_id="TEST-MED-01",
        name="Medium signal",
        category="xss",
        score=3,
        matched="<img>",
        target="body",
    )
    rules_mgr = MockCustomRulesManager([low, med])
    cfg = GatewayConfig(mode="block", block_threshold=5)

    ctx = RequestContext(
        incident_id="AG-TEST-LOW-MED",
        client_ip="127.0.0.1",
        method="GET",
        path="/api/products",
    )
    decision = inspect(ctx, config=cfg, rules_manager=rules_mgr)

    assert decision.score == 5
    assert decision.action == "blocked"
    assert decision.status_code == 403


def test_monitor_mode_marks_flagged():
    """Verify that in monitor mode, score >= threshold forwards with action 'flagged'."""
    critical_finding = Finding(
        layer="signatures",
        rule_id="TEST-CRIT-01",
        name="Critical Exploit",
        category="sqli",
        score=5,
        matched="UNION SELECT",
        target="query",
    )
    rules_mgr = MockCustomRulesManager([critical_finding])
    cfg = GatewayConfig(mode="monitor", block_threshold=5)

    ctx = RequestContext(
        incident_id="AG-TEST-MONITOR",
        client_ip="127.0.0.1",
        method="GET",
        path="/api/products",
    )
    decision = inspect(ctx, config=cfg, rules_manager=rules_mgr)

    assert decision.score == 5
    assert decision.action == "flagged"
    assert decision.status_code == 200


def test_catch_all_blocks_request_and_upstream_never_called():
    """Verify that a blocked request returns 403 JSON and never hits the upstream service."""

    async def _test():
        received_at_upstream: list[httpx.Request] = []

        def mock_upstream(request: httpx.Request) -> httpx.Response:
            received_at_upstream.append(request)
            return httpx.Response(status_code=200, json={"status": "upstream_called"})

        # Gateway configured in block mode with real rules
        cfg = GatewayConfig(upstream_url="http://upstream.test", mode="block")
        rules_mgr = RuleManager("config/rules.yaml")
        app = create_app(config=cfg, rule_manager=rules_mgr)

        app.state.http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(mock_upstream),
            base_url="http://upstream.test",
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gateway.test",
        ) as client:
            # 1. Malicious SQLi request -> Blocked at gateway
            resp_blocked = await client.get("/api/products?search=' UNION SELECT 1,2,3--")
            assert resp_blocked.status_code == 403
            data = resp_blocked.json()
            assert data["error"] == "Request blocked"
            assert data["incident_id"].startswith("AG-")

            # Must NEVER reach upstream!
            assert len(received_at_upstream) == 0

            # 2. Benign request -> Allowed through
            resp_allowed = await client.get("/api/products?search=phone")
            assert resp_allowed.status_code == 200
            assert len(received_at_upstream) == 1

        await app.state.http_client.aclose()

    run_async(_test())
