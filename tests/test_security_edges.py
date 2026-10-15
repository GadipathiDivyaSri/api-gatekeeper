"""
Comprehensive Security, Concurrency, and Edge-Case Tests.
Validates:
1. ReDoS resistance across all 16 signature rules under pathological inputs.
2. Information leakage prevention and sensitive header removal.
3. SQL parameterization immunity against injection payloads in event store queries.
4. Rate limiting and strike threshold exact boundary behavior.
5. Mode switching dynamics (block, monitor, off).
6. Hold-out benign corpus zero false positive verification.
"""

from __future__ import annotations

import time
import pytest
from fastapi.testclient import TestClient

from backend.app import app as backend_app
from gateway.config import GatewayConfig
from gateway.contract import ContractManager
from gateway.events import EventStore
from gateway.main import create_app
from gateway.models import Event, Finding, RequestContext
from gateway.normalizer import normalize_string
from gateway.pipeline import inspect
from gateway.ratelimit import BanManager, RateLimiter
from gateway.rules import RuleManager
from gateway.shield import apply_shield_headers, create_masked_error_response, should_mask_response


# -----------------------------------------------------------------------------
# 1. ReDoS Resilience Tests
# -----------------------------------------------------------------------------


def test_redos_resilience_all_rules() -> None:
    """
    Verify that pathological inputs with repeating tokens and characters do not
    cause exponential backtracking or CPU stalls in signature rules.
    """
    rule_mgr = RuleManager()
    pathological_samples = [
        "A" * 5000,
        "union select " * 200,
        "((((" * 100 + "))))" * 100,
        "../" * 500,
        "${${${" * 50 + "jndi:" + "}}}" * 50,
        "'" + " " * 1000 + "--",
        "<" * 500 + "script" + ">" * 500,
        "cat " * 200 + "; " * 200,
        "http://127.0.0.1/" + "a/" * 500,
        "nikto " * 200,
        "%0d%0a" * 100 + "Header: value",
    ]

    for sample in pathological_samples:
        variants = normalize_string(sample)
        targets = {
            "path": variants,
            "query": variants,
            "body": variants,
            "headers": variants,
            "ua": variants,
        }

        t0 = time.perf_counter()
        findings = rule_mgr.match(targets)
        elapsed = time.perf_counter() - t0

        # Each match must complete in well under 50ms
        assert elapsed < 0.05, f"ReDoS suspected: rule match took {elapsed*1000:.2f}ms on payload: {sample[:30]}..."


# -----------------------------------------------------------------------------
# 2. Information Disclosure & Response Shielding Tests
# -----------------------------------------------------------------------------


def test_response_shield_strips_sensitive_headers() -> None:
    """Verify that backend server fingerprinting headers are removed."""
    dirty_headers = {
        "Server": "Werkzeug/2.0.1 Python/3.9.7",
        "X-Powered-By": "Express / FastAPI",
        "Content-Type": "application/json",
        "Content-Length": "42",
        "Connection": "keep-alive",
    }
    sanitized = apply_shield_headers(dirty_headers)

    # Leaking headers must be stripped
    assert "server" not in sanitized
    assert "Server" not in sanitized
    assert "x-powered-by" not in sanitized
    assert "X-Powered-By" not in sanitized
    assert "connection" not in sanitized

    # Defensive headers must be present
    assert sanitized["X-Content-Type-Options"] == "nosniff"
    assert sanitized["X-Frame-Options"] == "DENY"
    assert sanitized["Referrer-Policy"] == "no-referrer"
    assert sanitized["Cache-Control"] == "no-store"
    assert sanitized["Content-Security-Policy"] == "default-src 'none'"


def test_masked_error_response_format() -> None:
    """Verify that 500 errors produce generic error JSON with incident_id and no leakages."""
    incident_id = "AG-20261015-120000-abcd"
    masked_resp = create_masked_error_response(500, incident_id, base_headers={"Server": "InternalServer"})

    assert masked_resp.status_code == 500
    import json
    body = json.loads(masked_resp.body)
    assert body["error"] == "Internal error"
    assert body["incident_id"] == incident_id
    assert "traceback" not in body
    assert "stack" not in body
    assert "exception" not in body
    assert "Server" not in masked_resp.headers


# -----------------------------------------------------------------------------
# 3. SQL Injection Parameterization Immunity in Events Store
# -----------------------------------------------------------------------------


def test_event_store_sql_injection_resilience(tmp_path) -> None:
    """Verify that malicious SQL syntax in event fields does not break queries."""
    store = EventStore(data_dir=tmp_path)

    # Malicious injection string in fields
    sqli_str = "127.0.0.1'; DROP TABLE events; --"
    ev = Event(
        incident_id="AG-INJECT-001",
        ts=time.time(),
        client_ip=sqli_str,
        method="GET",
        path="/api/test' OR '1'='1",
        query="search=' OR 1=1--",
        user_agent="Mozilla/5.0' UNION SELECT 1,2,3--",
        body_excerpt="{'data': 'drop table'}",
        decoded_excerpt="test",
        action="blocked",
        score=5,
        primary_category="sqli",
        severity="critical",
        findings=[],
        status_code=403,
        latency_ms=0.5,
        upstream_ms=0.0,
        reached_backend=False,
    )

    conn = store.get_connection()
    try:
        # Batch insert with parameterized query
        with conn:
            conn.execute(
                """
                INSERT INTO events (
                    incident_id, ts, client_ip, method, path, query, user_agent,
                    body_excerpt, decoded_excerpt, action, score, primary_category,
                    severity, findings, status_code, latency_ms, upstream_ms, reached_backend
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    ev.incident_id, ev.ts, ev.client_ip, ev.method, ev.path,
                    ev.query, ev.user_agent, ev.body_excerpt, ev.decoded_excerpt,
                    ev.action, ev.score, ev.primary_category, ev.severity,
                    "[]", ev.status_code, ev.latency_ms, ev.upstream_ms, 0
                ),
            )
    finally:
        conn.close()

    # Query using functions that use parameterized filters
    events = store.get_events(limit=10, action="blocked", category="sqli")
    assert len(events) == 1
    assert events[0]["client_ip"] == sqli_str

    incident = store.get_event_by_incident_id("AG-INJECT-001")
    assert incident is not None
    assert incident["incident_id"] == "AG-INJECT-001"

    top = store.get_top_attackers(limit=5)
    assert len(top) == 1
    assert top[0]["client_ip"] == sqli_str

    # Table still exists and is not dropped
    conn2 = store.get_connection()
    try:
        cursor = conn2.cursor()
        cursor.execute("SELECT COUNT(*) FROM events;")
        count = cursor.fetchone()[0]
        assert count == 1
    finally:
        conn2.close()


# -----------------------------------------------------------------------------
# 4. Rate Limiting & Strike Threshold Boundary Tests
# -----------------------------------------------------------------------------


def test_rate_limiter_and_ban_manager_exact_strikes() -> None:
    """Verify that exactly strike_threshold triggers an active ban."""
    config = GatewayConfig()
    config.strikes.ban_threshold = 3
    config.strikes.ban_sec = 60

    ban_mgr = BanManager(config)
    rl = RateLimiter(config)

    ip = "198.51.100.99"

    # Strike 1
    banned1 = ban_mgr.add_strike(ip, "Attack 1")
    assert banned1 is False
    is_b1, _ = ban_mgr.is_banned(ip)
    assert is_b1 is False

    # Strike 2
    banned2 = ban_mgr.add_strike(ip, "Attack 2")
    assert banned2 is False
    is_b2, _ = ban_mgr.is_banned(ip)
    assert is_b2 is False

    # Strike 3: exactly hits threshold -> banned!
    banned3 = ban_mgr.add_strike(ip, "Attack 3")
    assert banned3 is True
    is_b3, rem_sec = ban_mgr.is_banned(ip)
    assert is_b3 is True
    assert rem_sec > 0

    # Rate limiter check still respects rate limit bucket
    allowed, retry = rl.check(ip, "/api/products")
    assert allowed is True

    # Unban IP
    unbanned = ban_mgr.unban(ip)
    assert unbanned is True
    is_b4, _ = ban_mgr.is_banned(ip)
    assert is_b4 is False


# -----------------------------------------------------------------------------
# 5. Gateway Mode Dynamics (Block, Monitor, Off)
# -----------------------------------------------------------------------------


def test_pipeline_mode_transitions() -> None:
    """Verify inspection behavior across block, monitor, and off modes."""
    rule_mgr = RuleManager()

    attack_ctx = RequestContext(
        incident_id="AG-MODE-TEST",
        client_ip="198.51.100.5",
        method="POST",
        path="/api/products",
        body_text="<script>alert(1)</script>",
        user_agent="Mozilla/5.0",
    )

    # 1. BLOCK mode: action is 'blocked', status_code is 403
    cfg_block = GatewayConfig(mode="block")
    dec_block = inspect(attack_ctx, config=cfg_block, rules_manager=rule_mgr)
    assert dec_block.action == "blocked"
    assert dec_block.status_code == 403

    # 2. MONITOR mode: action is 'flagged', status_code is 200 (allowed to proceed)
    cfg_monitor = GatewayConfig(mode="monitor")
    dec_monitor = inspect(attack_ctx, config=cfg_monitor, rules_manager=rule_mgr)
    assert dec_monitor.action == "flagged"
    assert dec_monitor.status_code == 200
    assert len(dec_monitor.findings) > 0

    # 3. OFF mode: action is 'allowed', findings are empty, completely bypassed
    cfg_off = GatewayConfig(mode="off")
    dec_off = inspect(attack_ctx, config=cfg_off, rules_manager=rule_mgr)
    assert dec_off.action == "allowed"
    assert dec_off.status_code == 200
    assert len(dec_off.findings) == 0


# -----------------------------------------------------------------------------
# 6. Benchmark Hold-Out Benign Zero False Positive Validation
# -----------------------------------------------------------------------------


def test_benign_corpus_zero_false_positives() -> None:
    """Verify that representative realistic benign traffic never triggers false positives."""
    rule_mgr = RuleManager()
    cfg_block = GatewayConfig(mode="block")
    benign_samples = [
        ("GET", "/api/products", "category=electronics&limit=10", ""),
        ("GET", "/api/products/1", "", ""),
        ("POST", "/api/feedback", "", '{"product_id": 1, "comment": "Great product! Works well with 5V power."}'),
        ("POST", "/api/feedback", "", '{"product_id": 2, "comment": "Can you explain: standard deviation = sqrt(variance)?"}'),
        ("POST", "/api/login", "", '{"username": "alice", "password": "AlicePassword123!"}'),
        ("POST", "/api/register", "", '{"username": "charlie_brown", "email": "charlie@example.com", "password": "SecurePassword#99"}'),
        ("GET", "/api/orders/101", "", ""),
        ("GET", "/api/health", "", ""),
    ]

    for method, path, query, body in benign_samples:
        ctx = RequestContext(
            incident_id="BENIGN-VERIFY",
            client_ip="192.168.1.50",
            method=method,
            path=path,
            query_string=query,
            query_params={k: [v] for k, v in [pair.split("=") for pair in query.split("&")]} if query else {},
            body_text=body,
            body_bytes=body.encode("utf-8"),
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        dec = inspect(ctx, config=cfg_block, rules_manager=rule_mgr)
        assert dec.action == "allowed", f"False positive triggered on benign sample: {method} {path} ? {query} Body: {body} - Findings: {dec.findings}"
        assert dec.score == 0

