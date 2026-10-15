"""
Rate Limiting, Strikes, and Bans Unit Tests (Module M4).
Uses an injectable fake clock for deterministic, fast testing of token buckets,
login limits, strikes, bans, and IP independence without sleeping.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from gateway.config import GatewayConfig
from gateway.main import create_app
from gateway.models import RequestContext
from gateway.pipeline import inspect
from gateway.ratelimit import BanManager, RateLimiter, TokenBucket
from gateway.rules import RuleManager


class FakeClock:
    """Controllable clock for fast, deterministic time simulation."""

    def __init__(self, start_time: float = 1_000_000.0) -> None:
        self.current_time = start_time

    def time(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


def run_async(coro: Any) -> Any:
    return asyncio.run(coro)


# -----------------------------------------------------------------------------
# Unit Tests: TokenBucket
# -----------------------------------------------------------------------------


def test_token_bucket_consume_and_refill():
    """Verify TokenBucket capacity, consumption, and fractional refill using fake clock."""
    clock = FakeClock()
    bucket = TokenBucket(capacity=5, refill_per_sec=1.0, clock=clock.time)

    # Consume all 5 tokens
    for _ in range(5):
        allowed, retry_after = bucket.consume()
        assert allowed is True
        assert retry_after == 0.0

    # 6th attempt should be rejected
    allowed, retry_after = bucket.consume()
    assert allowed is False
    assert retry_after >= 1.0

    # Advance clock by 2 seconds -> 2 tokens should be refilled
    clock.advance(2.0)
    allowed1, _ = bucket.consume()
    allowed2, _ = bucket.consume()
    allowed3, _ = bucket.consume()
    assert allowed1 is True
    assert allowed2 is True
    assert allowed3 is False


# -----------------------------------------------------------------------------
# Unit Tests: RateLimiter & Scopes
# -----------------------------------------------------------------------------


def test_general_rate_limit_20_pass_rest_429():
    """Verify 30 rapid requests to general endpoint: first 20 pass, rest get 429."""
    clock = FakeClock()
    cfg = GatewayConfig()
    cfg.rate_limit.capacity = 20
    cfg.rate_limit.refill_per_sec = 5.0
    limiter = RateLimiter(config=cfg, clock=clock.time)

    client_ip = "198.51.100.1"
    results = [limiter.check(client_ip, "/api/products")[0] for _ in range(30)]

    assert results[:20] == [True] * 20
    assert results[20:] == [False] * 10


def test_login_rate_limit_sixth_attempt_429():
    """Verify 6th login attempt within a minute gets 429."""
    clock = FakeClock()
    cfg = GatewayConfig()
    cfg.login_rate_limit.capacity = 5
    cfg.login_rate_limit.refill_per_sec = 0.0833
    limiter = RateLimiter(config=cfg, clock=clock.time)

    client_ip = "198.51.100.2"
    results = [limiter.check(client_ip, "/api/login")[0] for _ in range(6)]

    assert results[:5] == [True] * 5
    assert results[5] is False


def test_rate_limiter_client_ip_independence():
    """Verify that exhausting IP 1 does not affect IP 2."""
    clock = FakeClock()
    cfg = GatewayConfig()
    cfg.rate_limit.capacity = 5
    limiter = RateLimiter(config=cfg, clock=clock.time)

    ip1 = "198.51.100.10"
    ip2 = "198.51.100.20"

    # Exhaust IP 1
    for _ in range(5):
        assert limiter.check(ip1, "/api/products")[0] is True
    assert limiter.check(ip1, "/api/products")[0] is False

    # IP 2 should still be allowed
    assert limiter.check(ip2, "/api/products")[0] is True


# -----------------------------------------------------------------------------
# Unit Tests: Strikes & Bans
# -----------------------------------------------------------------------------


def test_three_strikes_trigger_ban_and_expiry():
    """Verify 3 strikes inside 60 s trigger a ban for 120 s, and ban expires cleanly."""
    clock = FakeClock()
    cfg = GatewayConfig()
    cfg.strikes.window_sec = 60
    cfg.strikes.ban_threshold = 3
    cfg.strikes.ban_sec = 120
    bm = BanManager(config=cfg, clock=clock.time)

    ip = "203.0.113.5"
    assert bm.is_banned(ip)[0] is False

    # Strike 1
    clock.advance(5)
    banned = bm.record_blocked(ip, reason="Attack 1")
    assert banned is False
    assert bm.is_banned(ip)[0] is False

    # Strike 2
    clock.advance(10)
    banned = bm.record_blocked(ip, reason="Attack 2")
    assert banned is False
    assert bm.is_banned(ip)[0] is False

    # Strike 3 within window -> BANNED
    clock.advance(10)
    banned = bm.record_blocked(ip, reason="Attack 3")
    assert banned is True

    # Check ban state
    is_banned, remaining = bm.is_banned(ip)
    assert is_banned is True
    assert remaining == 120

    # Advance 60s -> Still banned
    clock.advance(60)
    is_banned, remaining = bm.is_banned(ip)
    assert is_banned is True
    assert remaining == 60

    # Advance another 61s (total 121s) -> Ban EXPIRED
    clock.advance(61)
    is_banned, remaining = bm.is_banned(ip)
    assert is_banned is False


def test_rate_limiting_accrues_strikes():
    """Verify that every 20 rate limit events accrue 1 strike, and 60 events ban."""
    clock = FakeClock()
    cfg = GatewayConfig()
    cfg.strikes.ban_threshold = 3
    cfg.strikes.rate_limited_per_strike = 20
    bm = BanManager(config=cfg, clock=clock.time)

    ip = "203.0.113.99"

    # 19 rate limits: no strike
    for _ in range(19):
        assert bm.record_rate_limited(ip) is False

    # 20th rate limit: 1st strike
    assert bm.record_rate_limited(ip) is False

    # 40th rate limit: 2nd strike
    for _ in range(19):
        bm.record_rate_limited(ip)
    assert bm.record_rate_limited(ip) is False

    # 60th rate limit: 3rd strike -> BANNED!
    for _ in range(19):
        bm.record_rate_limited(ip)
    assert bm.record_rate_limited(ip) is True
    assert bm.is_banned(ip)[0] is True


# -----------------------------------------------------------------------------
# End-to-End Pipeline & Route Tests
# -----------------------------------------------------------------------------


def test_e2e_rate_limit_and_ban_pipeline():
    """Verify gateway responses: 429 with Retry-After, and 403 on temporary ban."""

    async def _test():
        clock = FakeClock()
        cfg = GatewayConfig(upstream_url="http://upstream.test")
        cfg.rate_limit.capacity = 2
        cfg.rate_limit.refill_per_sec = 0.5
        cfg.strikes.ban_threshold = 2
        cfg.strikes.ban_sec = 60

        rate_limiter = RateLimiter(config=cfg, clock=clock.time)
        ban_manager = BanManager(config=cfg, clock=clock.time)
        rules_mgr = RuleManager("config/rules.yaml")

        def mock_upstream(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": "ok"})

        app = create_app(
            config=cfg,
            rule_manager=rules_mgr,
            rate_limiter=rate_limiter,
            ban_manager=ban_manager,
        )
        app.state.http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(mock_upstream),
            base_url="http://upstream.test",
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gateway.test",
        ) as client:
            # 1. First 2 requests pass
            r1 = await client.get("/api/products")
            assert r1.status_code == 200
            r2 = await client.get("/api/products")
            assert r2.status_code == 200

            # 2. 3rd request gets 429 with Retry-After
            r3 = await client.get("/api/products")
            assert r3.status_code == 429
            assert "retry-after" in r3.headers
            assert r3.json()["error"] == "Too Many Requests"

            # Advance clock so rate limit bucket refills
            clock.advance(10.0)

            # 3. Simulate two blocked attack requests -> triggers 2 strikes -> BAN
            rb1 = await client.get("/api/products?search=' UNION SELECT 1,2,3--")
            assert rb1.status_code == 403
            assert rb1.json()["error"] == "Request blocked"

            rb2 = await client.get("/api/products?search=' UNION SELECT 1,2,3--")
            assert rb2.status_code == 403
            assert rb2.json()["error"] == "Request blocked"

            # 4. Next benign request receives 403 IP temporarily banned
            r_banned = await client.get("/api/products")
            assert r_banned.status_code == 403
            assert r_banned.json()["error"] == "IP temporarily banned"
            assert "retry-after" in r_banned.headers

        await app.state.http_client.aclose()

    run_async(_test())


def test_token_bucket_peek_does_not_consume():
    """Verify that peek() returns availability without consuming any tokens."""
    bucket = TokenBucket(capacity=2, refill_per_sec=0.0)
    allowed, retry = bucket.peek()
    assert allowed is True
    assert retry == 0.0

    # Bucket still has full tokens
    allowed1, _ = bucket.consume()
    assert allowed1 is True
    allowed2, _ = bucket.consume()
    assert allowed2 is True
    # Now empty
    allowed3, _ = bucket.consume()
    assert allowed3 is False


def test_lazy_expiration_pruning_and_unban():
    """Verify lazy pruning of expired bans and manual unban restoration."""
    clock = FakeClock()
    cfg = GatewayConfig()
    cfg.strikes.ban_threshold = 2
    cfg.strikes.ban_sec = 30
    ban_mgr = BanManager(config=cfg, clock=clock.time)

    ip = "198.51.100.88"
    ban_mgr.add_strike(ip, count=2)
    is_b, _ = ban_mgr.is_banned(ip)
    assert is_b is True

    # Active bans list contains the entry
    active = ban_mgr.list_bans()
    assert any(b["ip"] == ip for b in active)

    # Advance clock past ban duration (35s)
    clock.advance(35.0)

    # Check is_banned should now report False and prune the ban
    is_b_after, _ = ban_mgr.is_banned(ip)
    assert is_b_after is False
    assert len(ban_mgr.list_bans()) == 0

