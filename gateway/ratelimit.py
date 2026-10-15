"""
Rate Limiting, Strikes, and Temporary IP Ban Management (Module M4).
Token bucket rate limiting per client IP (general + login scope),
strike tracking, temporary auto-banning, and lazy expiration pruning with injectable clock.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from gateway.config import GatewayConfig, get_config


class TokenBucket:
    """Token bucket implementation with fractional refill and clock injection."""

    def __init__(
        self,
        capacity: float,
        refill_per_sec: float,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.clock = clock or time.time
        self.tokens = float(capacity)
        self.last_refill = self.clock()

    def consume(
        self,
        tokens: float = 1.0,
        now: float | None = None,
    ) -> tuple[bool, float]:
        """
        Attempt to consume tokens.
        Returns (allowed: bool, retry_after: float).
        """
        current_time = self.clock() if now is None else now
        elapsed = max(0.0, current_time - self.last_refill)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = current_time

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, 0.0

        deficit = tokens - self.tokens
        retry_after = max(1.0, math.ceil(deficit / self.refill_per_sec)) if self.refill_per_sec > 0 else 60.0
        return False, retry_after

    def peek(self, now: float | None = None) -> tuple[bool, float]:
        """Check availability without consuming tokens."""
        current_time = self.clock() if now is None else now
        elapsed = max(0.0, current_time - self.last_refill)
        available = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if available >= 1.0:
            return True, 0.0
        deficit = 1.0 - available
        retry_after = max(1.0, math.ceil(deficit / self.refill_per_sec)) if self.refill_per_sec > 0 else 60.0
        return False, retry_after


class RateLimiter:
    """
    Dual-scope rate limiter managing token buckets keyed by (client_ip, scope).
    Applies stricter capacity/refill to login paths matching path_regex.
    """

    def __init__(
        self,
        config: GatewayConfig | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        cfg = config or get_config()
        self.general_capacity = float(cfg.rate_limit.capacity)
        self.general_refill = float(cfg.rate_limit.refill_per_sec)

        self.login_capacity = float(cfg.login_rate_limit.capacity)
        self.login_refill = float(cfg.login_rate_limit.refill_per_sec)
        self.login_regex = re.compile(cfg.login_rate_limit.path_regex)

        self.clock = clock or time.time
        self._buckets: dict[tuple[str, str], TokenBucket] = {}

    def _get_bucket(self, client_ip: str, scope: str) -> TokenBucket:
        key = (client_ip, scope)
        if key not in self._buckets:
            if scope == "login":
                self._buckets[key] = TokenBucket(
                    capacity=self.login_capacity,
                    refill_per_sec=self.login_refill,
                    clock=self.clock,
                )
            else:
                self._buckets[key] = TokenBucket(
                    capacity=self.general_capacity,
                    refill_per_sec=self.general_refill,
                    clock=self.clock,
                )
        return self._buckets[key]

    def check(
        self,
        client_ip: str,
        path: str,
        consume: bool = True,
        now: float | None = None,
    ) -> tuple[bool, float]:
        """
        Evaluate rate limit for request.
        Returns (allowed: bool, retry_after: float).
        """
        is_login = bool(self.login_regex.search(path))
        scope = "login" if is_login else "general"
        bucket = self._get_bucket(client_ip, scope)

        if consume:
            return bucket.consume(1.0, now=now)
        return bucket.peek(now=now)

    def reset(self) -> None:
        """Clear all active buckets."""
        self._buckets.clear()


@dataclass
class BanEntry:
    ip: str
    reason: str
    banned_at: float
    expires_at: float

    def to_dict(self, now: float) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "banned_at": self.banned_at,
            "expires_at": self.expires_at,
            "remaining_sec": max(0.0, math.ceil(self.expires_at - now)),
        }


class BanManager:
    """
    Tracks strikes and manages temporary IP bans with lazy expiration pruning.
    Strikes: blocked +1, every 20 rate_limited +1.
    >= ban_threshold strikes in window_sec -> ban for ban_sec.
    """

    def __init__(
        self,
        config: GatewayConfig | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        cfg = config or get_config()
        self.window_sec = float(cfg.strikes.window_sec)
        self.ban_threshold = int(cfg.strikes.ban_threshold)
        self.ban_sec = float(cfg.strikes.ban_sec)
        self.rate_limited_per_strike = int(cfg.strikes.rate_limited_per_strike)

        self.clock = clock or time.time
        self._strikes: dict[str, list[float]] = {}
        self._rate_limit_counts: dict[str, int] = {}
        self._bans: dict[str, BanEntry] = {}

    def _prune(self, current_time: float) -> None:
        """Lazily prune expired strikes and expired bans."""
        cutoff = current_time - self.window_sec

        # Prune expired strikes
        expired_ips: list[str] = []
        for ip, timestamps in self._strikes.items():
            valid = [ts for ts in timestamps if ts > cutoff]
            if valid:
                self._strikes[ip] = valid
            else:
                expired_ips.append(ip)
        for ip in expired_ips:
            del self._strikes[ip]

        # Prune expired bans
        expired_bans = [
            ip for ip, entry in self._bans.items() if entry.expires_at <= current_time
        ]
        for ip in expired_bans:
            del self._bans[ip]

    def is_banned(
        self,
        ip: str,
        now: float | None = None,
    ) -> tuple[bool, float]:
        """
        Check if an IP address is currently banned.
        Returns (is_banned: bool, remaining_sec: float).
        """
        current_time = self.clock() if now is None else now
        self._prune(current_time)

        if ip in self._bans:
            entry = self._bans[ip]
            remaining = max(0.0, math.ceil(entry.expires_at - current_time))
            return True, remaining
        return False, 0.0

    def add_strike(
        self,
        ip: str,
        reason: str = "",
        count: int = 1,
        now: float | None = None,
    ) -> bool:
        """
        Add one or more strikes to an IP. If threshold reached, bans IP.
        Returns True if the IP was banned as a result.
        """
        current_time = self.clock() if now is None else now
        self._prune(current_time)

        if ip not in self._strikes:
            self._strikes[ip] = []

        for _ in range(count):
            self._strikes[ip].append(current_time)

        if len(self._strikes[ip]) >= self.ban_threshold:
            ban_reason = reason or f"Accumulated {len(self._strikes[ip])} strikes within {int(self.window_sec)}s"
            self._bans[ip] = BanEntry(
                ip=ip,
                reason=ban_reason,
                banned_at=current_time,
                expires_at=current_time + self.ban_sec,
            )
            # Clear strikes upon banning
            self._strikes.pop(ip, None)
            return True
        return False

    def record_blocked(
        self,
        ip: str,
        reason: str = "",
        now: float | None = None,
    ) -> bool:
        """Record a blocked request (+1 strike)."""
        return self.add_strike(ip, reason=reason or "Blocked request", count=1, now=now)

    def record_rate_limited(
        self,
        ip: str,
        now: float | None = None,
    ) -> bool:
        """Record a rate-limited request (+1 strike per rate_limited_per_strike violations)."""
        current_time = self.clock() if now is None else now
        self._prune(current_time)

        self._rate_limit_counts[ip] = self._rate_limit_counts.get(ip, 0) + 1
        if self._rate_limit_counts[ip] % self.rate_limited_per_strike == 0:
            return self.add_strike(
                ip,
                reason=f"Repeated rate limit violations ({self.rate_limited_per_strike} events)",
                count=1,
                now=current_time,
            )
        return False

    def list_bans(self, now: float | None = None) -> list[dict[str, Any]]:
        """Return all currently active bans."""
        current_time = self.clock() if now is None else now
        self._prune(current_time)
        return [entry.to_dict(current_time) for entry in self._bans.values()]

    def unban(self, ip: str) -> bool:
        """Manually unban an IP address."""
        existed = False
        if ip in self._bans:
            del self._bans[ip]
            existed = True
        if ip in self._strikes:
            del self._strikes[ip]
        if ip in self._rate_limit_counts:
            del self._rate_limit_counts[ip]
        return existed


_DEFAULT_RATE_LIMITER: RateLimiter | None = None
_DEFAULT_BAN_MANAGER: BanManager | None = None


def get_rate_limiter(config: GatewayConfig | None = None) -> RateLimiter:
    """Return globally cached RateLimiter instance."""
    global _DEFAULT_RATE_LIMITER
    if _DEFAULT_RATE_LIMITER is None or config is not None:
        _DEFAULT_RATE_LIMITER = RateLimiter(config=config)
    return _DEFAULT_RATE_LIMITER


def get_ban_manager(config: GatewayConfig | None = None) -> BanManager:
    """Return globally cached BanManager instance."""
    global _DEFAULT_BAN_MANAGER
    if _DEFAULT_BAN_MANAGER is None or config is not None:
        _DEFAULT_BAN_MANAGER = BanManager(config=config)
    return _DEFAULT_BAN_MANAGER
