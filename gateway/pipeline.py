"""
Inspection Pipeline Module (Modules M3 & M4).
Orchestrates ban checks, dual-scope rate limiting, multi-decode normalization,
signature rule matching, and risk scoring to produce a Decision.
Pure and deterministic for reuse in proxying, dry-run (/ _gk/api/test), and benchmarking.
"""

from __future__ import annotations

from gateway.config import GatewayConfig, get_config
from gateway.models import Decision, RequestContext
from gateway.normalizer import build_targets
from gateway.ratelimit import BanManager, RateLimiter, get_ban_manager, get_rate_limiter
from gateway.rules import RuleManager, get_rule_manager


def inspect(
    ctx: RequestContext,
    config: GatewayConfig | None = None,
    rules_manager: RuleManager | None = None,
    contract_manager: Any | None = None,
    rate_limiter: RateLimiter | None = None,
    ban_manager: BanManager | None = None,
    dry_run: bool = False,
    now: float | None = None,
) -> Decision:
    """
    Evaluate request context through Gatekeeper inspection layers:
    1. Ban check (active temporary bans).
    2. Rate limit check (general or login scope).
    3. Normalization (multi-decode variants, JSON/form extraction).
    4. OpenAPI Contract Guard (allow-list, schema, parameter validation).
    5. Signature matching (declared targets).
    6. Risk scoring and action determination (allowed / flagged / blocked).
    """
    active_config = config or get_config()
    if active_config.mode == "off":
        return Decision(
            action="allowed",
            score=0,
            findings=[],
            status_code=200,
            reason="Gateway inspection disabled (off mode)",
        )
    active_rules = rules_manager or get_rule_manager()

    # 1. Ban Check (skip if ban_manager is explicitly None in dry-runs without ban tracking)
    active_bans = ban_manager if ban_manager is not None else (None if dry_run else get_ban_manager(active_config))
    if active_bans is not None:
        is_banned, remaining_sec = active_bans.is_banned(ctx.client_ip, now=now)
        if is_banned:
            return Decision(
                action="banned",
                score=0,
                findings=[],
                status_code=403,
                reason=f"Client IP {ctx.client_ip} is temporarily banned ({int(remaining_sec)}s remaining)",
                retry_after=int(remaining_sec),
            )

    # 2. Rate Limit Check (skip if rate_limiter is explicitly None in dry-runs)
    active_rl = rate_limiter if rate_limiter is not None else (None if dry_run else get_rate_limiter(active_config))
    if active_rl is not None:
        allowed, retry_after = active_rl.check(
            client_ip=ctx.client_ip,
            path=ctx.path,
            consume=not dry_run,
            now=now,
        )
        if not allowed:
            if not dry_run and active_bans is not None:
                active_bans.record_rate_limited(ctx.client_ip, now=now)
            return Decision(
                action="rate_limited",
                score=0,
                findings=[],
                status_code=429,
                reason="Rate limit capacity exceeded",
                retry_after=int(retry_after),
            )

    # 3. Normalise inspection targets
    variants_by_target = build_targets(ctx)

    # 4. OpenAPI Contract Guard (positive security model)
    contract_findings = []
    if contract_manager is not None:
        contract_findings = contract_manager.validate(ctx)

    # 5. Match signature rules
    signature_findings = active_rules.match(variants_by_target)
    findings = contract_findings + signature_findings

    # 6. Sum rule scores
    total_score = sum(f.score for f in findings)
    threshold = active_config.block_threshold

    # 6. Determine action based on threshold and mode
    if total_score >= threshold:
        if active_config.mode == "block":
            if not dry_run and active_bans is not None:
                active_bans.record_blocked(
                    ctx.client_ip,
                    reason=f"Blocked for security findings: {[f.rule_id for f in findings]}",
                    now=now,
                )
            return Decision(
                action="blocked",
                score=total_score,
                findings=findings,
                status_code=403,
                reason=f"Security score {total_score} meets or exceeds block threshold {threshold}",
            )
        else:
            return Decision(
                action="flagged",
                score=total_score,
                findings=findings,
                status_code=200,
                reason=f"Security score {total_score} meets or exceeds threshold {threshold} (monitor mode)",
            )

    return Decision(
        action="allowed",
        score=total_score,
        findings=findings,
        status_code=200,
        reason="Request passed security inspection",
    )
