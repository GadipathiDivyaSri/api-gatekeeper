"""
Inspection Pipeline Module (Module M3).
Orchestrates normalization, signature matching, and risk scoring to produce a Decision.
Pure and deterministic for reuse in proxying, dry-run (/ _gk/api/test), and benchmarking.
"""

from __future__ import annotations

from gateway.config import GatewayConfig, get_config
from gateway.models import Decision, RequestContext
from gateway.normalizer import build_targets
from gateway.rules import RuleManager, get_rule_manager


def inspect(
    ctx: RequestContext,
    config: GatewayConfig | None = None,
    rules_manager: RuleManager | None = None,
) -> Decision:
    """
    Pure inspection function evaluating request context against security rules.
    Does not forward, write to DB, or mutate rate limiting/ban state.
    """
    active_config = config or get_config()
    active_rules = rules_manager or get_rule_manager()

    # 1. Normalise inspection targets
    variants_by_target = build_targets(ctx)

    # 2. Match signature rules (including bot rules)
    findings = active_rules.match(variants_by_target)

    # 3. Sum distinct rule scores
    total_score = sum(f.score for f in findings)
    threshold = active_config.block_threshold

    # 4. Determine action based on threshold and mode
    if total_score >= threshold:
        if active_config.mode == "block":
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
