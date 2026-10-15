"""
Signature Rules Engine (Module M3).
Loads, compiles, validates, and matches YAML signature rules against normalized targets.
Supports hot-reload and dynamic enabling/disabling of rules.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from gateway.models import Finding
from gateway.normalizer import Variant

logger = logging.getLogger("api_gatekeeper.rules")


@dataclass
class Rule:
    """A compiled signature rule."""

    id: str
    name: str
    category: str
    pattern: str
    compiled: re.Pattern | None
    targets: list[str]
    score: int
    severity: str
    cwe: str = ""
    owasp: str = ""
    attack: str = ""
    enabled: bool = True


class RuleManager:
    """Manages loading, precompilation, hot-reloading, and matching of rules."""

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self.rules_path = Path(rules_path) if rules_path else Path("config/rules.yaml")
        self._rules: dict[str, Rule] = {}
        self.load_rules(self.rules_path)

    def load_rules(self, path: Path | str) -> int:
        """Load and compile rules from YAML file, skipping invalid patterns."""
        target_path = Path(path)
        if not target_path.is_file():
            logger.warning("Rules file not found at %s", target_path)
            return 0

        with open(target_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw_rules = data.get("rules", [])
        loaded_count = 0
        new_rules: dict[str, Rule] = {}

        for item in raw_rules:
            rule_id = item.get("id")
            pattern_str = item.get("pattern", "")
            if not rule_id or not pattern_str:
                logger.warning("Skipping rule with missing id or pattern: %s", item)
                continue

            try:
                compiled = re.compile(pattern_str)
            except re.error as err:
                logger.error("Skipping rule %s: invalid regex '%s': %s", rule_id, pattern_str, err)
                continue

            rule = Rule(
                id=str(rule_id),
                name=str(item.get("name", rule_id)),
                category=str(item.get("category", "general")),
                pattern=pattern_str,
                compiled=compiled,
                targets=[str(t).lower() for t in item.get("targets", [])],
                score=int(item.get("score", 5)),
                severity=str(item.get("severity", "medium")),
                cwe=str(item.get("cwe", "")),
                owasp=str(item.get("owasp", "")),
                attack=str(item.get("attack", "")),
                enabled=bool(item.get("enabled", True)),
            )
            new_rules[rule.id] = rule
            loaded_count += 1

        self._rules = new_rules
        logger.info("Loaded %d signature rules from %s", loaded_count, target_path)
        return loaded_count

    def reload(self) -> int:
        """Hot-reload rules from disk."""
        return self.load_rules(self.rules_path)

    def get_rules(self) -> list[Rule]:
        """Return all loaded rules."""
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get rule by ID."""
        return self._rules.get(rule_id)

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule dynamically."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = enabled
            return True
        return False

    def match(self, variants_by_target: dict[str, list[Variant]]) -> list[Finding]:
        """
        Evaluate all enabled rules against normalized variants.
        Returns a list of distinct findings (one finding per matched rule).
        """
        findings: list[Finding] = []

        for rule in self._rules.values():
            if not rule.enabled or not rule.compiled:
                continue

            matched_finding: Finding | None = None

            for target in rule.targets:
                variants = variants_by_target.get(target, [])
                for variant in variants:
                    # Match against normalized variant text
                    match_obj = rule.compiled.search(variant.text)
                    if not match_obj and variant.text:
                        # Fallback case-folded match
                        match_obj = rule.compiled.search(variant.text.lower())

                    if match_obj:
                        matched_snippet = match_obj.group(0)
                        matched_finding = Finding(
                            layer="signatures",
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            score=rule.score,
                            matched=matched_snippet,
                            target=target,
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                            attack=rule.attack,
                        )
                        break

                if matched_finding:
                    break

            if matched_finding:
                findings.append(matched_finding)

        return findings


_DEFAULT_RULE_MANAGER: RuleManager | None = None


def get_rule_manager(rules_path: Path | str | None = None) -> RuleManager:
    """Return globally cached RuleManager or initialize a new one."""
    global _DEFAULT_RULE_MANAGER
    if _DEFAULT_RULE_MANAGER is None or rules_path is not None:
        _DEFAULT_RULE_MANAGER = RuleManager(rules_path)
    return _DEFAULT_RULE_MANAGER
