"""
Gateway Configuration Module (Module M2).
Loads settings from config/gateway.yaml with environment variable overrides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RateLimitConfig:
    capacity: int = 20
    refill_per_sec: float = 5.0


@dataclass
class LoginRateLimitConfig:
    path_regex: str = r"^/api/login$"
    capacity: int = 5
    refill_per_sec: float = 0.0833


@dataclass
class StrikesConfig:
    window_sec: int = 60
    ban_threshold: int = 3
    ban_sec: int = 120
    rate_limited_per_strike: int = 20


@dataclass
class ContractConfig:
    enabled: bool = True
    strict_extra_fields: bool = True
    unknown_query_param_score: int = 2
    sensitive_fields: list[str] = field(
        default_factory=lambda: [
            "role",
            "is_admin",
            "isAdmin",
            "admin",
            "balance",
            "price",
            "permissions",
            "verified",
        ]
    )


@dataclass
class GatewayConfig:
    upstream_url: str = "http://127.0.0.1:9000"
    mode: str = "block"  # "block" or "monitor"
    block_threshold: int = 5
    max_body_bytes: int = 1048576  # 1 MB
    client_ip_source: str = "socket"  # "socket", "xff_first", "xff_last"
    admin_token: str = ""
    demo_mode: bool = True
    data_dir: Path = Path("data")
    openapi_source: str = "upstream"
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    login_rate_limit: LoginRateLimitConfig = field(default_factory=LoginRateLimitConfig)
    strikes: StrikesConfig = field(default_factory=StrikesConfig)
    contract: ContractConfig = field(default_factory=ContractConfig)


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Safely parse YAML config file if it exists."""
    if not path.is_file():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_config(config_path: Path | str | None = None) -> GatewayConfig:
    """Load configuration from YAML file and apply environment variable overrides."""
    target_path = Path(config_path) if config_path else Path("config/gateway.yaml")
    data = _load_yaml_file(target_path)

    # Sub-configurations
    rl_data = data.get("rate_limit", {})
    rate_limit = RateLimitConfig(
        capacity=int(rl_data.get("capacity", 20)),
        refill_per_sec=float(rl_data.get("refill_per_sec", 5.0)),
    )

    lrl_data = data.get("login_rate_limit", {})
    login_rate_limit = LoginRateLimitConfig(
        path_regex=str(lrl_data.get("path_regex", r"^/api/login$")),
        capacity=int(lrl_data.get("capacity", 5)),
        refill_per_sec=float(lrl_data.get("refill_per_sec", 0.0833)),
    )

    str_data = data.get("strikes", {})
    strikes = StrikesConfig(
        window_sec=int(str_data.get("window_sec", 60)),
        ban_threshold=int(str_data.get("ban_threshold", 3)),
        ban_sec=int(str_data.get("ban_sec", 120)),
        rate_limited_per_strike=int(str_data.get("rate_limited_per_strike", 20)),
    )

    ct_data = data.get("contract", {})
    contract = ContractConfig(
        enabled=bool(ct_data.get("enabled", True)),
        strict_extra_fields=bool(ct_data.get("strict_extra_fields", True)),
        unknown_query_param_score=int(ct_data.get("unknown_query_param_score", 2)),
        sensitive_fields=list(
            ct_data.get(
                "sensitive_fields",
                [
                    "role",
                    "is_admin",
                    "isAdmin",
                    "admin",
                    "balance",
                    "price",
                    "permissions",
                    "verified",
                ],
            )
        ),
    )

    # Core configuration with YAML base
    config = GatewayConfig(
        upstream_url=str(data.get("upstream_url", "http://127.0.0.1:9000")),
        mode=str(data.get("mode", "block")).lower(),
        block_threshold=int(data.get("block_threshold", 5)),
        max_body_bytes=int(data.get("max_body_bytes", 1048576)),
        client_ip_source=str(data.get("client_ip_source", "socket")).lower(),
        admin_token=str(data.get("admin_token", "")),
        demo_mode=bool(data.get("demo_mode", True)),
        data_dir=Path(os.getenv("DATA_DIR", data.get("data_dir", "data"))),
        openapi_source=str(data.get("openapi_source", "upstream")),
        rate_limit=rate_limit,
        login_rate_limit=login_rate_limit,
        strikes=strikes,
        contract=contract,
    )

    # Apply environment variable overrides per MASTER_CONTEXT
    if env_upstream := os.getenv("UPSTREAM_URL"):
        config.upstream_url = env_upstream
    if env_mode := os.getenv("GATEWAY_MODE") or os.getenv("MODE"):
        config.mode = env_mode.lower()
    if env_threshold := os.getenv("BLOCK_THRESHOLD"):
        config.block_threshold = int(env_threshold)
    if env_max_body := os.getenv("MAX_BODY_BYTES"):
        config.max_body_bytes = int(env_max_body)
    if env_ip_source := os.getenv("CLIENT_IP_SOURCE"):
        config.client_ip_source = env_ip_source.lower()
    if env_admin_token := os.getenv("ADMIN_TOKEN"):
        config.admin_token = env_admin_token
    if env_demo_mode := os.getenv("DEMO_MODE"):
        config.demo_mode = env_demo_mode.lower() in ("true", "1", "yes")
    if env_openapi_source := os.getenv("OPENAPI_SOURCE"):
        config.openapi_source = env_openapi_source

    return config


_CONFIG_INSTANCE: GatewayConfig | None = None


def get_config() -> GatewayConfig:
    """Return globally cached GatewayConfig or load a new instance."""
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = load_config()
    return _CONFIG_INSTANCE


def reset_config_cache() -> None:
    """Reset configuration cache (useful in tests)."""
    global _CONFIG_INSTANCE
    _CONFIG_INSTANCE = None
