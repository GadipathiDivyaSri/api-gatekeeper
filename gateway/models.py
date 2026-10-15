"""
Gateway Core Models (Module M2).
Dataclasses for RequestContext, Finding, Decision, and Event.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single security finding produced by inspection layers."""

    layer: str  # "signatures" | "bot" | "contract" | "anomaly"
    rule_id: str
    name: str
    category: str
    score: int
    matched: str
    target: str
    cwe: str = ""
    owasp: str = ""
    attack: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return asdict(self)


@dataclass
class Decision:
    """Result of request inspection determining whether to block, flag, or allow."""

    action: str = "allowed"  # "allowed" | "blocked" | "flagged" | "rate_limited" | "banned" | "error_masked"
    score: int = 0
    findings: list[Finding] = field(default_factory=list)
    status_code: int = 200
    reason: str = ""


@dataclass
class RequestContext:
    """Normalized intake context of an incoming HTTP request."""

    incident_id: str
    client_ip: str
    method: str
    path: str
    query_string: str = ""
    query_params: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    body_bytes: bytes = b""
    body_text: str = ""
    json_body: Any | None = None
    form_body: dict[str, list[str]] | None = None
    content_type: str = ""


@dataclass
class Event:
    """Security audit event written to SQLite and emitted over WebSocket."""

    incident_id: str
    ts: float
    client_ip: str
    method: str
    path: str
    action: str  # "allowed" | "blocked" | "flagged" | "rate_limited" | "banned" | "error_masked"
    score: int
    primary_category: str
    severity: str
    findings: list[dict[str, Any]]
    status_code: int
    latency_ms: float
    upstream_ms: float
    reached_backend: bool
    query: str = ""
    user_agent: str = ""
    body_excerpt: str = ""
    decoded_excerpt: str = ""
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert event to serializable dictionary."""
        return asdict(self)
