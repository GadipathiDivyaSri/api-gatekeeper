"""
Unit and Integration Tests for Module M8: OpenAPI Contract Guard.
Tests positive security model, endpoint allow-listing, parameter types,
body schemas, sensitive field injection, and fail-open behavior.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import app as backend_app
from gateway.config import GatewayConfig
from gateway.contract import ContractManager
from gateway.main import create_app
from gateway.models import RequestContext
from gateway.pipeline import inspect


@pytest.fixture
def openapi_spec() -> dict:
    """Fixture providing DemoShop's OpenAPI schema."""
    return backend_app.openapi()


@pytest.fixture
def contract_mgr(openapi_spec: dict) -> ContractManager:
    """Fixture providing ContractManager initialized with DemoShop's spec."""
    config = GatewayConfig()
    return ContractManager(config=config, spec=openapi_spec)


def test_unknown_endpoint_blocked(contract_mgr: ContractManager) -> None:
    """Verify that requests to paths not in OpenAPI spec are blocked with CONTRACT-UNKNOWN-ENDPOINT."""
    ctx = RequestContext(
        incident_id="TEST-UNKNOWN",
        client_ip="198.51.100.1",
        method="GET",
        path="/admin",
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert decision.action == "blocked"
    assert decision.status_code == 403
    assert any(f.rule_id == "CONTRACT-UNKNOWN-ENDPOINT" for f in decision.findings)
    finding = next(f for f in decision.findings if f.rule_id == "CONTRACT-UNKNOWN-ENDPOINT")
    assert finding.score == 5
    assert finding.cwe == "CWE-1059"
    assert finding.owasp == "API9:2023"


def test_undefined_method_on_known_path_blocked(contract_mgr: ContractManager) -> None:
    """Verify that undefined HTTP methods on known endpoints are blocked."""
    ctx = RequestContext(
        incident_id="TEST-BAD-METHOD",
        client_ip="198.51.100.1",
        method="DELETE",
        path="/api/health",
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert decision.action == "blocked"
    assert any(f.rule_id == "CONTRACT-UNKNOWN-ENDPOINT" for f in decision.findings)


def test_options_and_head_allowed_to_known_paths(contract_mgr: ContractManager) -> None:
    """Verify that OPTIONS and HEAD to known endpoints are permitted."""
    for method in ("OPTIONS", "HEAD"):
        ctx = RequestContext(
            incident_id=f"TEST-{method}",
            client_ip="198.51.100.1",
            method=method,
            path="/api/products",
            user_agent="Mozilla/5.0",
        )
        decision = inspect(ctx, contract_manager=contract_mgr)
        assert decision.action == "allowed"
        contract_findings = [f for f in decision.findings if f.layer == "contract"]
        assert len(contract_findings) == 0


def test_path_template_matching_and_type_validation(contract_mgr: ContractManager) -> None:
    """Verify path template matching (/api/products/{product_id}) and integer type check."""
    # 1. Valid integer ID passes
    ctx_valid = RequestContext(
        incident_id="TEST-PATH-VALID",
        client_ip="198.51.100.1",
        method="GET",
        path="/api/products/42",
    )
    decision_valid = inspect(ctx_valid, contract_manager=contract_mgr)
    assert decision_valid.action == "allowed"

    # 2. String instead of integer ID fails
    ctx_invalid = RequestContext(
        incident_id="TEST-PATH-INVALID",
        client_ip="198.51.100.1",
        method="GET",
        path="/api/products/not-an-integer",
    )
    decision_invalid = inspect(ctx_invalid, contract_manager=contract_mgr)
    assert decision_invalid.action == "blocked"
    assert any(f.rule_id == "CONTRACT-SCHEMA" for f in decision_invalid.findings)


def test_query_param_type_violation_limit_abc(contract_mgr: ContractManager) -> None:
    """Verify that string value for integer query parameter (limit=abc) triggers CONTRACT-SCHEMA."""
    ctx = RequestContext(
        incident_id="TEST-LIMIT-ABC",
        client_ip="198.51.100.1",
        method="GET",
        path="/api/products",
        query_string="limit=abc",
        query_params={"limit": ["abc"]},
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert decision.action == "blocked"
    assert decision.status_code == 403
    assert any(f.rule_id == "CONTRACT-SCHEMA" for f in decision.findings)


def test_unknown_query_param(contract_mgr: ContractManager) -> None:
    """Verify that undeclared query parameters trigger CONTRACT-UNKNOWN-PARAM (score 2)."""
    ctx = RequestContext(
        incident_id="TEST-UNKNOWN-PARAM",
        client_ip="198.51.100.1",
        method="GET",
        path="/api/products",
        query_string="search=phone&evil_param=1",
        query_params={"search": ["phone"], "evil_param": ["1"]},
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert any(f.rule_id == "CONTRACT-UNKNOWN-PARAM" for f in decision.findings)
    finding = next(f for f in decision.findings if f.rule_id == "CONTRACT-UNKNOWN-PARAM")
    assert finding.score == 2


def test_sensitive_field_injection_blocked(contract_mgr: ContractManager) -> None:
    """Verify that extra field matching sensitive_fields (e.g. 'role') triggers CONTRACT-SENSITIVE-FIELD (score 5)."""
    body_dict = {
        "username": "attacker",
        "email": "attacker@example.com",
        "password": "Password123!",
        "role": "admin",
    }
    import json

    body_str = json.dumps(body_dict)
    ctx = RequestContext(
        incident_id="TEST-SENSITIVE-ROLE",
        client_ip="198.51.100.1",
        method="POST",
        path="/api/register",
        headers={"content-type": "application/json"},
        body_text=body_str,
        body_bytes=body_str.encode("utf-8"),
        json_body=body_dict,
        content_type="application/json",
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert decision.action == "blocked"
    assert decision.status_code == 403
    assert any(f.rule_id == "CONTRACT-SENSITIVE-FIELD" for f in decision.findings)
    finding = next(f for f in decision.findings if f.rule_id == "CONTRACT-SENSITIVE-FIELD")
    assert finding.score == 5
    assert finding.cwe == "CWE-915"


def test_extra_undeclared_body_field(contract_mgr: ContractManager) -> None:
    """Verify that non-sensitive extra body fields trigger CONTRACT-EXTRA-FIELD (score 3)."""
    body_dict = {
        "username": "legit_user",
        "email": "user@example.com",
        "password": "Password123!",
        "discount_code": "PROMO2026",
    }
    import json

    body_str = json.dumps(body_dict)
    ctx = RequestContext(
        incident_id="TEST-EXTRA-FIELD",
        client_ip="198.51.100.1",
        method="POST",
        path="/api/register",
        headers={"content-type": "application/json"},
        body_text=body_str,
        body_bytes=body_str.encode("utf-8"),
        json_body=body_dict,
        content_type="application/json",
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert any(f.rule_id == "CONTRACT-EXTRA-FIELD" for f in decision.findings)
    finding = next(f for f in decision.findings if f.rule_id == "CONTRACT-EXTRA-FIELD")
    assert finding.score == 3


def test_valid_request_passes_cleanly(contract_mgr: ContractManager) -> None:
    """Verify that completely spec-valid requests produce zero contract findings."""
    body_dict = {
        "username": "valid_user",
        "email": "user@example.com",
        "password": "Password123!",
    }
    import json

    body_str = json.dumps(body_dict)
    ctx = RequestContext(
        incident_id="TEST-VALID",
        client_ip="198.51.100.1",
        method="POST",
        path="/api/register",
        headers={"content-type": "application/json", "user-agent": "Mozilla/5.0"},
        user_agent="Mozilla/5.0",
        body_text=body_str,
        body_bytes=body_str.encode("utf-8"),
        json_body=body_dict,
        content_type="application/json",
    )
    decision = inspect(ctx, contract_manager=contract_mgr)

    assert decision.action == "allowed"
    contract_findings = [f for f in decision.findings if f.layer == "contract"]
    assert len(contract_findings) == 0


def test_fail_open_when_spec_unavailable() -> None:
    """Verify that Contract Guard fails open (contract_active=False, zero blocks) if spec is missing."""
    config = GatewayConfig(openapi_source="http://127.0.0.1:54321/nonexistent.json")
    mgr = ContractManager(config=config)

    assert not mgr.is_active

    ctx = RequestContext(
        incident_id="TEST-FAIL-OPEN",
        client_ip="198.51.100.1",
        method="GET",
        path="/any/random/path",
    )
    findings = mgr.validate(ctx)
    assert len(findings) == 0


def test_e2e_contract_guard_fastapi(openapi_spec: dict) -> None:
    """End-to-end integration test with FastAPI TestClient."""
    config = GatewayConfig(demo_mode=True)
    contract_mgr = ContractManager(config=config, spec=openapi_spec)
    app = create_app(config=config, contract_manager=contract_mgr)
    client = TestClient(app)

    # 1. GET /admin -> 403
    r1 = client.get("/admin")
    assert r1.status_code == 403
    assert r1.json()["error"] == "Request blocked"

    # 2. Register body with "role": "admin" -> 403
    r2 = client.post(
        "/api/register",
        json={"username": "alice", "email": "a@b.com", "password": "Password123!", "role": "admin"},
    )
    assert r2.status_code == 403

    # 3. limit=abc -> 403
    r3 = client.get("/api/products", params={"limit": "abc"})
    assert r3.status_code == 403

    # 4. GET /_gk/api/stats shows contract_active=True
    r4 = client.get("/_gk/api/stats")
    assert r4.status_code == 200
    assert r4.json()["contract_active"] is True

    # 5. POST /_gk/api/rules/reload refreshes rules and contract
    r5 = client.post("/_gk/api/rules/reload")
    assert r5.status_code == 200
    assert "contract_active" in r5.json()
