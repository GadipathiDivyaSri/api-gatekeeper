"""
Unit and Integration Tests for Module M7: Security Scorecard, Benchmark, and Corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from gateway.benchmark import _load_yaml, case_to_context, run_benchmark
from gateway.config import GatewayConfig
from gateway.main import create_app
from gateway.models import RequestContext
from gateway.pipeline import inspect
from gateway.rules import RuleManager, get_rule_manager


def test_corpus_file_sizing() -> None:
    """Verify minimum dataset sizing: >= 60 dev, >= 40 holdout, >= 80 benign."""
    corpus_dir = Path("tests/corpus")
    dev_cases = _load_yaml(corpus_dir / "attacks_dev.yaml")
    holdout_cases = _load_yaml(corpus_dir / "attacks_holdout.yaml")
    benign_cases = _load_yaml(corpus_dir / "benign.yaml")

    assert len(dev_cases) >= 60, f"Expected >= 60 dev attacks, got {len(dev_cases)}"
    assert len(holdout_cases) >= 40, f"Expected >= 40 holdout attacks, got {len(holdout_cases)}"
    assert len(benign_cases) >= 80, f"Expected >= 80 benign cases, got {len(benign_cases)}"


def test_case_to_context_mapping() -> None:
    """Verify parsing of query, headers, and json body into RequestContext."""
    case = {
        "id": "test-001",
        "method": "POST",
        "path": "/api/feedback",
        "query": "ref=partner&lang=en",
        "headers": {"X-Custom": "test-header", "User-Agent": "CustomUA/1.0"},
        "body": '{"product_id": 1, "comment": "test comment"}',
        "client_ip": "198.51.100.99",
    }
    ctx = case_to_context(case)

    assert isinstance(ctx, RequestContext)
    assert ctx.method == "POST"
    assert ctx.path == "/api/feedback"
    assert ctx.client_ip == "198.51.100.99"
    assert ctx.query_string == "ref=partner&lang=en"
    assert ctx.query_params.get("ref") == ["partner"]
    assert ctx.user_agent == "CustomUA/1.0"
    assert ctx.json_body == {"product_id": 1, "comment": "test comment"}


def test_benchmark_acceptance_thresholds() -> None:
    """
    Execute benchmark and verify acceptance criteria:
    hold-out detection >= 95% and false positives <= 2%.
    """
    results = run_benchmark(save=True)

    holdout = results["holdout"]
    dev = results["dev"]
    latency = results["latency_ms"]

    # Holdout acceptance
    assert holdout["total_attacks"] >= 40
    assert holdout["detection"] >= 0.95, f"Holdout detection rate {holdout['detection']} below 0.95 target"
    assert holdout["fp_rate"] <= 0.02, f"Holdout false positive rate {holdout['fp_rate']} exceeds 0.02 max"

    # Dev acceptance
    assert dev["total_attacks"] >= 60
    assert dev["detection"] >= 0.95, f"Dev detection rate {dev['detection']} below 0.95 target"
    assert dev["fp_rate"] <= 0.02, f"Dev false positive rate {dev['fp_rate']} exceeds 0.02 max"

    # Latency numbers sanity
    assert latency["p50"] > 0
    assert latency["p95"] > 0
    assert latency["p95"] >= latency["p50"]

    # Verify latest file was written
    latest_path = Path("data/benchmark_latest.json")
    assert latest_path.is_file()
    saved = json.loads(latest_path.read_text(encoding="utf-8"))
    assert "holdout" in saved
    assert saved["holdout"]["detection"] == holdout["detection"]


def test_benchmark_admin_endpoints() -> None:
    """Verify POST /_gk/api/benchmark and GET /_gk/api/benchmark/latest."""
    config = GatewayConfig(demo_mode=True)
    app = create_app(config=config)
    client = TestClient(app)

    # 1. Trigger benchmark run
    resp_post = client.post("/_gk/api/benchmark")
    assert resp_post.status_code == 200
    data_post = resp_post.json()
    assert "dev" in data_post
    assert "holdout" in data_post
    assert data_post["holdout"]["detection"] >= 0.95

    # 2. Fetch latest benchmark
    resp_get = client.get("/_gk/api/benchmark/latest")
    assert resp_get.status_code == 200
    data_get = resp_get.json()
    assert data_get["holdout"]["detection"] == data_post["holdout"]["detection"]


def test_simulate_admin_endpoint() -> None:
    """Verify POST /_gk/api/simulate runs when demo_mode=True."""
    config = GatewayConfig(demo_mode=True)
    app = create_app(config=config)
    client = TestClient(app)

    resp = client.post("/_gk/api/simulate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "running"
