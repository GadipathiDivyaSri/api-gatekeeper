"""
Security Scorecard & Benchmark Engine (Module M7).
Evaluates attack detection rate, false positive rate, per-category recall,
and inspection latency against labelled test corpora in pure dry-run mode.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any
import urllib.parse
import yaml

from gateway.config import GatewayConfig, get_config
from gateway.models import RequestContext
from gateway.pipeline import inspect
from gateway.rules import RuleManager, get_rule_manager


def _load_yaml(path: Path) -> list[dict[str, Any]]:
    """Safely load YAML test cases list from disk."""
    if not path.is_file():
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data if isinstance(data, list) else []


def case_to_context(case: dict[str, Any]) -> RequestContext:
    """Build a RequestContext from a declarative corpus test case."""
    method = str(case.get("method", "GET")).upper()
    path = str(case.get("path", "/api/products"))
    if not path.startswith("/"):
        path = f"/{path}"

    # Handle query
    raw_query = case.get("query")
    query_string = ""
    query_params: dict[str, list[str]] = {}
    if isinstance(raw_query, dict):
        query_string = urllib.parse.urlencode(raw_query)
        query_params = {k: [str(v)] if not isinstance(v, list) else [str(x) for x in v] for k, v in raw_query.items()}
    elif isinstance(raw_query, str):
        query_string = raw_query
        query_params = urllib.parse.parse_qs(raw_query, keep_blank_values=True)

    # Handle headers
    raw_headers = case.get("headers") or {}
    headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
    user_agent = headers.get("user-agent", "")

    # Handle body
    raw_body = case.get("body")
    body_text = ""
    body_bytes = b""
    json_body = None
    if isinstance(raw_body, dict):
        body_text = json.dumps(raw_body)
        body_bytes = body_text.encode("utf-8")
        json_body = raw_body
        headers.setdefault("content-type", "application/json")
    elif isinstance(raw_body, str):
        body_text = raw_body
        body_bytes = raw_body.encode("utf-8")
        if headers.get("content-type", "").startswith("application/json") or body_text.strip().startswith(("{", "[")):
            try:
                json_body = json.loads(body_text)
            except Exception:
                pass

    content_type = headers.get("content-type", "")

    return RequestContext(
        incident_id=f"BENCH-{case.get('id', 'unknown')}",
        client_ip=case.get("client_ip", "198.51.100.1"),
        method=method,
        path=path,
        query_string=query_string,
        query_params=query_params,
        headers=headers,
        user_agent=user_agent,
        body_bytes=body_bytes,
        body_text=body_text,
        json_body=json_body,
        content_type=content_type,
    )


def evaluate_set(
    attack_cases: list[dict[str, Any]],
    benign_cases: list[dict[str, Any]],
    config: GatewayConfig,
    rules_manager: RuleManager,
    all_latencies_ms: list[float],
) -> dict[str, Any]:
    """Evaluate attacks and benign cases, recording detection and false positive rates."""
    attacks_blocked = 0
    missed: list[str] = []
    category_stats: dict[str, dict[str, Any]] = {}

    for case in attack_cases:
        cid = case.get("id", "unknown")
        cat = case.get("category", "general")
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "detected": 0, "recall": 0.0}
        category_stats[cat]["total"] += 1

        ctx = case_to_context(case)

        t0 = time.perf_counter()
        decision = inspect(ctx, config=config, rules_manager=rules_manager, dry_run=True)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        all_latencies_ms.append(lat_ms)

        if decision.action == "blocked":
            attacks_blocked += 1
            category_stats[cat]["detected"] += 1
        else:
            missed.append(cid)

    # Compute recall per category
    for cat_data in category_stats.values():
        total = cat_data["total"]
        detected = cat_data["detected"]
        cat_data["recall"] = round(detected / total, 4) if total > 0 else 0.0

    # Evaluate false positives on benign set
    benign_blocked = 0
    false_positives: list[str] = []
    for case in benign_cases:
        cid = case.get("id", "unknown")
        ctx = case_to_context(case)

        t0 = time.perf_counter()
        decision = inspect(ctx, config=config, rules_manager=rules_manager, dry_run=True)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        all_latencies_ms.append(lat_ms)

        if decision.action == "blocked":
            benign_blocked += 1
            false_positives.append(cid)

    total_attacks = len(attack_cases)
    total_benign = len(benign_cases)

    detection_rate = round(attacks_blocked / total_attacks, 4) if total_attacks > 0 else 0.0
    fp_rate = round(benign_blocked / total_benign, 4) if total_benign > 0 else 0.0

    return {
        "detection": detection_rate,
        "fp_rate": fp_rate,
        "total_attacks": total_attacks,
        "attacks_blocked": attacks_blocked,
        "total_benign": total_benign,
        "benign_blocked": benign_blocked,
        "per_category": category_stats,
        "missed": missed,
        "false_positives": false_positives,
    }


def run_benchmark(
    config: GatewayConfig | None = None,
    rules_manager: RuleManager | None = None,
    save: bool = True,
    corpus_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Execute complete Security Scorecard benchmark against dev and hold-out corpora."""
    active_config = config or get_config()
    # Force block mode in benchmark to evaluate blocking decisions
    bench_config = GatewayConfig(
        upstream_url=active_config.upstream_url,
        mode="block",
        block_threshold=active_config.block_threshold,
        max_body_bytes=active_config.max_body_bytes,
        client_ip_source=active_config.client_ip_source,
    )
    active_rules = rules_manager or get_rule_manager()

    base_dir = Path(corpus_dir) if corpus_dir else Path("tests/corpus")
    dev_path = base_dir / "attacks_dev.yaml"
    holdout_path = base_dir / "attacks_holdout.yaml"
    benign_path = base_dir / "benign.yaml"

    dev_cases = _load_yaml(dev_path)
    holdout_cases = _load_yaml(holdout_path)
    benign_cases = _load_yaml(benign_path)

    all_latencies: list[float] = []

    dev_results = evaluate_set(dev_cases, benign_cases, bench_config, active_rules, all_latencies)
    holdout_results = evaluate_set(holdout_cases, benign_cases, bench_config, active_rules, all_latencies)

    # Compute latency statistics
    if all_latencies:
        sorted_lats = sorted(all_latencies)
        n = len(sorted_lats)
        p50 = sorted_lats[int(n * 0.50)]
        p95 = sorted_lats[int(n * 0.95)]
        p99 = sorted_lats[min(n - 1, int(n * 0.99))]
        mean = sum(sorted_lats) / n
    else:
        p50 = p95 = p99 = mean = 0.0

    benchmark_data = {
        "dev": dev_results,
        "holdout": holdout_results,
        "latency_ms": {
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "mean": round(mean, 3),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if save:
        data_dir = Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)
        latest_path = data_dir / "benchmark_latest.json"
        with open(latest_path, "w", encoding="utf-8") as f:
            json.dump(benchmark_data, f, indent=2)

    return benchmark_data


def print_scorecard(results: dict[str, Any]) -> None:
    """Print an ASCII formatted security scorecard summary."""
    dev = results.get("dev", {})
    holdout = results.get("holdout", {})
    lat = results.get("latency_ms", {})

    print("\n" + "=" * 70)
    print("           API GATEKEEPER -- SECURITY SCORECARD REPORT           ")
    print("=" * 70)
    print(f"Generated at: {results.get('generated_at')}\n")

    print("+---------------------------+--------------+--------------+-----------+")
    print("| Metric                    | Dev Corpus   | Holdout Set  | Target    |")
    print("+---------------------------+--------------+--------------+-----------+")
    print(f"| Total Attacks Tested      | {dev.get('total_attacks', 0):<12} | {holdout.get('total_attacks', 0):<12} | >= 40     |")
    print(f"| Attacks Blocked           | {dev.get('attacks_blocked', 0):<12} | {holdout.get('attacks_blocked', 0):<12} |           |")
    print(f"| Detection Rate            | {dev.get('detection', 0)*100:.1f}%{'':<7} | {holdout.get('detection', 0)*100:.1f}%{'':<7} | >= 95.0%  |")
    print(f"| Total Benign Tested       | {dev.get('total_benign', 0):<12} | {holdout.get('total_benign', 0):<12} | >= 80     |")
    print(f"| False Positives (Blocked) | {dev.get('benign_blocked', 0):<12} | {holdout.get('benign_blocked', 0):<12} | 0         |")
    print(f"| False Positive Rate       | {dev.get('fp_rate', 0)*100:.1f}%{'':<7} | {holdout.get('fp_rate', 0)*100:.1f}%{'':<7} | <= 2.0%   |")
    print("+---------------------------+--------------+--------------+-----------+")

    print("\nPer-Category Recall (Holdout):")
    print("+-----------------------+------------+--------------+----------+")
    print("| Category              | Attacks    | Blocked      | Recall   |")
    print("+-----------------------+------------+--------------+----------+")
    for cat, stats in holdout.get("per_category", {}).items():
        print(f"| {cat:<21} | {stats.get('total', 0):<10} | {stats.get('detected', 0):<12} | {stats.get('recall', 0)*100:.1f}%{'':<4} |")
    print("+-----------------------+------------+--------------+----------+")

    print("\nInspection Latency Overhead:")
    print(f"  * p50:  {lat.get('p50', 0):.3f} ms")
    print(f"  * p95:  {lat.get('p95', 0):.3f} ms")
    print(f"  * p99:  {lat.get('p99', 0):.3f} ms")
    print(f"  * Mean: {lat.get('mean', 0):.3f} ms")

    if holdout.get("missed"):
        print(f"\n[!] Missed holdout attacks: {holdout.get('missed')}")
    if holdout.get("false_positives"):
        print(f"\n[!] False positives: {holdout.get('false_positives')}")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    import sys

    res = run_benchmark(save=True)
    print_scorecard(res)

    h_det = res.get("holdout", {}).get("detection", 0.0)
    h_fp = res.get("holdout", {}).get("fp_rate", 1.0)

    if h_det < 0.95:
        print(f"ERROR: Holdout detection {h_det*100:.1f}% < 95.0% target!")
        sys.exit(1)
    if h_fp > 0.02:
        print(f"ERROR: False positive rate {h_fp*100:.1f}% > 2.0% maximum!")
        sys.exit(1)

    print("[SUCCESS] BENCHMARK ACCEPTANCE TARGETS ACHIEVED!")
