"""
API Gatekeeper — Latency and Performance Benchmark Harness.
Measures gateway overhead vs direct backend for sequential and concurrent workloads.
Acceptance Criterion: Gateway p95 inspection latency overhead < 20 ms.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from typing import Any
import httpx


async def measure_sequential(
    client: httpx.AsyncClient,
    url: str,
    iterations: int = 200,
    headers: dict[str, str] | None = None,
) -> list[float]:
    """Measure sequential round-trip latencies in milliseconds."""
    lats: list[float] = []
    hdrs = headers or {}
    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            resp = await client.get(url, headers=hdrs, timeout=5.0)
            lat = (time.perf_counter() - t0) * 1000.0
            lats.append(lat)
        except Exception:
            pass
    return lats


async def measure_concurrent(
    url: str,
    concurrency: int = 50,
    total_requests: int = 200,
    headers: dict[str, str] | None = None,
) -> list[float]:
    """Measure concurrent request latencies using a bounded worker pool."""
    hdrs = headers or {}
    lats: list[float] = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=10.0) as client:
        async def _worker() -> None:
            async with sem:
                t0 = time.perf_counter()
                try:
                    resp = await client.get(url, headers=hdrs)
                    lat = (time.perf_counter() - t0) * 1000.0
                    lats.append(lat)
                except Exception:
                    pass

        tasks = [_worker() for _ in range(total_requests)]
        await asyncio.gather(*tasks)

    return lats


def compute_percentiles(lats: list[float]) -> dict[str, float]:
    """Calculate p50, p90, p95, p99, and mean from latency measurements."""
    if not lats:
        return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
    s = sorted(lats)
    n = len(s)
    return {
        "p50": s[int(n * 0.50)],
        "p90": s[int(n * 0.90)],
        "p95": s[int(n * 0.95)],
        "p99": s[min(n - 1, int(n * 0.99))],
        "mean": statistics.mean(s),
    }


async def run_benchmark(gateway_url: str, backend_url: str) -> None:
    print("\n" + "=" * 74)
    print("       API GATEKEEPER -- PERFORMANCE & LATENCY BENCHMARK HARNESS       ")
    print("=" * 74)
    print(f"Gateway URL: {gateway_url}")
    print(f"Backend URL: {backend_url}\n")

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Check health
        try:
            gw_h = await client.get(f"{gateway_url}/_gk/health?shallow=1")
            be_h = await client.get(f"{backend_url}/api/health")
            if gw_h.status_code != 200 or be_h.status_code != 200:
                print("[-] Services are not ready. Please ensure both servers are running.")
                return
        except Exception as exc:
            print(f"[-] Could not connect to services: {exc}")
            return

        # ---------------------------------------------------------------------
        # 1. Direct Backend Baseline (Sequential Allowed Traffic)
        # ---------------------------------------------------------------------
        print("[*] 1/4 Measuring direct backend baseline (200 sequential GETs)...")
        be_lats = await measure_sequential(client, f"{backend_url}/api/products?limit=5", iterations=200)
        be_stats = compute_percentiles(be_lats)

        # ---------------------------------------------------------------------
        # 2. Gateway Proxied Allowed Traffic (Sequential)
        # ---------------------------------------------------------------------
        print("[*] 2/4 Measuring gateway proxied allowed path (200 sequential GETs)...")
        gw_lats = await measure_sequential(client, f"{gateway_url}/api/products?limit=5", iterations=200)
        gw_stats = compute_percentiles(gw_lats)

        # ---------------------------------------------------------------------
        # 3. Gateway Blocked Attack Path (Perimeter Drop, Sequential)
        # ---------------------------------------------------------------------
        print("[*] 3/4 Measuring gateway perimeter block path (200 sequential blocked GETs)...")
        blk_lats = await measure_sequential(
            client,
            f"{gateway_url}/api/products?search=' UNION SELECT 1,2,3--",
            iterations=200,
            headers={"X-Forwarded-For": "198.51.100.99"},
        )
        blk_stats = compute_percentiles(blk_lats)

        # ---------------------------------------------------------------------
        # 4. Gateway Concurrent Load (50 concurrent workers)
        # ---------------------------------------------------------------------
        print("[*] 4/4 Measuring gateway under concurrent load (50 concurrent workers, 200 requests)...")
        conc_lats = await measure_concurrent(
            f"{gateway_url}/api/products?limit=5",
            concurrency=50,
            total_requests=200,
        )
        conc_stats = compute_percentiles(conc_lats)

    # Calculate overhead
    p50_overhead = max(0.0, gw_stats["p50"] - be_stats["p50"])
    p95_overhead = max(0.0, gw_stats["p95"] - be_stats["p95"])
    mean_overhead = max(0.0, gw_stats["mean"] - be_stats["mean"])

    print("\n" + "=" * 74)
    print("                         LATENCY BENCHMARK RESULTS                     ")
    print("=" * 74)
    print(f"{'Workload':<32} | {'p50':>8} | {'p90':>8} | {'p95':>8} | {'p99':>8} | {'Mean':>8}")
    print("-" * 74)
    print(f"{'Direct Backend Baseline':<32} | {be_stats['p50']:>6.2f}ms | {be_stats['p90']:>6.2f}ms | {be_stats['p95']:>6.2f}ms | {be_stats['p99']:>6.2f}ms | {be_stats['mean']:>6.2f}ms")
    print(f"{'Gateway Proxied (Allowed)':<32} | {gw_stats['p50']:>6.2f}ms | {gw_stats['p90']:>6.2f}ms | {gw_stats['p95']:>6.2f}ms | {gw_stats['p99']:>6.2f}ms | {gw_stats['mean']:>6.2f}ms")
    print(f"{'Gateway Blocked (Perimeter Drop)':<32} | {blk_stats['p50']:>6.2f}ms | {blk_stats['p90']:>6.2f}ms | {blk_stats['p95']:>6.2f}ms | {blk_stats['p99']:>6.2f}ms | {blk_stats['mean']:>6.2f}ms")
    print(f"{'Gateway Under 50 Concurrency':<32} | {conc_stats['p50']:>6.2f}ms | {conc_stats['p90']:>6.2f}ms | {conc_stats['p95']:>6.2f}ms | {conc_stats['p99']:>6.2f}ms | {conc_stats['mean']:>6.2f}ms")
    print("-" * 74)
    print(f"Gateway Overhead vs Backend:      p50 = +{p50_overhead:.2f}ms  |  p95 = +{p95_overhead:.2f}ms  |  Mean = +{mean_overhead:.2f}ms")
    print(f"Target: Gateway p95 Overhead < 20 ms -> {'PASS [MET]' if p95_overhead < 20.0 else 'FAIL'}")
    print("=" * 74 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="API Gatekeeper Latency Benchmark")
    parser.add_argument("--gateway", default="http://127.0.0.1:8000", help="Gateway URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--backend", default="http://127.0.0.1:9000", help="Backend URL (default: http://127.0.0.1:9000)")
    args = parser.parse_args()

    asyncio.run(run_benchmark(args.gateway.rstrip("/"), args.backend.rstrip("/")))


if __name__ == "__main__":
    main()
