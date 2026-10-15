"""
API Gatekeeper — Module M10 Live Acceptance Walkthrough.
Demonstrates live mode toggling, rules policy toggling, and mode-comparison metrics
against running backend and gateway instances.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any
import httpx


def wait_for_service(url: str, name: str, timeout: float = 12.0) -> bool:
    """Poll a service URL until it returns 200 OK or times out."""
    start = time.perf_counter()
    with httpx.Client() as client:
        while time.perf_counter() - start < timeout:
            try:
                res = client.get(url, timeout=1.0)
                if res.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.3)
    return False


def get_latest_event(client: httpx.Client, gateway_url: str, token: str | None = None) -> dict[str, Any] | None:
    """Fetch the single most recent security event from SQLite."""
    time.sleep(0.2)  # Allow SQLite batch queue to commit
    headers = {"X-Admin-Token": token} if token else {}
    resp = client.get(f"{gateway_url}/_gk/api/events?limit=1", headers=headers, timeout=5.0)
    if resp.status_code == 200:
        data = resp.json()
        events = data if isinstance(data, list) else data.get("events", [])
        return events[0] if events else None
    return None


def run_walkthrough(gateway_url: str, backend_url: str, token: str | None = None) -> bool:
    headers = {"X-Admin-Token": token} if token else {}

    print("\n" + "=" * 78)
    print("        API GATEKEEPER -- MODULE M10 LIVE ACCEPTANCE WALKTHROUGH        ")
    print("=" * 78)
    print(f"Gateway URL: {gateway_url}")
    print(f"Backend URL: {backend_url}")
    print(f"Dashboard:   {gateway_url}/_gk/\n")

    with httpx.Client() as client:
        # Check health
        gw_health = client.get(f"{gateway_url}/_gk/health", timeout=3.0)
        assert gw_health.status_code == 200, f"Gateway health failed: {gw_health.text}"
        print(f"[+] Gateway is healthy: {gw_health.json()}")

        # ---------------------------------------------------------------------
        # Step 1: Default BLOCK Mode
        # ---------------------------------------------------------------------
        print("\n" + "-" * 78)
        print(">>> STEP 1: VERIFY DEFAULT 'BLOCK' MODE")
        print("-" * 78)

        # Set mode to block
        res = client.post(f"{gateway_url}/_gk/api/mode", json={"mode": "block"}, headers=headers, timeout=3.0)
        assert res.status_code == 200
        print(f"[*] Gateway Mode Set: {res.json()['mode'].upper()}")

        # Send SQLi attack probe
        probe_ip = "198.51.100.50"
        print(f"[*] Sending SQLi attack probe from {probe_ip}: GET /api/products?search=' UNION SELECT 1,2,3--")
        resp = client.get(
            f"{gateway_url}/api/products",
            params={"search": "' UNION SELECT 1,2,3--"},
            headers={"X-Forwarded-For": probe_ip},
            timeout=5.0,
        )
        print(f"[*] Response Status: HTTP {resp.status_code} ({'BLOCKED' if resp.status_code == 403 else 'ALLOWED'})")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

        evt = get_latest_event(client, gateway_url, token)
        assert evt is not None
        print(f"[*] Event Record: ID={evt['id']} | Action={evt['action'].upper()} | Category={evt['primary_category']} | Reached Backend={evt['reached_backend']}")
        assert evt["action"] == "blocked"
        assert evt["reached_backend"] is False
        print(">>> SUCCESS: Attack BLOCKED at perimeter with reached_backend=False")

        # ---------------------------------------------------------------------
        # Step 2: Toggle to MONITOR Mode
        # ---------------------------------------------------------------------
        print("\n" + "-" * 78)
        print(">>> STEP 2: TOGGLE TO 'MONITOR' MODE (Simulating Detection-Only)")
        print("-" * 78)

        res = client.post(f"{gateway_url}/_gk/api/mode", json={"mode": "monitor"}, headers=headers, timeout=3.0)
        assert res.status_code == 200
        print(f"[*] Gateway Mode Changed: {res.json()['mode'].upper()} (Broadcasting mode_changed)")

        # Send same attack probe
        probe_ip = "198.51.100.51"
        print(f"[*] Sending SQLi attack probe from {probe_ip}: GET /api/products?search=' UNION SELECT 1,2,3--")
        resp = client.get(
            f"{gateway_url}/api/products",
            params={"search": "' UNION SELECT 1,2,3--"},
            headers={"X-Forwarded-For": probe_ip},
            timeout=5.0,
        )
        print(f"[*] Response Status: HTTP {resp.status_code} ({'FLAGGED (Passed to backend)' if resp.status_code == 200 else 'UNEXPECTED'})")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        evt = get_latest_event(client, gateway_url, token)
        assert evt is not None
        print(f"[*] Event Record: ID={evt['id']} | Action={evt['action'].upper()} | Category={evt['primary_category']} | Reached Backend={evt['reached_backend']}")
        assert evt["action"] == "flagged"
        assert evt["reached_backend"] is True
        print(">>> SUCCESS: Attack FLAGGED in monitor mode with reached_backend=True")

        # ---------------------------------------------------------------------
        # Step 3: Toggle back to BLOCK Mode
        # ---------------------------------------------------------------------
        print("\n" + "-" * 78)
        print(">>> STEP 3: TOGGLE BACK TO 'BLOCK' MODE")
        print("-" * 78)

        res = client.post(f"{gateway_url}/_gk/api/mode", json={"mode": "block"}, headers=headers, timeout=3.0)
        assert res.status_code == 200
        print(f"[*] Gateway Mode Restored: {res.json()['mode'].upper()}")

        # Send same attack probe
        probe_ip = "198.51.100.52"
        print(f"[*] Sending SQLi attack probe from {probe_ip}: GET /api/products?search=' UNION SELECT 1,2,3--")
        resp = client.get(
            f"{gateway_url}/api/products",
            params={"search": "' UNION SELECT 1,2,3--"},
            headers={"X-Forwarded-For": probe_ip},
            timeout=5.0,
        )
        print(f"[*] Response Status: HTTP {resp.status_code} ({'BLOCKED' if resp.status_code == 403 else 'ALLOWED'})")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

        evt = get_latest_event(client, gateway_url, token)
        assert evt is not None
        print(f"[*] Event Record: ID={evt['id']} | Action={evt['action'].upper()} | Category={evt['primary_category']} | Reached Backend={evt['reached_backend']}")
        assert evt["action"] == "blocked"
        assert evt["reached_backend"] is False
        print(">>> SUCCESS: Attack re-BLOCKED with reached_backend=False")

        # ---------------------------------------------------------------------
        # Step 4: Rule Control — Disable Rule SQLI-001
        # ---------------------------------------------------------------------
        print("\n" + "-" * 78)
        print(">>> STEP 4: RULE TABLE CONTROL -- DISABLE RULE 'SQLI-001'")
        print("-" * 78)

        res = client.patch(f"{gateway_url}/_gk/api/rules/SQLI-001", json={"enabled": False}, headers=headers, timeout=3.0)
        assert res.status_code == 200
        print(f"[*] Rule SQLI-001 Disabled: enabled={res.json()['enabled']} (Broadcasting rule_toggled)")

        # Send SQLi probe matching SQLI-001
        probe_ip = "198.51.100.53"
        print(f"[*] Sending SQLi probe from {probe_ip} while SQLI-001 is DISABLED")
        resp = client.get(
            f"{gateway_url}/api/products",
            params={"search": "' UNION SELECT 1,2,3--"},
            headers={"X-Forwarded-For": probe_ip},
            timeout=5.0,
        )
        print(f"[*] Response Status: HTTP {resp.status_code} ({'ALLOWED' if resp.status_code == 200 else 'BLOCKED'})")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        evt = get_latest_event(client, gateway_url, token)
        assert evt is not None
        print(f"[*] Event Record: ID={evt['id']} | Action={evt['action'].upper()} | Category={evt['primary_category']} | Reached Backend={evt['reached_backend']}")
        assert evt["action"] == "allowed"
        assert evt["reached_backend"] is True
        print(">>> SUCCESS: Probe allowed through when rule is disabled (reached_backend=True)")

        # ---------------------------------------------------------------------
        # Step 5: Rule Control — Re-enable Rule SQLI-001
        # ---------------------------------------------------------------------
        print("\n" + "-" * 78)
        print(">>> STEP 5: RULE TABLE CONTROL -- RE-ENABLE RULE 'SQLI-001'")
        print("-" * 78)

        res = client.patch(f"{gateway_url}/_gk/api/rules/SQLI-001", json={"enabled": True}, headers=headers, timeout=3.0)
        assert res.status_code == 200
        print(f"[*] Rule SQLI-001 Re-enabled: enabled={res.json()['enabled']}")

        # Send SQLi probe again
        probe_ip = "198.51.100.54"
        print(f"[*] Sending SQLi probe from {probe_ip} after re-enabling SQLI-001")
        resp = client.get(
            f"{gateway_url}/api/products",
            params={"search": "' UNION SELECT 1,2,3--"},
            headers={"X-Forwarded-For": probe_ip},
            timeout=5.0,
        )
        print(f"[*] Response Status: HTTP {resp.status_code} ({'BLOCKED' if resp.status_code == 403 else 'ALLOWED'})")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

        evt = get_latest_event(client, gateway_url, token)
        assert evt is not None
        print(f"[*] Event Record: ID={evt['id']} | Action={evt['action'].upper()} | Category={evt['primary_category']} | Reached Backend={evt['reached_backend']}")
        assert evt["action"] == "blocked"
        assert evt["reached_backend"] is False
        print(">>> SUCCESS: Active blocking restored immediately for SQLI-001")

        # ---------------------------------------------------------------------
        # Step 6: Mode Comparison & Rolling 60s Metrics Banner
        # ---------------------------------------------------------------------
        print("\n" + "-" * 78)
        print(">>> STEP 6: QUERY ROLLING 60s MODE COMPARISON METRICS")
        print("-" * 78)

        time.sleep(0.3)
        res = client.get(f"{gateway_url}/_gk/api/mode-comparison?window=60", headers=headers, timeout=3.0)
        assert res.status_code == 200
        data = res.json()
        comp = data.get("comparison", data) if isinstance(data, dict) else {}

        total_60s = comp.get("total_60s", 0)
        blocked_60s = comp.get("blocked_60s", 0)
        reached_60s = comp.get("reached_backend_60s", 0)
        blocked_pct = (blocked_60s / total_60s * 100.0) if total_60s > 0 else 0.0
        reached_pct = (reached_60s / total_60s * 100.0) if total_60s > 0 else 0.0

        print(f"Current Gateway Mode:       {comp.get('current_mode', '').upper()}")
        print(f"Rolling Window:             {comp.get('window_sec', 60)} seconds")
        print(f"Total Requests (60s):       {total_60s}")
        print(f"Blocked at Perimeter (60s): {blocked_60s} ({blocked_pct:.1f}%)")
        print(f"Flagged (Monitor Mode):     {comp.get('flagged_60s', 0)}")
        print(f"Allowed Clean Requests:     {comp.get('allowed_60s', 0)}")
        print(f"Reached Upstream Backend:   {reached_60s} ({reached_pct:.1f}% backend load)")

        print("\n" + "=" * 78)
        print("   ALL MODULE M10 ACCEPTANCE REQUIREMENTS SUCCESSFULLY VERIFIED!   ")
        print("=" * 78 + "\n")
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="API Gatekeeper M10 Walkthrough")
    parser.add_argument("--gateway", default="http://127.0.0.1:8000", help="Gateway URL")
    parser.add_argument("--backend", default="http://127.0.0.1:9000", help="Backend URL")
    parser.add_argument("--token", default=None, help="Admin token (if ADMIN_TOKEN configured)")
    parser.add_argument("--keep-running", action="store_true", help="Keep backend and gateway servers running after walkthrough")
    args = parser.parse_args()

    # Check if servers are running
    backend_up = wait_for_service(f"{args.backend}/api/health", "Backend", timeout=1.0)
    gateway_up = wait_for_service(f"{args.gateway}/_gk/health", "Gateway", timeout=1.0)

    started_procs: list[subprocess.Popen[Any]] = []

    try:
        if not backend_up:
            print("[*] Starting DemoShop Backend on 127.0.0.1:9000...")
            python_bin = sys.executable
            # Seed DB first
            subprocess.run([python_bin, "-m", "backend.seed"], check=True)
            p_back = subprocess.Popen(
                [python_bin, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "9000"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            started_procs.append(p_back)
            if not wait_for_service(f"{args.backend}/api/health", "Backend", timeout=10.0):
                print("[-] Error: DemoShop backend failed to start.")
                sys.exit(1)
            print("[+] DemoShop Backend is UP on http://127.0.0.1:9000")

        if not gateway_up:
            print("[*] Starting API Gatekeeper on 127.0.0.1:8000...")
            python_bin = sys.executable
            p_gw = subprocess.Popen(
                [python_bin, "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            started_procs.append(p_gw)
            if not wait_for_service(f"{args.gateway}/_gk/health", "Gateway", timeout=10.0):
                print("[-] Error: API Gatekeeper failed to start.")
                sys.exit(1)
            print("[+] API Gatekeeper is UP on http://127.0.0.1:8000")

        # Run walkthrough
        success = run_walkthrough(args.gateway, args.backend, args.token)
        if not success:
            sys.exit(1)

    finally:
        if started_procs and not args.keep_running:
            print("[*] Stopping temporary test services...")
            for p in started_procs:
                p.terminate()
                p.wait()
            print("[+] Clean shutdown complete.")


if __name__ == "__main__":
    main()
