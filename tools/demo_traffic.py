"""
API Gatekeeper — Benign Demo Traffic Generator (Module M7).
Sends realistic, legitimate e-commerce traffic (searches, product views,
logins, customer reviews) to showcase live allowed traffic alongside attack streams.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import httpx


BENIGN_ACTIONS = [
    {
        "name": "Product Search",
        "method": "GET",
        "path": "/api/products",
        "params": lambda: {"search": random.choice(["shoes", "running shoes", "jacket", "headphones", "wireless charger", "organic cotton t-shirt", "laptop bag"])},
        "headers": lambda: {},
        "json": None,
    },
    {
        "name": "View Product Detail",
        "method": "GET",
        "path": lambda: f"/api/products/{random.randint(1, 4)}",
        "params": lambda: {},
        "headers": lambda: {},
        "json": None,
    },
    {
        "name": "Category Filter",
        "method": "GET",
        "path": "/api/products",
        "params": lambda: {"category": random.choice(["apparel", "electronics", "home", "books"])},
        "headers": lambda: {},
        "json": None,
    },
    {
        "name": "Customer Feedback",
        "method": "POST",
        "path": "/api/feedback",
        "params": lambda: {},
        "headers": lambda: {"Content-Type": "application/json"},
        "json": lambda: {
            "product_id": random.randint(1, 4),
            "rating": random.choice([4, 5]),
            "comment": random.choice([
                "Really love this product, fast delivery!",
                "Great quality for the price.",
                "Packaging was clean and secure.",
                "Would definitely recommend to friends.",
                "Customer service was very helpful."
            ]),
        },
    },
    {
        "name": "User Login",
        "method": "POST",
        "path": "/api/login",
        "params": lambda: {},
        "headers": lambda: {"Content-Type": "application/json"},
        "json": lambda: {
            "username": random.choice(["alice", "bob", "carol"]),
            "password": "Password123!",
        },
    },
    {
        "name": "Health Check",
        "method": "GET",
        "path": "/api/health",
        "params": lambda: {},
        "headers": lambda: {},
        "json": None,
    },
]

CLIENT_IPS = [
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "203.0.113.13",
    "203.0.113.14",
    "203.0.113.15",
    "203.0.113.16",
    "203.0.113.17",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="API Gatekeeper Benign Demo Traffic Generator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Gateway URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--rate", type=float, default=2.0, help="Requests per second (default: 2.0)")
    parser.add_argument("--count", type=int, default=30, help="Number of requests to send (0 = infinite loop)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    interval = 1.0 / max(0.1, args.rate)

    print("\n" + "=" * 65)
    print("         API GATEKEEPER -- BENIGN DEMO TRAFFIC GENERATOR         ")
    print("=" * 65)
    print(f"Target Gateway: {base_url}")
    print(f"Target Rate:    {args.rate} req/sec (interval: {interval:.2f}s)")
    print(f"Total Requests: {'Infinite (Ctrl+C to stop)' if args.count == 0 else args.count}\n")

    sent = 0
    passed = 0

    with httpx.Client() as client:
        try:
            while args.count == 0 or sent < args.count:
                action = random.choice(BENIGN_ACTIONS)
                path = action["path"]() if callable(action["path"]) else action["path"]
                params = action["params"]() if callable(action["params"]) else {}
                headers = action["headers"]() if callable(action["headers"]) else {}
                json_data = action["json"]() if callable(action["json"]) else None

                client_ip = random.choice(CLIENT_IPS)
                headers["X-Forwarded-For"] = client_ip

                t0 = time.perf_counter()
                try:
                    resp = client.request(
                        method=action["method"],
                        url=f"{base_url}{path}",
                        params=params,
                        headers=headers,
                        json=json_data,
                        timeout=5.0,
                    )
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = resp.status_code
                    if status_code == 200:
                        passed += 1
                except Exception as exc:
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = 0

                sent += 1
                print(f"[{sent:03d}] {action['method']} {path:<20} | IP: {client_ip} | HTTP {status_code} | {lat_ms:.2f} ms")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped by user.")

    print("\n" + "=" * 65)
    print(f"Completed: {passed} / {sent} requests passed successfully (HTTP 200)")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
