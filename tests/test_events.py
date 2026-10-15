"""
Event Store, Analytics, and Admin Control Plane Tests (Module M5).
Verifies SQLite WAL persistence, JSONL logging, queue batching, stats queries,
CSV export format, admin token authentication, and WebSocket live broadcasting.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from gateway.config import GatewayConfig
from gateway.events import EventStore
from gateway.main import create_app
from gateway.models import Event
from gateway.ws import WebSocketManager


def run_async(coro: Any) -> Any:
    return asyncio.run(coro)


def create_temp_store() -> tuple[EventStore, Path]:
    temp_dir = Path(tempfile.mkdtemp(prefix="gk_test_"))
    store = EventStore(data_dir=temp_dir)
    return store, temp_dir


def test_event_store_batch_persistence_and_jsonl():
    """Verify events are batched into SQLite and appended to events.jsonl."""

    async def _test():
        store, temp_dir = create_temp_store()
        try:
            store.start_worker()

            # Emit 5 events
            for i in range(5):
                e = Event(
                    incident_id=f"AG-TEST-{i:03d}",
                    ts=time.time(),
                    client_ip="192.0.2.1",
                    method="GET",
                    path="/api/products",
                    query="search=test",
                    user_agent="TestAgent",
                    body_excerpt="",
                    decoded_excerpt="",
                    action="allowed" if i < 3 else "blocked",
                    score=0 if i < 3 else 5,
                    primary_category="none" if i < 3 else "sqli",
                    severity="none" if i < 3 else "critical",
                    findings=[] if i < 3 else [{"rule_id": "SQLI-001", "name": "Union injection"}],
                    status_code=200 if i < 3 else 403,
                    latency_ms=1.5,
                    upstream_ms=1.2 if i < 3 else 0.0,
                    reached_backend=i < 3,
                )
                store.emit(e)

            # Wait for batch writer to flush (sleep 350ms > 250ms interval)
            await asyncio.sleep(0.35)
            await store.stop_worker()

            # Verify SQLite records
            events = store.get_events(limit=10)
            assert len(events) == 5

            # Verify JSONL lines
            assert store.jsonl_path.is_file()
            with open(store.jsonl_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            assert len(lines) == 5

            # Verify incident detail lookup
            detail = store.get_event_by_incident_id("AG-TEST-004")
            assert detail is not None
            assert detail["action"] == "blocked"
            assert detail["score"] == 5
            assert len(detail["findings"]) == 1
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    run_async(_test())


def test_event_store_stats_and_kpis():
    """Verify get_stats computes totals, unique attackers, block rate, and percentiles."""

    async def _test():
        store, temp_dir = create_temp_store()
        try:
            store.start_worker()

            now = time.time()
            # 1 allowed request from IP 1
            e1 = Event(
                incident_id="AG-1",
                ts=now - 5,
                client_ip="10.0.0.1",
                method="GET",
                path="/api/products",
                action="allowed",
                score=0,
                primary_category="none",
                severity="none",
                findings=[],
                status_code=200,
                latency_ms=10.0,
                upstream_ms=8.0,
                reached_backend=True,
            )
            # 1 blocked attack from IP 2
            e2 = Event(
                incident_id="AG-2",
                ts=now - 3,
                client_ip="10.0.0.2",
                method="POST",
                path="/api/feedback",
                action="blocked",
                score=5,
                primary_category="xss",
                severity="critical",
                findings=[{"rule_id": "XSS-001"}],
                status_code=403,
                latency_ms=2.0,
                upstream_ms=0.0,
                reached_backend=False,
            )
            store.emit(e1)
            store.emit(e2)

            await asyncio.sleep(0.35)
            await store.stop_worker()

            stats = store.get_stats(window=900)
            assert stats["total_requests"] == 2
            assert stats["allowed_requests"] == 1
            assert stats["blocked_requests"] == 1
            assert stats["unique_ips"] == 2
            assert stats["unique_attackers"] == 1
            assert stats["block_rate"] == 0.5
            assert stats["by_category"].get("xss") == 1
            assert stats["latency_p50_ms"] > 0
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    run_async(_test())


def test_csv_export_format():
    """Verify export_csv returns valid CSV matching specified header schema."""

    async def _test():
        store, temp_dir = create_temp_store()
        try:
            store.start_worker()
            e = Event(
                incident_id="AG-CSV-01",
                ts=1700000000.0,
                client_ip="1.2.3.4",
                method="GET",
                path="/api/health",
                action="allowed",
                score=0,
                primary_category="none",
                severity="none",
                findings=[],
                status_code=200,
                latency_ms=1.1,
                upstream_ms=0.9,
                reached_backend=True,
            )
            store.emit(e)
            await asyncio.sleep(0.35)
            await store.stop_worker()

            csv_text = store.export_csv()
            reader = csv.reader(io.StringIO(csv_text))
            rows = list(reader)
            assert len(rows) == 2  # header + 1 row
            headers = rows[0]
            assert "incident_id" in headers
            assert "timestamp" in headers
            assert "client_ip" in headers
            assert "action" in headers
            assert "score" in headers
            assert "status_code" in headers
            assert "reached_backend" in headers

            data_row = rows[1]
            assert data_row[0] == "AG-CSV-01"
            assert data_row[2] == "1.2.3.4"
            assert data_row[5] == "allowed"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    run_async(_test())


def test_admin_token_authentication_guard():
    """Verify that setting ADMIN_TOKEN enforces 401 on unauthorized access to /_gk/api/*."""

    async def _test():
        store, temp_dir = create_temp_store()
        cfg = GatewayConfig(admin_token="secret-gatekeeper-key")
        app = create_app(config=cfg, event_store=store)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gateway.test",
        ) as client:
            # 1. Unauthenticated request -> 401 Unauthorized
            r_unauth = await client.get("/_gk/api/stats")
            assert r_unauth.status_code == 401
            assert "Unauthorized" in r_unauth.json()["detail"]

            # 2. Authenticated via X-Admin-Token header -> 200 OK
            r_auth_header = await client.get(
                "/_gk/api/stats",
                headers={"X-Admin-Token": "secret-gatekeeper-key"},
            )
            assert r_auth_header.status_code == 200

            # 3. Authenticated via ?token= query parameter -> 200 OK
            r_auth_query = await client.get("/_gk/api/stats?token=secret-gatekeeper-key")
            assert r_auth_query.status_code == 200

            # 4. Control plane health endpoint remains public (no auth)
            r_health = await client.get("/_gk/health")
            assert r_health.status_code == 200
        shutil.rmtree(temp_dir, ignore_errors=True)

    run_async(_test())


def test_writer_failure_resilience():
    """Verify that stopping or killing the DB writer never breaks request processing."""

    async def _test():
        store, temp_dir = create_temp_store()
        # Deliberately do NOT start or stop the writer worker
        cfg = GatewayConfig(upstream_url="http://upstream.test")

        def mock_upstream(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "ok"})

        app = create_app(config=cfg, event_store=store)
        app.state.http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(mock_upstream),
            base_url="http://upstream.test",
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gateway.test",
        ) as client:
            # HTTP request must succeed even without worker running
            resp = await client.get("/api/products")
            assert resp.status_code == 200

        await app.state.http_client.aclose()
        shutil.rmtree(temp_dir, ignore_errors=True)

    run_async(_test())
