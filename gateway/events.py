"""
Event Store and Security Analytics (Module M5).
Asynchronous batch event writer (SQLite WAL + events.jsonl),
live WebSocket event broadcasting, and high-performance KPI analytics queries.
Never blocks the HTTP request path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from gateway.models import Event
from gateway.ws import WebSocketManager, get_ws_manager

logger = logging.getLogger("api_gatekeeper.events")


class EventStore:
    """Manages SQLite event persistence, JSONL logging, queue batching, and analytics."""

    def __init__(
        self,
        data_dir: Path | str | None = None,
        ws_manager: WebSocketManager | None = None,
    ) -> None:
        self.data_dir = Path(data_dir or os.getenv("DATA_DIR", "data"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "events.db"
        self.jsonl_path = self.data_dir / "events.jsonl"
        self.ws_manager = ws_manager or get_ws_manager()

        self.queue: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=10_000)
        self.running: bool = False
        self._worker_task: asyncio.Task[None] | None = None

        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database with WAL mode and schema."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT UNIQUE NOT NULL,
                        ts REAL NOT NULL,
                        client_ip TEXT NOT NULL,
                        method TEXT NOT NULL,
                        path TEXT NOT NULL,
                        query TEXT,
                        user_agent TEXT,
                        body_excerpt TEXT,
                        decoded_excerpt TEXT,
                        action TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        primary_category TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        findings TEXT NOT NULL,
                        status_code INTEGER NOT NULL,
                        latency_ms REAL NOT NULL,
                        upstream_ms REAL NOT NULL,
                        reached_backend INTEGER NOT NULL
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events(client_ip);")
        finally:
            conn.close()

    def start_worker(self) -> None:
        """Start the background writer task."""
        if not self.running:
            self.running = True
            self._worker_task = asyncio.create_task(self._batch_writer_loop())

    async def stop_worker(self) -> None:
        """Stop writer task and flush any remaining items in queue."""
        if self.running:
            self.running = False
            await self.queue.put(None)  # Sentinel to wake up worker
            if self._worker_task:
                try:
                    await asyncio.wait_for(self._worker_task, timeout=2.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                self._worker_task = None

    def emit(self, event: Event) -> None:
        """
        Non-blocking enqueue of an event.
        Never throws or blocks the caller if the queue or DB fails.
        """
        try:
            self.queue.put_nowait(event)
        except Exception as exc:
            logger.warning("Event queue full or error while enqueueing: %s", exc)

    async def _batch_writer_loop(self) -> None:
        """
        Drains queue in batches every 250ms or up to 100 events,
        writing to SQLite and appending to JSONL.
        """
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")

        try:
            while self.running or not self.queue.empty():
                batch: list[Event] = []

                # Wait for at least one event or timeout after 250ms
                try:
                    first_event = await asyncio.wait_for(self.queue.get(), timeout=0.25)
                    if first_event is not None:
                        batch.append(first_event)
                except asyncio.TimeoutError:
                    pass

                # Drain additional events currently in queue (up to 100)
                while len(batch) < 100 and not self.queue.empty():
                    item = self.queue.get_nowait()
                    if item is not None:
                        batch.append(item)

                if batch:
                    await self._write_batch(conn, batch)

        except asyncio.CancelledError:
            # Drain remaining items on cancellation
            batch = []
            while not self.queue.empty():
                item = self.queue.get_nowait()
                if item is not None:
                    batch.append(item)
            if batch:
                await self._write_batch(conn, batch)
        except Exception as exc:
            logger.error("Unexpected error in event writer loop: %s", exc, exc_info=True)
        finally:
            conn.close()

    async def _write_batch(self, conn: sqlite3.Connection, batch: list[Event]) -> None:
        """Write batch of events to SQLite, append to JSONL, and broadcast over WebSocket."""
        # 1. SQLite Batch Insert
        try:
            records = [
                (
                    e.incident_id,
                    e.ts,
                    e.client_ip,
                    e.method,
                    e.path,
                    e.query[:1024] if e.query else "",
                    e.user_agent[:256] if e.user_agent else "",
                    e.body_excerpt[:2048] if e.body_excerpt else "",
                    e.decoded_excerpt[:2048] if e.decoded_excerpt else "",
                    e.action,
                    e.score,
                    e.primary_category,
                    e.severity,
                    json.dumps(e.findings),
                    e.status_code,
                    e.latency_ms,
                    e.upstream_ms,
                    1 if e.reached_backend else 0,
                )
                for e in batch
            ]
            with conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO events (
                        incident_id, ts, client_ip, method, path, query, user_agent,
                        body_excerpt, decoded_excerpt, action, score, primary_category,
                        severity, findings, status_code, latency_ms, upstream_ms, reached_backend
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    records,
                )
        except Exception as exc:
            logger.error("Failed to write event batch to SQLite: %s", exc)

        # 2. JSONL Append
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                for e in batch:
                    f.write(json.dumps(e.to_dict()) + "\n")
        except Exception as exc:
            logger.error("Failed to append event batch to JSONL: %s", exc)

        # 3. Live WebSocket Broadcast
        for e in batch:
            try:
                await self.ws_manager.broadcast(e.to_dict())
            except Exception as exc:
                logger.debug("Failed to broadcast event over WebSocket: %s", exc)

    # -------------------------------------------------------------------------
    # Analytics & Query APIs
    # -------------------------------------------------------------------------

    def get_connection(self) -> sqlite3.Connection:
        """Return a read connection with row_factory set to sqlite3.Row."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_events(
        self,
        limit: int = 50,
        action: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve recent events matching optional action and category filters."""
        limit = min(max(1, limit), 500)
        query = "SELECT * FROM events"
        conditions: list[str] = []
        params: list[Any] = []

        if action:
            conditions.append("action = ?")
            params.append(action)
        if category:
            conditions.append("primary_category = ?")
            params.append(category)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                try:
                    item["findings"] = json.loads(item["findings"])
                except Exception:
                    item["findings"] = []
                item["reached_backend"] = bool(item["reached_backend"])
                results.append(item)
            return results
        finally:
            conn.close()

    def get_event_by_incident_id(self, incident_id: str) -> dict[str, Any] | None:
        """Fetch full incident details by incident_id."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["findings"] = json.loads(item["findings"])
            except Exception:
                item["findings"] = []
            item["reached_backend"] = bool(item["reached_backend"])
            return item
        finally:
            conn.close()

    def get_stats(self, window: int = 900) -> dict[str, Any]:
        """Compute key KPI metrics over the specified rolling time window (seconds)."""
        now = time.time()
        start_ts = now - window if window > 0 else 0.0

        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            # Action counts
            cursor.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN action = 'flagged' THEN 1 ELSE 0 END) as flagged,
                    SUM(CASE WHEN action = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited,
                    SUM(CASE WHEN action = 'banned' THEN 1 ELSE 0 END) as banned,
                    COUNT(DISTINCT client_ip) as unique_ips,
                    COUNT(DISTINCT CASE WHEN action != 'allowed' THEN client_ip END) as unique_attackers,
                    SUM(CASE WHEN reached_backend = 1 THEN 1 ELSE 0 END) as reached_backend
                FROM events
                WHERE ts >= ?;
                """,
                (start_ts,),
            )
            row = cursor.fetchone()
            total = row["total"] or 0
            allowed = row["allowed"] or 0
            blocked = row["blocked"] or 0
            flagged = row["flagged"] or 0
            rate_limited = row["rate_limited"] or 0
            banned = row["banned"] or 0
            unique_ips = row["unique_ips"] or 0
            unique_attackers = row["unique_attackers"] or 0
            reached_backend = row["reached_backend"] or 0

            block_rate = round(blocked / total, 4) if total > 0 else 0.0

            # Attack category counts
            cursor.execute(
                """
                SELECT primary_category, COUNT(*) as count
                FROM events
                WHERE ts >= ? AND action != 'allowed' AND primary_category != 'none'
                GROUP BY primary_category
                ORDER BY count DESC;
                """,
                (start_ts,),
            )
            categories = {r["primary_category"]: r["count"] for r in cursor.fetchall()}

            # Latency percentiles (p50, p95)
            cursor.execute(
                """
                SELECT latency_ms FROM events
                WHERE ts >= ?
                ORDER BY latency_ms ASC;
                """,
                (start_ts,),
            )
            latencies = [r["latency_ms"] for r in cursor.fetchall()]
            p50 = 0.0
            p95 = 0.0
            if latencies:
                n = len(latencies)
                p50 = round(latencies[int(n * 0.50)], 2)
                p95 = round(latencies[min(int(n * 0.95), n - 1)], 2)

            return {
                "window_sec": window,
                "total_requests": total,
                "allowed_requests": allowed,
                "blocked_requests": blocked,
                "flagged_requests": flagged,
                "rate_limited_requests": rate_limited,
                "banned_requests": banned,
                "unique_ips": unique_ips,
                "unique_attackers": unique_attackers,
                "block_rate": block_rate,
                "reached_backend_count": reached_backend,
                "by_category": categories,
                "latency_p50_ms": p50,
                "latency_p95_ms": p95,
            }
        finally:
            conn.close()

    def get_mode_comparison(self, window_sec: int = 60, current_mode: str = "block") -> dict[str, Any]:
        """
        Compute rolling before/after mode comparison metrics over the specified window (default 60s).
        Returns counts for total, blocked at perimeter, flagged (monitor), allowed, and reached backend.
        """
        now = time.time()
        start_ts = now - window_sec if window_sec > 0 else 0.0

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN action = 'flagged' THEN 1 ELSE 0 END) as flagged,
                    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN action = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited,
                    SUM(CASE WHEN action = 'banned' THEN 1 ELSE 0 END) as banned,
                    SUM(CASE WHEN action = 'error_masked' THEN 1 ELSE 0 END) as error_masked,
                    SUM(CASE WHEN reached_backend = 1 THEN 1 ELSE 0 END) as reached_backend,
                    SUM(CASE WHEN reached_backend = 0 THEN 1 ELSE 0 END) as blocked_perimeter
                FROM events
                WHERE ts >= ?;
                """,
                (start_ts,),
            )
            row = cursor.fetchone()
            total = row["total"] or 0
            blocked = row["blocked"] or 0
            flagged = row["flagged"] or 0
            allowed = row["allowed"] or 0
            reached = row["reached_backend"] or 0
            perimeter = row["blocked_perimeter"] or 0

            return {
                "window_sec": window_sec,
                "current_mode": current_mode,
                "total_60s": total,
                "blocked_60s": blocked,
                "flagged_60s": flagged,
                "allowed_60s": allowed,
                "reached_backend_60s": reached,
                "blocked_perimeter_60s": perimeter,
            }
        finally:
            conn.close()

    def get_timeline(self, bucket: int = 10, window: int = 900) -> list[dict[str, Any]]:
        """Compute time-series histogram buckets of allowed vs blocked requests."""
        bucket = max(1, bucket)
        now = time.time()
        start_ts = now - window if window > 0 else 0.0

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    (CAST(ts / ? AS INT) * ?) as bucket_ts,
                    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN action != 'allowed' THEN 1 ELSE 0 END) as blocked,
                    COUNT(*) as total
                FROM events
                WHERE ts >= ?
                GROUP BY bucket_ts
                ORDER BY bucket_ts ASC;
                """,
                (bucket, bucket, start_ts),
            )
            return [
                {
                    "timestamp": r["bucket_ts"],
                    "allowed": r["allowed"] or 0,
                    "blocked": r["blocked"] or 0,
                    "total": r["total"] or 0,
                }
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        """Retrieve leaderboard of attacker IP addresses with attack categories and last seen."""
        limit = min(max(1, limit), 100)
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    client_ip,
                    COUNT(*) as total_attacks,
                    MAX(ts) as last_seen,
                    GROUP_CONCAT(DISTINCT primary_category) as categories
                FROM events
                WHERE action != 'allowed'
                GROUP BY client_ip
                ORDER BY total_attacks DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                cats = [c.strip() for c in (r["categories"] or "").split(",") if c.strip()]
                results.append(
                    {
                        "client_ip": r["client_ip"],
                        "total_attacks": r["total_attacks"],
                        "categories": cats,
                        "last_seen": r["last_seen"],
                    }
                )
            return results
        finally:
            conn.close()

    def export_csv(self) -> str:
        """Export all events as a comma-separated CSV string."""
        import csv
        import io

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    incident_id, ts, client_ip, method, path, action,
                    score, primary_category, severity, status_code,
                    latency_ms, upstream_ms, reached_backend
                FROM events
                ORDER BY ts ASC;
                """
            )
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(
                [
                    "incident_id",
                    "timestamp",
                    "client_ip",
                    "method",
                    "path",
                    "action",
                    "score",
                    "primary_category",
                    "severity",
                    "status_code",
                    "latency_ms",
                    "upstream_ms",
                    "reached_backend",
                ]
            )
            for row in cursor.fetchall():
                writer.writerow(list(row))
            return output.getvalue()
        finally:
            conn.close()


_DEFAULT_EVENT_STORE: EventStore | None = None


def get_event_store(data_dir: Path | str | None = None) -> EventStore:
    """Return globally cached EventStore instance."""
    global _DEFAULT_EVENT_STORE
    if _DEFAULT_EVENT_STORE is None or data_dir is not None:
        _DEFAULT_EVENT_STORE = EventStore(data_dir=data_dir)
    return _DEFAULT_EVENT_STORE
