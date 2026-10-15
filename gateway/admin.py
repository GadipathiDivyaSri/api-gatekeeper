"""
Control Plane Admin API Router (Module M5).
Endpoints under /_gk/api for KPIs, events, incidents, timeline, rules, bans,
CSV export, and dry-run payload testing with X-Admin-Token authentication.
"""

from __future__ import annotations

import csv
import io
import time
import urllib.parse
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from gateway.config import GatewayConfig
from gateway.events import EventStore
from gateway.models import RequestContext
from gateway.normalizer import build_targets
from gateway.pipeline import inspect
from gateway.ratelimit import BanManager
from gateway.rules import RuleManager


admin_router = APIRouter(prefix="/_gk/api", tags=["Control Plane Admin"])


# -----------------------------------------------------------------------------
# Authentication Guard: X-Admin-Token / ?token=
# -----------------------------------------------------------------------------


def verify_admin_token(
    request: Request,
    x_admin_token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
    token: Annotated[str | None, Query()] = None,
) -> None:
    """Validate admin token if ADMIN_TOKEN is configured."""
    config: GatewayConfig = request.app.state.config
    expected_token = config.admin_token
    if not expected_token:
        return  # Open access in local demo mode

    provided_token = x_admin_token or token
    if not provided_token or provided_token != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing admin token",
        )


# -----------------------------------------------------------------------------
# KPI Stats & Event Feed
# -----------------------------------------------------------------------------


@admin_router.get("/stats", dependencies=[Depends(verify_admin_token)])
def get_stats(
    request: Request,
    window: Annotated[int, Query(ge=0, description="Rolling time window in seconds (0 = all time)")] = 900,
) -> dict[str, Any]:
    """Retrieve security gateway KPIs and aggregated metrics."""
    store: EventStore = request.app.state.event_store
    stats = store.get_stats(window=window)
    contract_active = False
    if hasattr(request.app.state, "contract_manager") and request.app.state.contract_manager is not None:
        contract_active = request.app.state.contract_manager.is_active
    stats["contract_active"] = contract_active
    return stats


@admin_router.get("/events", dependencies=[Depends(verify_admin_token)])
def get_events(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    action: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
) -> list[dict[str, Any]]:
    """Retrieve list of recent security audit events."""
    store: EventStore = request.app.state.event_store
    return store.get_events(limit=limit, action=action, category=category)


@admin_router.get("/events/{incident_id}", dependencies=[Depends(verify_admin_token)])
def get_event_detail(
    incident_id: str,
    request: Request,
) -> dict[str, Any]:
    """Retrieve incident detail by unique incident_id."""
    store: EventStore = request.app.state.event_store
    event = store.get_event_by_incident_id(incident_id)
    if not event:
        raise HTTPException(status_code=404, detail="Incident not found")
    return event


@admin_router.get("/timeline", dependencies=[Depends(verify_admin_token)])
def get_timeline(
    request: Request,
    bucket: Annotated[int, Query(ge=1, le=3600)] = 10,
    window: Annotated[int, Query(ge=1, le=86400)] = 900,
) -> list[dict[str, Any]]:
    """Retrieve time-series histogram buckets of allowed vs blocked requests."""
    store: EventStore = request.app.state.event_store
    return store.get_timeline(bucket=bucket, window=window)


@admin_router.get("/top-attackers", dependencies=[Depends(verify_admin_token)])
def get_top_attackers(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> list[dict[str, Any]]:
    """Retrieve top attacker IP addresses leaderboard."""
    store: EventStore = request.app.state.event_store
    return store.get_top_attackers(limit=limit)


@admin_router.get("/export.csv", dependencies=[Depends(verify_admin_token)])
def export_csv(request: Request) -> Response:
    """Download full event audit trail as CSV."""
    store: EventStore = request.app.state.event_store
    csv_data = store.export_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="gatekeeper_events.csv"'},
    )


# -----------------------------------------------------------------------------
# Gateway Mode & Rules Management
# -----------------------------------------------------------------------------


class ModeRequest(BaseModel):
    mode: str = Field(..., pattern="^(block|monitor)$")


@admin_router.get("/mode", dependencies=[Depends(verify_admin_token)])
def get_mode(request: Request) -> dict[str, str]:
    """Get active operating mode."""
    return {"mode": request.app.state.config.mode}


@admin_router.post("/mode", dependencies=[Depends(verify_admin_token)])
async def set_mode(payload: ModeRequest, request: Request) -> dict[str, str]:
    """Toggle gateway mode between 'block' and 'monitor' and broadcast change live."""
    request.app.state.config.mode = payload.mode
    ws_mgr = getattr(request.app.state, "ws_manager", None)
    if ws_mgr:
        await ws_mgr.broadcast({
            "type": "mode_changed",
            "mode": payload.mode,
            "ts": time.time(),
        })
    return {"mode": request.app.state.config.mode}


@admin_router.get("/mode-comparison", dependencies=[Depends(verify_admin_token)])
def get_mode_comparison(
    request: Request,
    window: Annotated[int, Query(ge=1, le=3600)] = 60,
) -> dict[str, Any]:
    """Return rolling 60s comparison metrics for block vs monitor mode."""
    store: EventStore = request.app.state.event_store
    return store.get_mode_comparison(window_sec=window, current_mode=request.app.state.config.mode)


@admin_router.get("/rules", dependencies=[Depends(verify_admin_token)])
def list_rules(request: Request) -> list[dict[str, Any]]:
    """List all signature rules and their active status."""
    rule_mgr: RuleManager = request.app.state.rule_manager
    rules = rule_mgr.get_rules()
    return [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "pattern": r.pattern,
            "targets": r.targets,
            "score": r.score,
            "severity": r.severity,
            "cwe": r.cwe,
            "owasp": r.owasp,
            "attack": r.attack,
            "enabled": r.enabled,
        }
        for r in rules
    ]


@admin_router.post("/rules/reload", dependencies=[Depends(verify_admin_token)])
async def reload_rules(request: Request) -> dict[str, Any]:
    """Hot-reload signature rules and OpenAPI contract from source and broadcast update."""
    rule_mgr: RuleManager = request.app.state.rule_manager
    count = rule_mgr.reload()
    contract_active = False
    if hasattr(request.app.state, "contract_manager") and request.app.state.contract_manager is not None:
        contract_active = request.app.state.contract_manager.reload()
    ws_mgr = getattr(request.app.state, "ws_manager", None)
    if ws_mgr:
        await ws_mgr.broadcast({
            "type": "rules_reloaded",
            "count": count,
            "contract_active": contract_active,
            "ts": time.time(),
        })
    return {"status": "ok", "loaded_rules_count": count, "contract_active": contract_active}


class RuleToggleRequest(BaseModel):
    enabled: bool


@admin_router.patch("/rules/{rule_id}", dependencies=[Depends(verify_admin_token)])
async def toggle_rule(rule_id: str, payload: RuleToggleRequest, request: Request) -> dict[str, Any]:
    """Enable or disable a specific signature rule dynamically and broadcast change."""
    rule_mgr: RuleManager = request.app.state.rule_manager
    success = rule_mgr.set_rule_enabled(rule_id, payload.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    ws_mgr = getattr(request.app.state, "ws_manager", None)
    if ws_mgr:
        await ws_mgr.broadcast({
            "type": "rule_toggled",
            "rule_id": rule_id,
            "enabled": payload.enabled,
            "ts": time.time(),
        })
    return {"rule_id": rule_id, "enabled": payload.enabled}


# -----------------------------------------------------------------------------
# Ban List Management
# -----------------------------------------------------------------------------


@admin_router.get("/bans", dependencies=[Depends(verify_admin_token)])
def list_bans(request: Request) -> list[dict[str, Any]]:
    """List all currently active temporary IP bans."""
    ban_mgr: BanManager = request.app.state.ban_manager
    return ban_mgr.list_bans()


@admin_router.delete("/bans/{ip}", dependencies=[Depends(verify_admin_token)])
async def unban_ip(ip: str, request: Request) -> dict[str, Any]:
    """Remove an active ban for an IP address and broadcast update."""
    ban_mgr: BanManager = request.app.state.ban_manager
    unbanned = ban_mgr.unban(ip)
    ws_mgr = getattr(request.app.state, "ws_manager", None)
    if ws_mgr:
        await ws_mgr.broadcast({
            "type": "unbanned",
            "ip": ip,
            "unbanned": unbanned,
            "ts": time.time(),
        })
    return {"ip": ip, "unbanned": unbanned}


# -----------------------------------------------------------------------------
# Payload Tester (Dry-Run Inspection)
# -----------------------------------------------------------------------------


class TestPayloadRequest(BaseModel):
    method: str = "GET"
    path: str = "/api/products"
    query: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    client_ip: str = "127.0.0.1"


@admin_router.post("/test", dependencies=[Depends(verify_admin_token)])
def test_payload(payload: TestPayloadRequest, request: Request) -> dict[str, Any]:
    """
    Perform dry-run inspection of a test payload.
    Never forwarded to backend and does not mutate rate limit or ban state.
    Returns decision, findings, score, and complete decode chains.
    """
    parsed_q: dict[str, list[str]] = {}
    if payload.query:
        parsed_q = urllib.parse.parse_qs(payload.query, keep_blank_values=True)

    ctx = RequestContext(
        incident_id="AG-DRYRUN-TEST",
        client_ip=payload.client_ip,
        method=payload.method.upper(),
        path=payload.path if payload.path.startswith("/") else f"/{payload.path}",
        query_string=payload.query,
        query_params=parsed_q,
        headers=payload.headers,
        user_agent=payload.headers.get("user-agent", "PayloadTester/1.0"),
        body_bytes=payload.body.encode("utf-8") if payload.body else b"",
        body_text=payload.body,
        content_type=payload.headers.get("content-type", "application/json"),
    )

    targets = build_targets(ctx)
    decision = inspect(
        ctx,
        config=request.app.state.config,
        rules_manager=request.app.state.rule_manager,
        contract_manager=getattr(request.app.state, "contract_manager", None),
        dry_run=True,
    )

    # Format decode chains for dashboard visualization
    decode_chains: dict[str, list[dict[str, Any]]] = {}
    for target_name, variants in targets.items():
        decode_chains[target_name] = [
            {"text": v.text, "chain": v.chain} for v in variants if v.text
        ]

    return {
        "action": decision.action,
        "score": decision.score,
        "status_code": decision.status_code,
        "reason": decision.reason,
        "findings": [f.to_dict() for f in decision.findings],
        "decode_chains": decode_chains,
    }


# -----------------------------------------------------------------------------
# Security Benchmark & Simulator Controls (Module M7)
# -----------------------------------------------------------------------------


@admin_router.post("/benchmark", dependencies=[Depends(verify_admin_token)])
def trigger_benchmark(request: Request) -> dict[str, Any]:
    """Execute the Security Scorecard benchmark and return metrics."""
    from gateway.benchmark import run_benchmark

    return run_benchmark(
        config=request.app.state.config,
        rules_manager=request.app.state.rule_manager,
        save=True,
    )


@admin_router.get("/benchmark/latest", dependencies=[Depends(verify_admin_token)])
def get_latest_benchmark() -> dict[str, Any]:
    """Retrieve the most recently saved benchmark scorecard."""
    import json
    from pathlib import Path

    latest_path = Path("data/benchmark_latest.json")
    if not latest_path.is_file():
        from gateway.benchmark import run_benchmark

        return run_benchmark(save=True)
    with open(latest_path, "r", encoding="utf-8") as f:
        return json.load(f)


@admin_router.post("/simulate", dependencies=[Depends(verify_admin_token)])
def trigger_simulator(request: Request) -> dict[str, Any]:
    """Run attack simulator in background subprocess if DEMO_MODE=true."""
    import subprocess
    import sys
    from pathlib import Path

    config: GatewayConfig = request.app.state.config
    if not config.demo_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Attack simulator is disabled when DEMO_MODE=false",
        )

    sim_script = Path("tools/attack_sim.py").resolve()
    if not sim_script.is_file():
        raise HTTPException(status_code=500, detail="Simulator script tools/attack_sim.py not found")

    subprocess.Popen(
        [sys.executable, str(sim_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return {
        "status": "running",
        "message": "Attack simulation launched in background",
    }

