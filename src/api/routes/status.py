"""
Status endpoint.

    GET /status  — stato completo del servizio: detector, queue, gateway, sniffer
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter

router = APIRouter(tags=["status"])

# App state condiviso
_app_state: Dict[str, Any] = {}


def set_app_state(state: Dict[str, Any]) -> None:
    global _app_state
    _app_state = state


@router.get(
    "/status",
    summary="Stato completo del servizio",
    response_description="Stato di tutti i componenti del servizio IDS",
)
async def get_status() -> Dict[str, Any]:
    """
    Ritorna lo stato completo del servizio hermes-ids.

    Include:
    - Stato e statistiche della coda eventi
    - Stato del gateway Hermes
    - Stato e statistiche di ogni detector
    - Statistiche dello sniffer
    - Statistiche del rate limiter
    - Uptime e informazioni di runtime
    """
    result: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "hermes-ids",
    }

    # ── Queue ─────────────────────────────────────────────────────────────────
    queue = _app_state.get("queue")
    if queue:
        result["queue"] = queue.get_stats()
    else:
        result["queue"] = {"status": "unavailable"}

    # ── Gateway ───────────────────────────────────────────────────────────────
    gateway = _app_state.get("gateway")
    if gateway:
        result["gateway"] = gateway.get_stats()
    else:
        result["gateway"] = {"status": "disabled"}

    # ── Detectors ─────────────────────────────────────────────────────────────
    detectors = _app_state.get("detectors", [])
    result["detectors"] = [d.get_status() for d in detectors]

    # ── Sniffer ───────────────────────────────────────────────────────────────
    sniffer = _app_state.get("sniffer")
    if sniffer:
        result["sniffer"] = {
            "running": sniffer._running,
            "interface": sniffer._interface,
            "mock_mode": sniffer._use_mock,
            "packets_captured": sniffer.packets_captured,
        }
    else:
        result["sniffer"] = {"status": "unavailable"}

    # ── Rate Limiter ──────────────────────────────────────────────────────────
    rate_limiter = _app_state.get("rate_limiter")
    if rate_limiter:
        result["rate_limiter"] = rate_limiter.get_stats()
    else:
        result["rate_limiter"] = {"status": "disabled"}

    # ── Event Store ───────────────────────────────────────────────────────────
    event_store = _app_state.get("event_store")
    if event_store is not None:
        result["event_store"] = {
            "size": len(event_store),
            "max_size": event_store.maxlen,
        }

    return result
