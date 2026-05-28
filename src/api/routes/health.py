"""
Health check endpoints.

    GET /health  — liveness probe: il servizio è in piedi
    GET /ready   — readiness probe: tutti i componenti sono operativi
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])

# Riferimento all'app state (iniettato da server.py)
_app_state: Dict[str, Any] = {}


def set_app_state(state: Dict[str, Any]) -> None:
    """Inietta il riferimento allo stato applicativo condiviso."""
    global _app_state
    _app_state = state


@router.get(
    "/health",
    summary="Liveness probe",
    response_description="Il servizio è in esecuzione",
    status_code=status.HTTP_200_OK,
)
async def health() -> Dict[str, Any]:
    """
    Liveness probe — verifica che il processo sia vivo.

    Da usare con Kubernetes `livenessProbe` o healthcheck Docker.
    Ritorna sempre 200 se il processo risponde.
    """
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "hermes-ids",
    }


@router.get(
    "/ready",
    summary="Readiness probe",
    response_description="Tutti i componenti sono operativi",
)
async def ready() -> JSONResponse:
    """
    Readiness probe — verifica che tutti i componenti siano pronti.

    Controlla:
    - Queue drain loop attivo
    - Gateway connesso (o disabled)
    - Sniffer in esecuzione (o mock mode)

    Ritorna 200 se tutto ok, 503 se qualcosa non è pronto.
    """
    checks: Dict[str, str] = {}
    all_ok = True

    # Check queue
    queue = _app_state.get("queue")
    if queue:
        checks["queue"] = "ok" if queue._running else "not_running"
        if not queue._running:
            all_ok = False
    else:
        checks["queue"] = "unavailable"
        all_ok = False

    # Check gateway
    gateway = _app_state.get("gateway")
    if gateway:
        from src.gateway.base import GatewayStatus
        gw_status = gateway.status
        if gw_status in (GatewayStatus.CONNECTED, GatewayStatus.DISABLED):
            checks["gateway"] = "ok"
        else:
            checks["gateway"] = gw_status.value
            # Gateway non connesso non è bloccante (rientrerà)
    else:
        checks["gateway"] = "disabled"

    # Check sniffer
    sniffer = _app_state.get("sniffer")
    if sniffer:
        checks["sniffer"] = "ok" if sniffer._running else "stopped"
    else:
        checks["sniffer"] = "unavailable"
        all_ok = False

    http_status = status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(
        content={
            "status": "ready" if all_ok else "not_ready",
            "checks": checks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        status_code=http_status,
    )
