"""
FastAPI application factory per l'API REST locale di hermes-ids.

Espone:
    GET /health    — liveness probe
    GET /ready     — readiness probe
    GET /events    — lista eventi con filtri
    GET /events/{id} — singolo evento
    GET /status    — stato completo servizio
    GET /metrics   — metriche Prometheus (inline)

Nota: il server Prometheus dedicato (porta 9090) è avviato separatamente
in main.py tramite metrics.start_metrics_server().
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Any, Deque, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from src.api import metrics as prom_metrics
from src.api.routes import events as events_routes
from src.api.routes import health as health_routes
from src.api.routes import status as status_routes
from src.api.routes import whitelist as whitelist_routes
from src.core.config import APIConfig
from src.core.event import IDSEvent

logger = logging.getLogger(__name__)


def create_app(
    api_config: APIConfig,
    app_state: Dict[str, Any],
    event_store: Deque[IDSEvent],
) -> FastAPI:
    """
    Factory function per l'applicazione FastAPI.

    Args:
        api_config:  configurazione API (host, port, cors, ecc.)
        app_state:   dizionario di stato condiviso (queue, gateway, detectors, ecc.)
        event_store: ring buffer degli eventi recenti
    """
    app = FastAPI(
        title="Hermes-IDS API",
        description=(
            "REST API locale per il servizio IDS integrato con Hermes.Agent. "
            "Espone eventi di detection, stato dei componenti e metriche."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=api_config.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # ── Inietta state condiviso nelle route ───────────────────────────────────
    health_routes.set_app_state(app_state)
    status_routes.set_app_state(app_state)
    events_routes.set_event_store(event_store)
    whitelist_routes.set_whitelist_dependencies(
        manager=app_state.get("whitelist_manager"),
        event_store=event_store,
        detectors=app_state.get("detectors", []),
    )

    # Aggiungi event_store allo state per /status
    app_state["event_store"] = event_store

    # ── Registra router ───────────────────────────────────────────────────────
    app.include_router(health_routes.router)
    app.include_router(events_routes.router)
    app.include_router(status_routes.router)
    app.include_router(whitelist_routes.router)

    # ── Endpoint metrics inline (alternativo alla porta 9090) ────────────────
    @app.get(
        "/metrics",
        response_class=PlainTextResponse,
        tags=["metrics"],
        summary="Metriche Prometheus",
        include_in_schema=True,
    )
    async def metrics_endpoint() -> str:
        """Metriche Prometheus in formato text/plain per scraping."""
        return prom_metrics.get_metrics_text()

    # ── Startup / shutdown hooks ──────────────────────────────────────────────
    @app.on_event("startup")
    async def on_startup() -> None:
        logger.info(
            f"Hermes-IDS API started on {api_config.host}:{api_config.port}"
        )

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        logger.info("Hermes-IDS API shutting down")

    return app
