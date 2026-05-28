"""
Prometheus Metrics per Hermes-IDS.

Registra tutte le metriche Prometheus del servizio:
    ids_events_total            Counter — eventi per detector + severity
    ids_events_dropped_total    Counter — eventi scartati per overflow queue
    ids_queue_depth             Gauge   — dimensione attuale della coda
    ids_packets_captured_total  Counter — pacchetti catturati dallo sniffer
    ids_gateway_publish_total   Counter — pubblicazioni gateway per esito
    ids_gateway_connected       Gauge   — 1 se connesso, 0 altrimenti

Esposizione:
    Porta 9090 — /metrics (scraping Prometheus)
    La porta è separata dall'API principale (8765) per sicurezza.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_metrics_available = False
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        start_http_server,
    )
    _metrics_available = True
except ImportError:
    logger.warning("prometheus_client not installed — metrics disabled")

# ─── Definizione metriche ────────────────────────────────────────────────────

if _metrics_available:
    # Eventi IDS generati per detector e severity
    IDS_EVENTS_TOTAL = Counter(
        "ids_events_total",
        "Total IDS events generated",
        labelnames=["detector", "severity"],
    )

    # Eventi scartati per overflow della coda interna
    IDS_EVENTS_DROPPED = Counter(
        "ids_events_dropped_total",
        "Total IDS events dropped due to queue overflow",
    )

    # Dimensione attuale della coda interna
    IDS_QUEUE_DEPTH = Gauge(
        "ids_queue_depth",
        "Current depth of the internal event queue",
    )

    # Pacchetti catturati dallo sniffer
    IDS_PACKETS_CAPTURED = Counter(
        "ids_packets_captured_total",
        "Total packets captured by the sniffer",
    )

    # Pubblicazioni al gateway per esito (success/failure)
    IDS_GATEWAY_PUBLISH = Counter(
        "ids_gateway_publish_total",
        "Total gateway publish attempts",
        labelnames=["outcome"],  # "success" | "failure"
    )

    # Stato connessione gateway (1=connected, 0=disconnected)
    IDS_GATEWAY_CONNECTED = Gauge(
        "ids_gateway_connected",
        "Gateway connection status (1=connected, 0=disconnected)",
    )

    # Rate limiter — richieste permesse/rifiutate
    IDS_RATE_LIMITER = Counter(
        "ids_rate_limiter_total",
        "Rate limiter decisions",
        labelnames=["decision"],  # "allowed" | "rejected"
    )


def record_event(detector: str, severity: str) -> None:
    """Incrementa il counter degli eventi per detector + severity."""
    if _metrics_available:
        IDS_EVENTS_TOTAL.labels(detector=detector, severity=severity).inc()


def record_dropped() -> None:
    """Incrementa il counter degli eventi scartati."""
    if _metrics_available:
        IDS_EVENTS_DROPPED.inc()


def set_queue_depth(depth: int) -> None:
    """Aggiorna il gauge della profondità coda."""
    if _metrics_available:
        IDS_QUEUE_DEPTH.set(depth)


def record_packet() -> None:
    """Incrementa il counter dei pacchetti catturati."""
    if _metrics_available:
        IDS_PACKETS_CAPTURED.inc()


def record_publish(success: bool) -> None:
    """Registra l'esito di una pubblicazione gateway."""
    if _metrics_available:
        outcome = "success" if success else "failure"
        IDS_GATEWAY_PUBLISH.labels(outcome=outcome).inc()


def set_gateway_connected(connected: bool) -> None:
    """Aggiorna lo stato di connessione del gateway."""
    if _metrics_available:
        IDS_GATEWAY_CONNECTED.set(1 if connected else 0)


def record_rate_limiter(allowed: bool) -> None:
    """Registra decisione del rate limiter."""
    if _metrics_available:
        decision = "allowed" if allowed else "rejected"
        IDS_RATE_LIMITER.labels(decision=decision).inc()


def start_metrics_server(port: int = 9090) -> None:
    """
    Avvia il server HTTP Prometheus sulla porta specificata.

    Questo è un server separato dall'API FastAPI principale,
    accessibile solo per il scraping Prometheus.
    """
    if not _metrics_available:
        logger.warning("Metrics server not started — prometheus_client not available")
        return
    try:
        start_http_server(port)
        logger.info(f"Prometheus metrics server started on :{port}/metrics")
    except Exception as exc:
        logger.error(f"Failed to start metrics server on port {port}: {exc}")


def get_metrics_text() -> str:
    """Ritorna le metriche in formato Prometheus text (per /metrics endpoint)."""
    if not _metrics_available:
        return "# metrics not available\n"
    return generate_latest().decode("utf-8")
