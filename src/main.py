"""
Hermes-IDS — Entrypoint principale.

Orchestrazione completa del servizio:
    1. Carica configurazione da YAML
    2. Configura logging strutturato JSON (structlog)
    3. Avvia metrics server Prometheus
    4. Inizializza e avvia i componenti:
       - AsyncEventQueue con drain handlers
       - TokenBucketRateLimiter
       - Detector engine (tutti i detector abilitati + plugin)
       - PacketSniffer (reale o mock)
       - ARPPoller
       - HermesGatewayAdapter
       - FastAPI REST server
    5. Gestisce graceful shutdown su SIGTERM/SIGINT

CLI::

    python -m src.main --help
    python -m src.main --config config/config.yaml
    python -m src.main --config config/config.yaml --mock-capture
    python -m src.main --config config/config.yaml --no-hermes
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import os
import signal
import sys
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
import typer
import uvicorn

from src.core.config import AppConfig
from src.core.event import IDSEvent
from src.core.queue import AsyncEventQueue
from src.core.rate_limiter import TokenBucketRateLimiter

# Configurato dopo il setup del logger
logger: structlog.stdlib.BoundLogger

app_cli = typer.Typer(
    name="hermes-ids",
    help="IDS locale integrato con Hermes.Agent",
    add_completion=False,
)


# ─── Logging setup ───────────────────────────────────────────────────────────

def setup_logging(log_level: str, log_format: str) -> None:
    """
    Configura structlog per output JSON strutturato o console human-readable.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Riduci rumore da librerie terze
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.WARNING)


# ─── Plugin loader ────────────────────────────────────────────────────────────

def load_plugins(plugins_dir: str) -> int:
    """
    Carica dinamicamente i moduli nella directory plugins/.

    Ogni modulo deve definire una o più classi con @register_detector.
    Ritorna il numero di moduli caricati con successo.
    """
    log = structlog.get_logger("plugin_loader")
    path = Path(plugins_dir)
    if not path.exists():
        log.warning(f"Plugins directory not found: {path}")
        return 0

    loaded = 0
    for py_file in path.glob("*.py"):
        if py_file.stem.startswith("_"):
            continue
        module_name = f"plugins.{py_file.stem}"
        try:
            importlib.import_module(module_name)
            log.info(f"Plugin loaded: {module_name}")
            loaded += 1
        except Exception as exc:
            log.error(f"Failed to load plugin {module_name}: {exc}")

    return loaded


# ─── Detector engine factory ──────────────────────────────────────────────────

def build_detectors(
    config: AppConfig,
    emitter,
    whitelist_manager: Optional[Any] = None,
) -> List[Any]:
    """
    Istanzia tutti i detector abilitati dalla configurazione.

    Usa il registry globale per istanziare sia i detector built-in
    che quelli caricati dai plugin.

    Args:
        config:            configurazione applicazione
        emitter:           callback async per emettere eventi
        whitelist_manager: WhitelistManager condiviso (iniettato in NewHostDetector)
    """
    from src.detectors.base import get_detector_registry

    # Importa i detector built-in per assicurarne la registrazione
    import src.detectors  # noqa: F401

    registry = get_detector_registry()
    det_config = config.detectors
    det_instances = []

    # Mappa nome-configurazione per i detector built-in
    builtin_configs: Dict[str, Dict] = {
        "port_scan_detector": det_config.port_scan.model_dump(),
        "new_host_detector": det_config.new_host.model_dump(),
        "traffic_volume_detector": det_config.traffic_volume.model_dump(),
        "sensitive_ports_detector": det_config.sensitive_ports.model_dump(),
        "arp_spoof_detector": det_config.arp_spoof.model_dump(),
    }

    for name, cls in registry.items():
        cfg = builtin_configs.get(name, {"enabled": True})
        if cfg.get("enabled", True):
            # NewHostDetector riceve il WhitelistManager condiviso
            if name == "new_host_detector" and whitelist_manager is not None:
                instance = cls(
                    config=cfg,
                    emitter=emitter,
                    whitelist_manager=whitelist_manager,
                )
            else:
                instance = cls(config=cfg, emitter=emitter)
            det_instances.append(instance)
            structlog.get_logger("engine").info(
                f"Detector instantiated: {name}"
            )

    return det_instances


# ─── Orchestrazione principale ────────────────────────────────────────────────

class IDSEngine:
    """
    Motore principale del servizio IDS.

    Coordina tutti i componenti e gestisce il ciclo di vita.
    """

    def __init__(self, config: AppConfig, mock_capture: bool = False) -> None:
        self.config = config
        self.mock_capture = mock_capture
        self._shutdown_event = asyncio.Event()
        self.log = structlog.get_logger("engine")

        # Componenti (inizializzati in start())
        self.event_queue: Optional[AsyncEventQueue] = None
        self.rate_limiter: Optional[TokenBucketRateLimiter] = None
        self.detectors: List[Any] = []
        self.sniffer: Optional[Any] = None
        self.arp_poller: Optional[Any] = None
        self.gateway: Optional[Any] = None
        self.whitelist_manager: Optional[Any] = None
        self.event_store: deque = deque(maxlen=config.api.events_history_size)
        self.app_state: Dict[str, Any] = {}

    async def start(self) -> None:
        """Avvia tutti i componenti in ordine."""
        from src.api import metrics as prom_metrics
        from src.api.routes.events import add_event
        from src.capture.arp_poller import ARPPoller
        from src.capture.sniffer import PacketSniffer

        # ── Rate limiter ──────────────────────────────────────────────────────
        rl_cfg = self.config.rate_limiter
        self.rate_limiter = TokenBucketRateLimiter(
            max_per_second=rl_cfg.max_events_per_second,
            burst_size=rl_cfg.burst_size,
            enabled=rl_cfg.enabled,
        )
        self.log.info("Rate limiter initialized", **rl_cfg.model_dump())

        # ── Whitelist Manager ─────────────────────────────────────────────────
        from src.core.whitelist import WhitelistManager
        wl_file = self.config.detectors.new_host.known_hosts_file
        self.whitelist_manager = WhitelistManager(wl_file)
        loaded_hosts = await self.whitelist_manager.load()
        self.log.info("WhitelistManager loaded", hosts=loaded_hosts, file=wl_file)

        # ── Event queue ───────────────────────────────────────────────────────
        q_cfg = self.config.queue
        self.event_queue = AsyncEventQueue(
            max_size=q_cfg.max_size,
            drain_interval=q_cfg.drain_interval,
        )

        # ── Gateway ───────────────────────────────────────────────────────────
        adapter_type = self.config.hermes.adapter if self.config.hermes.enabled else "mock"
        if adapter_type == "webhook":
            from src.gateway.hermes_webhook_adapter import HermesWebhookAdapter
            self.gateway = HermesWebhookAdapter(self.config.hermes)
            self.log.info("Using HermesWebhookAdapter (HTTP POST)")
        elif adapter_type == "websocket":
            from src.gateway.hermes_adapter import HermesGatewayAdapter
            self.gateway = HermesGatewayAdapter(self.config.hermes)
            self.log.info("Using HermesGatewayAdapter (WebSocket)")
        else:
            from src.gateway.mock_adapter import MockGatewayAdapter
            self.gateway = MockGatewayAdapter()
            self.log.info("Using MockGatewayAdapter (no Hermes)")

        await self.gateway.connect()

        # ── Drain handlers ────────────────────────────────────────────────────
        async def on_event(event: IDSEvent) -> None:
            """
            Handler centrale: metriche + store + gateway (fire-and-forget).

            Il publish al gateway è schedulato come task background per non
            bloccare il drain loop: Hermes/Telegram può essere lento o assente.

            NOTA: add_event() e self.event_store condividono la STESSA deque
            (iniettata da server.py via set_event_store). Usiamo solo add_event()
            per evitare duplicati.
            """
            # Metriche
            prom_metrics.record_event(event.detector_name, event.severity.value)
            # Store locale — add_event() scrive sulla deque condivisa con la REST API
            add_event(event)
            # Gateway — fire-and-forget: non blocca il drain loop
            asyncio.ensure_future(_publish_event(event))

        async def _publish_event(event: IDSEvent) -> None:
            """Pubblica al gateway in background (retry/backoff gestiti internamente)."""
            ok = await self.gateway.publish(event)
            prom_metrics.record_publish(ok)
            prom_metrics.set_gateway_connected(
                self.gateway.status.value == "connected"
            )

        self.event_queue.add_handler(on_event)
        await self.event_queue.start()

        # ── Emitter con rate limiting ─────────────────────────────────────────
        async def rate_limited_emitter(event: IDSEvent) -> None:
            allowed = await self.rate_limiter.acquire()
            prom_metrics.record_rate_limiter(allowed)
            if allowed:
                self.event_queue.put_nowait_or_drop(event)
            else:
                prom_metrics.record_dropped()
                self.log.debug("Event rate-limited", event_id=event.id)

        # ── Detectors ─────────────────────────────────────────────────────────
        if self.config.plugins.enabled:
            loaded = load_plugins(self.config.plugins.directory)
            self.log.info(f"Loaded {loaded} plugin(s)")

        self.detectors = build_detectors(
            self.config, rate_limited_emitter, self.whitelist_manager
        )
        for det in self.detectors:
            await det.start()

        # ── Sniffer ───────────────────────────────────────────────────────────
        loop = asyncio.get_event_loop()
        self.sniffer = PacketSniffer(
            interface=self.config.capture.interface,
            bpf_filter=self.config.capture.bpf_filter,
            promiscuous=self.config.capture.promiscuous,
            loop=loop,
            use_mock=self.mock_capture,
        )

        def packet_callback(pkt: Any) -> None:
            """Bridge sync→async: dispatcha pacchetto ai detector."""
            prom_metrics.record_packet()
            # Crea task per ogni detector (non bloccante)
            for det in self.detectors:
                asyncio.ensure_future(det.process_packet(pkt))

        self.sniffer.add_callback(packet_callback)
        await self.sniffer.start()

        # ── ARP Poller ────────────────────────────────────────────────────────
        self.arp_poller = ARPPoller(
            interval_seconds=self.config.capture.arp_poll_interval,
            loop=loop,
        )

        def arp_table_callback(table: Dict[str, str]) -> None:
            """Dispatcha ARP table ai detector."""
            for det in self.detectors:
                asyncio.ensure_future(det.process_arp_table(table))

        self.arp_poller.add_callback(arp_table_callback)
        await self.arp_poller.start()

        # ── App state per la REST API ─────────────────────────────────────────
        self.app_state.update({
            "queue": self.event_queue,
            "gateway": self.gateway,
            "detectors": self.detectors,
            "sniffer": self.sniffer,
            "rate_limiter": self.rate_limiter,
            "whitelist_manager": self.whitelist_manager,
        })

        # ── Report periodico Telegram ─────────────────────────────────────────
        asyncio.ensure_future(self._report_loop())

        self.log.info(
            "Hermes-IDS engine started",
            detectors=len(self.detectors),
            mock=self.mock_capture,
        )

    # ─── Report periodico Telegram (bypass LLM) ──────────────────────────────

    def _format_report(self, events: list) -> str:
        """Formatta gli ultimi N eventi come messaggio Telegram."""
        from datetime import datetime, timezone
        SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        SEV_ORDER = ["critical", "high", "medium", "low", "info"]

        now = datetime.now(timezone.utc).strftime("%d/%m %H:%M UTC")

        counts: dict = {}
        for ev in events:
            s = ev.severity.value
            counts[s] = counts.get(s, 0) + 1

        sev_line = "  ".join(
            f"{SEV_EMOJI.get(s, '?')}×{counts[s]}"
            for s in SEV_ORDER if s in counts
        ) or "nessuno"

        lines = [
            f"📊 IDS Report — {now}",
            f"Ultimi {len(events)} eventi: {sev_line}",
            "─" * 26,
        ]

        if not events:
            lines.append("  (nessun evento recente)")
        else:
            max_ev = self.config.hermes.report.max_events
            for ev in list(events)[:max_ev]:
                sev  = ev.severity.value
                ts   = ev.timestamp.strftime("%d/%m %H:%M")
                det  = ev.detector_name.replace("_detector", "")
                src  = ev.source_ip or "?"
                summ = ev.summary[:70]
                lines.append(f"{SEV_EMOJI.get(sev, '?')} [{ts}] {det}")
                lines.append(f"   {src} — {summ}")
            if len(events) > max_ev:
                lines.append(f"  … +{len(events) - max_ev} altri")

        return "\n".join(lines)

    async def _send_report(self) -> None:
        """Invia il report su Telegram via webhook ids-report (deliver_only, no LLM)."""
        rpt = self.config.hermes.report
        if not rpt.enabled or not rpt.secret:
            return
        from src.gateway.hermes_webhook_adapter import HermesWebhookAdapter
        if not isinstance(self.gateway, HermesWebhookAdapter):
            return

        events = list(self.event_store)
        msg    = self._format_report(events)

        ok = await self.gateway.publish_text(msg, path=rpt.webhook_path, secret=rpt.secret)
        if ok:
            self.log.info("Periodic report sent to Telegram", events=len(events))
        else:
            self.log.warning("Periodic report delivery failed")

    async def _report_loop(self) -> None:
        """Background task: invia report ogni report.interval_seconds."""
        rpt = self.config.hermes.report
        if not rpt.enabled or not rpt.secret:
            self.log.info("Periodic report disabled (no secret configured)")
            return

        self.log.info(
            "Periodic report loop started",
            interval_s=rpt.interval_seconds,
            startup_delay_s=rpt.startup_delay_seconds,
        )
        # Attendi startup prima del primo invio
        try:
            await asyncio.wait_for(
                self._shutdown_event.wait(),
                timeout=float(rpt.startup_delay_seconds),
            )
            return  # shutdown durante attesa
        except asyncio.TimeoutError:
            pass

        while not self._shutdown_event.is_set():
            await self._send_report()
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=float(rpt.interval_seconds),
                )
                break  # shutdown
            except asyncio.TimeoutError:
                pass  # normale: invia prossimo report

    async def stop(self) -> None:
        """
        Graceful shutdown: stop nell'ordine inverso all'avvio.
        Garantisce che tutti gli eventi bufferizzati vengano processati.
        """
        self.log.info("Graceful shutdown started...")

        # 1. Ferma cattura nuovi pacchetti
        if self.sniffer:
            await self.sniffer.stop()
        if self.arp_poller:
            await self.arp_poller.stop()

        # 2. Stop detector
        for det in self.detectors:
            await det.stop()

        # 3. Drain + stop queue (flush eventi bufferizzati)
        if self.event_queue:
            await self.event_queue.stop()

        # 4. Disconnetti gateway
        if self.gateway:
            await self.gateway.disconnect()

        self.log.info("Hermes-IDS engine stopped")
        self._shutdown_event.set()

    def signal_shutdown(self) -> None:
        """Chiamato dal signal handler per iniziare lo shutdown."""
        self.log.info("Shutdown signal received")
        asyncio.get_event_loop().create_task(self.stop())


# ─── CLI ─────────────────────────────────────────────────────────────────────

@app_cli.command()
def run(
    config: str = typer.Option(
        "config/config.yaml",
        "--config", "-c",
        help="Path al file di configurazione YAML",
        envvar="HERMES_IDS_CONFIG",
    ),
    mock_capture: bool = typer.Option(
        False,
        "--mock-capture",
        help="Usa pacchetti sintetici (no root/Npcap necessario)",
    ),
    no_hermes: bool = typer.Option(
        False,
        "--no-hermes",
        help="Disabilita la pubblicazione al gateway Hermes",
    ),
    log_level: Optional[str] = typer.Option(
        None,
        "--log-level",
        help="Livello di log: DEBUG, INFO, WARNING, ERROR",
    ),
) -> None:
    """Avvia il servizio Hermes-IDS."""
    # Carica configurazione
    try:
        cfg = AppConfig.from_yaml(config)
    except FileNotFoundError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1)

    # Override CLI
    if log_level:
        cfg.service.log_level = log_level.upper()
    if no_hermes:
        cfg.hermes.enabled = False

    # Logging
    setup_logging(cfg.service.log_level, cfg.service.log_format)
    global logger
    logger = structlog.get_logger("main")

    logger.info(
        "Starting Hermes-IDS",
        version=cfg.service.version,
        config=config,
        mock_capture=mock_capture,
    )

    # Avvia metrics server Prometheus
    if cfg.metrics.enabled:
        from src.api import metrics as prom_metrics
        prom_metrics.start_metrics_server(cfg.metrics.port)

    # Avvia event loop
    asyncio.run(_async_main(cfg, mock_capture))


async def _async_main(config: AppConfig, mock_capture: bool) -> None:
    """
    Coroutine principale async.

    Uvicorn gira in un thread separato con il proprio event loop per
    evitare contese I/O con il loop del motore IDS (sniffer + detector).
    """
    import threading

    engine = IDSEngine(config, mock_capture=mock_capture)

    # Signal handlers (CTRL+C)
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            asyncio.get_event_loop().add_signal_handler(sig, engine.signal_shutdown)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda s, f: engine.signal_shutdown())

    # Avvia il motore IDS
    await engine.start()

    # Costruisce la FastAPI app
    from src.api.server import create_app

    fastapi_app = create_app(
        api_config=config.api,
        app_state=engine.app_state,
        event_store=engine.event_store,
    )

    server_config = uvicorn.Config(
        app=fastapi_app,
        host=config.api.host,
        port=config.api.port,
        log_level=config.service.log_level.lower(),
        access_log=False,
        # Uvicorn gestisce il proprio loop nel thread separato
        loop="asyncio",
    )
    server = uvicorn.Server(server_config)

    # Avvia uvicorn in un thread dedicato (loop separato dal motore IDS)
    # Questo evita che le callback call_soon_threadsafe del sniffer soffochino
    # l'I/O HTTP di uvicorn.
    def run_uvicorn() -> None:
        """Thread uvicorn con il proprio event loop asyncio."""
        asyncio.run(server.serve())

    uvicorn_thread = threading.Thread(
        target=run_uvicorn,
        name="uvicorn-server",
        daemon=True,
    )
    uvicorn_thread.start()

    # Attende la terminazione (shutdown event o CTRL+C)
    try:
        await engine._shutdown_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        # Segnala a uvicorn di uscire
        server.should_exit = True
        uvicorn_thread.join(timeout=5)
        if not engine._shutdown_event.is_set():
            await engine.stop()


def cli_entry() -> None:
    """Entrypoint per pyproject.toml scripts."""
    app_cli()


if __name__ == "__main__":
    app_cli()
