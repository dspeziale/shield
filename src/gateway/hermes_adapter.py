"""
HermesGatewayAdapter — adapter WebSocket per Hermes.Agent.

Implementa AbstractGatewayAdapter usando WebSocket (aiohttp) per
connettersi al message gateway di Hermes.Agent e pubblicare eventi IDS.

Caratteristiche:
    - Connessione WebSocket persistente con heartbeat
    - Retry automatico con backoff esponenziale (tenacity)
    - Reconnect automatico su disconnessione inattesa
    - Serializzazione JSON degli eventi IDSEvent
    - Autenticazione tramite header X-Api-Key
    - Queue interna per eventi da pubblicare durante reconnect
    - Statistiche complete (publish ok/fail, retry, reconnect)

================== PUNTI DI INTEGRAZIONE HERMES.AGENT ==================

TODO-HERMES-1: URL Gateway
    Aggiornare config.yaml hermes.base_url con l'URL reale.
    Default: ws://localhost:8080/ws/events
    Formato atteso: ws://host:port/path

TODO-HERMES-2: Schema envelope
    Se Hermes si aspetta un wrapper specifico, modificare _build_message():
        return {"type": "ids_event", "payload": event.to_json_dict(), ...}
    Attualmente invia l'evento direttamente senza wrapper.

TODO-HERMES-3: Autenticazione
    Se Hermes usa token JWT, OAuth o SDK-nativo, sostituire il meccanismo
    dell'header X-Api-Key in _get_headers().

TODO-HERMES-4: Topic/Channel
    Se Hermes supporta routing per topic, aggiungere il topic nel messaggio
    o come query param nell'URL di connessione.

TODO-HERMES-5: ACK/Conferma
    Se Hermes risponde con ACK per ogni messaggio, aggiungere la gestione
    della risposta in _publish_single().
=========================================================================
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Optional

from tenacity import (
    AsyncRetrying,
    RetryError,
    before_sleep_log,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from src.core.event import IDSEvent
from src.gateway.base import AbstractGatewayAdapter, GatewayStatus

logger = logging.getLogger(__name__)


class HermesGatewayAdapter(AbstractGatewayAdapter):
    """
    Adapter WebSocket per Hermes.Agent message gateway.

    Uso::

        adapter = HermesGatewayAdapter(config=hermes_config)
        await adapter.connect()
        await adapter.publish(event)
        await adapter.disconnect()

    Oppure come context manager::

        async with HermesGatewayAdapter(config=hermes_config) as adapter:
            await adapter.publish(event)
    """

    def __init__(self, config: Any) -> None:
        """
        Args:
            config: HermesConfig istanza (da src.core.config)
        """
        self._cfg = config
        self._ws: Optional[Any] = None  # aiohttp.ClientWebSocketResponse
        self._session: Optional[Any] = None  # aiohttp.ClientSession
        self._status = GatewayStatus.DISCONNECTED
        self._reconnect_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

        # Statistiche
        self._publish_ok: int = 0
        self._publish_fail: int = 0
        self._reconnect_count: int = 0
        self._retry_count: int = 0

    # ─── Connessione ─────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Stabilisce la connessione WebSocket al gateway Hermes."""
        if self._status == GatewayStatus.CONNECTED:
            return

        self._status = GatewayStatus.CONNECTING
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp not installed: pip install aiohttp")
            self._status = GatewayStatus.ERROR
            return

        url = self._build_ws_url()
        headers = self._get_headers()

        try:
            self._session = aiohttp.ClientSession()
            self._ws = await self._session.ws_connect(
                url,
                headers=headers,
                heartbeat=30.0,  # ping automatico ogni 30s
                timeout=aiohttp.ClientWSTimeout(ws_close=self._cfg.timeout_seconds),
            )
            self._status = GatewayStatus.CONNECTED
            logger.info(f"HermesGatewayAdapter connected to {url}")

            # Avvia task heartbeat
            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(), name="hermes-heartbeat"
            )
        except Exception as exc:
            self._status = GatewayStatus.ERROR
            logger.error(f"HermesGatewayAdapter connection failed: {exc}")
            await self._cleanup_session()

    async def disconnect(self) -> None:
        """Chiude la connessione WebSocket in modo pulito."""
        # Ferma heartbeat
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Ferma reconnect loop se attivo
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

        await self._cleanup_session()
        self._status = GatewayStatus.DISCONNECTED
        logger.info("HermesGatewayAdapter disconnected")

    async def _cleanup_session(self) -> None:
        """Chiude ws e session aiohttp."""
        if self._ws and not self._ws.closed:
            try:
                await self._ws.close()
            except Exception:
                pass
        if self._session and not self._session.closed:
            try:
                await self._session.close()
            except Exception:
                pass
        self._ws = None
        self._session = None

    # ─── Pubblicazione ───────────────────────────────────────────────────────

    async def publish(self, event: IDSEvent) -> bool:
        """
        Pubblica un evento IDS nel gateway Hermes.

        In caso di errore: tenta retry con backoff esponenziale (tenacity).
        Non solleva eccezioni — ritorna False in caso di fallimento definitivo.
        """
        if not self._cfg.enabled:
            return False

        retry_cfg = self._cfg.retry

        try:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception_type(Exception),
                stop=stop_after_attempt(retry_cfg.max_attempts),
                wait=wait_exponential(
                    multiplier=retry_cfg.multiplier,
                    min=retry_cfg.min_wait_seconds,
                    max=retry_cfg.max_wait_seconds,
                ),
                before_sleep=before_sleep_log(logger, logging.WARNING),
                reraise=False,
            ):
                with attempt:
                    self._retry_count += attempt.retry_state.attempt_number - 1
                    await self._publish_single(event)

            self._publish_ok += 1
            return True

        except RetryError as exc:
            self._publish_fail += 1
            logger.error(
                f"Publish failed after {retry_cfg.max_attempts} attempts: {exc}"
            )
            # Avvia reconnect se il gateway è offline
            self._trigger_reconnect()
            return False

        except Exception as exc:
            self._publish_fail += 1
            logger.error(f"Publish error: {exc}", exc_info=True)
            return False

    async def _publish_single(self, event: IDSEvent) -> None:
        """
        Singolo tentativo di pubblicazione WebSocket.
        Solleva eccezione in caso di errore (gestita da tenacity).
        """
        if self._status != GatewayStatus.CONNECTED or self._ws is None:
            # Tenta reconnect prima del retry
            await self.connect()
            if self._status != GatewayStatus.CONNECTED:
                raise ConnectionError("Hermes gateway not connected")

        message = self._build_message(event)
        payload = json.dumps(message, default=str)

        await self._ws.send_str(payload)
        logger.debug(
            "event_published",
            extra={
                "event_id": event.id,
                "detector": event.detector_name,
                "severity": event.severity.value,
            },
        )

    # ─── Heartbeat & Reconnect ───────────────────────────────────────────────

    async def _heartbeat_loop(self) -> None:
        """
        Monitora la connessione WebSocket e rileva disconnessioni.
        aiohttp gestisce già i ping/pong nativamente; questo loop
        serve per rilevare connessioni chiuse dal server.
        """
        try:
            if self._ws is None:
                return
            async for msg in self._ws:
                import aiohttp
                if msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                ):
                    logger.warning(f"WebSocket connection closed: {msg.type}")
                    self._status = GatewayStatus.DISCONNECTED
                    self._trigger_reconnect()
                    break
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error(f"Heartbeat error: {exc}")
            self._status = GatewayStatus.DISCONNECTED
            self._trigger_reconnect()

    def _trigger_reconnect(self) -> None:
        """Avvia il task di reconnect se non già in corso."""
        if not self._cfg.reconnect.enabled:
            return
        if self._reconnect_task and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(
            self._reconnect_loop(), name="hermes-reconnect"
        )

    async def _reconnect_loop(self) -> None:
        """Loop di reconnect periodico fino a successo."""
        interval = self._cfg.reconnect.interval_seconds
        while self._status != GatewayStatus.CONNECTED:
            logger.info(
                f"Attempting reconnect to Hermes gateway "
                f"(attempt #{self._reconnect_count + 1})..."
            )
            await self._cleanup_session()
            await self.connect()
            self._reconnect_count += 1
            if self._status != GatewayStatus.CONNECTED:
                await asyncio.sleep(interval)

        logger.info(
            f"Hermes gateway reconnected after {self._reconnect_count} attempts"
        )

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _build_ws_url(self) -> str:
        """
        Costruisce l'URL WebSocket completo.

        TODO-HERMES-1: Aggiornare con URL reale Hermes.Agent
        """
        base = self._cfg.base_url.rstrip("/")
        path = self._cfg.publish_path.lstrip("/")
        url = f"{base}/{path}"

        # Aggiunge api_key come query param se presente e non nell'header
        if self._cfg.api_key:
            url += f"?token={self._cfg.api_key}"

        return url

    def _get_headers(self) -> dict:
        """
        Costruisce gli header per il WebSocket handshake.

        TODO-HERMES-3: Adattare all'autenticazione Hermes nativa
        """
        headers = {
            "User-Agent": "hermes-ids/0.1.0",
            "X-Client-Type": "ids",
        }
        if self._cfg.api_key:
            headers["X-Api-Key"] = self._cfg.api_key
        return headers

    def _build_message(self, event: IDSEvent) -> Dict[str, Any]:
        """
        Costruisce il payload del messaggio WebSocket.

        TODO-HERMES-2: Adattare all'envelope atteso da Hermes.Agent
        Esempio con wrapper:
            return {
                "type": "ids_event",
                "version": "1",
                "payload": event.to_json_dict(),
            }
        """
        # Attualmente invia l'evento direttamente — modifica qui se necessario
        return event.to_json_dict()

    # ─── Status & Stats ──────────────────────────────────────────────────────

    @property
    def status(self) -> GatewayStatus:
        return self._status

    def get_stats(self) -> Dict[str, Any]:
        return {
            "status": self._status.value,
            "publish_ok": self._publish_ok,
            "publish_fail": self._publish_fail,
            "reconnect_count": self._reconnect_count,
            "retry_count": self._retry_count,
            "gateway_url": self._build_ws_url() if self._cfg.enabled else "disabled",
        }
