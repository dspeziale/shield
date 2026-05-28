"""
HermesWebhookAdapter — adapter HTTP/Webhook per Hermes.Agent.

Usa il sistema webhook di Hermes (porta 8644 di default) per pubblicare
eventi IDS. Ogni evento viene inviato come HTTP POST JSON al webhook
registrato con `hermes webhook subscribe`.

Questo è l'adapter preferito per integrazione con Hermes.Agent v0.13+,
dove il gateway è un messaging gateway (Telegram, Discord, ecc.) e riceve
eventi esterni tramite la piattaforma webhook.

Flusso:
    hermes-ids event → POST /webhooks/ids-events → Hermes gateway
                                                    → agent analysis
                                                    → Telegram / Discord

Configurazione::

    hermes:
      adapter: webhook              # <-- usa questo adapter
      base_url: http://127.0.0.1:8644
      publish_path: /webhooks/ids-events
      api_key: ""                   # = WEBHOOK_SECRET configurato in Hermes

Prerequisiti:
    hermes webhook subscribe ids-events \\
        --prompt "IDS Alert: {summary} [severity={severity}] from {source_ip}" \\
        --deliver telegram \\
        --description "Riceve eventi dall'IDS locale hermes-ids"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
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


class HermesWebhookAdapter(AbstractGatewayAdapter):
    """
    Adapter HTTP webhook per Hermes.Agent.

    Pubblica eventi IDS tramite HTTP POST al gateway webhook di Hermes.
    Non mantiene una connessione persistente: ogni publish è una richiesta
    HTTP indipendente (stateless, più semplice e robusto).

    Uso::

        adapter = HermesWebhookAdapter(config=hermes_config)
        await adapter.connect()         # no-op, verifica raggiungibilità
        ok = await adapter.publish(event)
    """

    def __init__(self, config: Any) -> None:
        self._cfg = config
        self._status = GatewayStatus.DISCONNECTED
        self._session: Optional[Any] = None  # aiohttp.ClientSession

        # Stats
        self._publish_ok: int = 0
        self._publish_fail: int = 0
        self._retry_count: int = 0

        # Circuit breaker: evita flood di retry quando il gateway è down.
        # Dopo _cb_threshold fallimenti consecutivi, apre il circuito e
        # salta i publish finché non è trascorso _cb_probe_interval secondi.
        self._cb_open: bool = False
        self._cb_failures: int = 0          # fallimenti consecutivi
        self._cb_threshold: int = 3         # apre dopo 3 fail di fila
        self._cb_probe_interval: float = 30.0  # probe ogni 30s
        self._cb_open_since: float = 0.0

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """
        Inizializza la sessione HTTP e verifica che il gateway sia raggiungibile.
        Non-blocking: lo stato si imposta su CONNECTED anche se il gateway
        non risponde (il retry avviene al momento del publish).
        """
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp not installed: pip install aiohttp")
            self._status = GatewayStatus.ERROR
            return

        # force_close=True: non riusa le connessioni keep-alive verso Hermes.
        # Evita che la 2a POST resti in attesa su una connessione chiusa dal server.
        connector = aiohttp.TCPConnector(force_close=True)
        self._session = aiohttp.ClientSession(
            headers=self._get_headers(),
            timeout=aiohttp.ClientTimeout(total=self._cfg.timeout_seconds),
            connector=connector,
        )
        self._status = GatewayStatus.CONNECTED
        logger.info(
            f"HermesWebhookAdapter ready -> {self._build_url()}"
        )

    async def disconnect(self) -> None:
        """Chiude la sessione HTTP."""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._status = GatewayStatus.DISCONNECTED
        logger.info("HermesWebhookAdapter disconnected")

    # ─── Pubblicazione ───────────────────────────────────────────────────────

    async def publish(self, event: IDSEvent) -> bool:
        """
        Pubblica un evento IDS via HTTP POST al webhook Hermes.

        Implementa un circuit breaker: dopo _cb_threshold fallimenti consecutivi
        apre il circuito e salta i publish per _cb_probe_interval secondi, poi
        riprova con un singolo tentativo (probe). Se il probe riesce il circuito
        si richiude e si torna alla normale operatività.

        Riprova con backoff esponenziale in caso di errore (quando circuito chiuso).
        Ritorna False (senza sollevare eccezioni) in caso di fallimento definitivo.
        """
        if not self._cfg.enabled:
            return False

        # ── Circuit breaker ───────────────────────────────────────────────────
        if self._cb_open:
            elapsed = time.monotonic() - self._cb_open_since
            if elapsed < self._cb_probe_interval:
                # Circuito aperto: scarta l'evento senza tentare connessione
                logger.debug(
                    f"Circuit open, skipping publish "
                    f"({self._cb_probe_interval - elapsed:.0f}s to probe)"
                )
                return False
            else:
                # Tempo di probe: riprova un singolo tentativo
                logger.info(
                    "Circuit breaker probe: attempting gateway reconnect..."
                )
                self._cb_open = False  # tentatively close; se fallisce si riapre

        if self._session is None:
            await self.connect()

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
                    await self._post_event(event)

            # Successo: azzera i fallimenti consecutivi
            self._publish_ok += 1
            if self._cb_failures > 0:
                logger.info(
                    f"Circuit breaker: gateway recovered "
                    f"(after {self._cb_failures} consecutive failures)"
                )
            self._cb_failures = 0
            return True

        except RetryError as exc:
            self._publish_fail += 1
            self._cb_failures += 1
            if self._cb_failures >= self._cb_threshold and not self._cb_open:
                self._cb_open = True
                self._cb_open_since = time.monotonic()
                logger.warning(
                    f"Circuit breaker OPEN: gateway unreachable after "
                    f"{self._cb_failures} consecutive failures. "
                    f"Probing again in {self._cb_probe_interval:.0f}s."
                )
            else:
                logger.error(
                    f"Webhook publish failed after {retry_cfg.max_attempts} attempts: {exc}"
                )
            return False

        except Exception as exc:
            self._publish_fail += 1
            self._cb_failures += 1
            logger.error(f"Webhook publish error: {exc}", exc_info=True)
            return False

    async def _post_event(self, event: IDSEvent) -> None:
        """
        Singolo POST HTTP al webhook Hermes.

        Il payload segue lo schema atteso dal webhook Hermes:
        il campo `payload` contiene l'evento IDS completo, mentre i campi
        flat (summary, severity, source_ip) sono esposti direttamente per
        il template del prompt Hermes.

        Template prompt Hermes consigliato::

            "IDS Alert [{severity}] {summary} — src: {source_ip}"
        """
        if self._session is None:
            raise ConnectionError("No HTTP session")

        # Payload: campi flat per il template Hermes + payload completo
        event_dict = event.to_json_dict()
        webhook_body = {
            # Campi flat accessibili nel prompt template Hermes ({dot.notation})
            "summary": event.summary,
            "severity": event.severity.value,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "detector_name": event.detector_name,
            "event_id": event.id,
            "timestamp": event_dict["timestamp"],
            "tags": ", ".join(event.tags),
            # Payload completo annidato
            "payload": event_dict,
        }

        url = self._build_url()
        body_bytes = json.dumps(webhook_body).encode("utf-8")
        headers = {}
        if self._cfg.api_key:
            sig = hmac.new(
                self._cfg.api_key.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Hub-Signature-256"] = f"sha256={sig}"

        async with self._session.post(
            url, data=body_bytes, headers=headers,
            # Eredita il timeout della sessione (timeout_seconds dal config)
        ) as resp:
            if resp.status not in (200, 201, 202, 204):
                body = await resp.text()
                raise RuntimeError(
                    f"Webhook POST failed: HTTP {resp.status} — {body[:200]}"
                )

        logger.debug(
            "webhook_event_posted",
            extra={
                "event_id": event.id,
                "severity": event.severity.value,
                "detector": event.detector_name,
                "url": url,
            },
        )

    async def publish_text(self, message: str, path: str, secret: str) -> bool:
        """
        Invia un messaggio testo libero a un webhook Hermes (es. ids-report).

        A differenza di publish(), non usa circuit-breaker né retry: è usato per
        report periodici dove il fallimento occasionale è accettabile.
        """
        if self._session is None:
            await self.connect()
        if self._session is None:
            return False

        url       = f"{self._cfg.base_url.rstrip('/')}{path}"
        body      = json.dumps({"message": message}).encode("utf-8")
        sig       = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers   = {"X-Hub-Signature-256": f"sha256={sig}"}

        try:
            import aiohttp as _aiohttp
            async with self._session.post(
                url, data=body, headers=headers,
                timeout=_aiohttp.ClientTimeout(total=10),
            ) as resp:
                ok = resp.status in (200, 201, 202, 204)
                if not ok:
                    body_txt = await resp.text()
                    logger.warning(f"publish_text HTTP {resp.status}: {body_txt[:100]}")
                return ok
        except Exception as exc:
            logger.warning(f"publish_text failed: {exc}")
            return False

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _build_url(self) -> str:
        """Costruisce l'URL completo del webhook Hermes."""
        base = self._cfg.base_url.rstrip("/")
        # Converti ws:// → http:// se necessario (config condivisa)
        base = base.replace("ws://", "http://").replace("wss://", "https://")
        path = self._cfg.publish_path.lstrip("/")
        return f"{base}/{path}"

    def _get_headers(self) -> dict:
        """Header HTTP per la richiesta webhook."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "hermes-ids/0.1.0",
            "X-Source": "hermes-ids",
        }
        # HMAC secret Hermes: passato come X-Hub-Signature o X-Webhook-Secret
        if self._cfg.api_key:
            headers["X-Hub-Signature"] = f"sha256={self._cfg.api_key}"
        return headers

    # ─── Status ──────────────────────────────────────────────────────────────

    @property
    def status(self) -> GatewayStatus:
        return self._status

    def get_stats(self) -> Dict[str, Any]:
        return {
            "status": self._status.value,
            "adapter_type": "webhook",
            "publish_ok": self._publish_ok,
            "publish_fail": self._publish_fail,
            "retry_count": self._retry_count,
            "webhook_url": self._build_url() if self._cfg.enabled else "disabled",
        }
