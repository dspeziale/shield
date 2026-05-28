"""
MockGatewayAdapter — adapter fittizio per test e sviluppo locale.

Simula un gateway senza richiedere una connessione reale.
Registra tutti gli eventi pubblicati in memoria per verifica nei test.

Modalità:
    - normal:  pubblica con successo (default)
    - failing: pubblica sempre con errore (simula gateway offline)
    - delayed: aggiunge latenza artificiale alla pubblicazione
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Literal, Optional

from src.core.event import IDSEvent
from src.gateway.base import AbstractGatewayAdapter, GatewayStatus

logger = logging.getLogger(__name__)

MockMode = Literal["normal", "failing", "delayed"]


class MockGatewayAdapter(AbstractGatewayAdapter):
    """
    Adapter mock per test e sviluppo senza gateway reale.

    Uso nei test::

        adapter = MockGatewayAdapter()
        await adapter.connect()
        await adapter.publish(event)
        assert len(adapter.published_events) == 1
        assert adapter.published_events[0].id == event.id
    """

    def __init__(
        self,
        mode: MockMode = "normal",
        delay_seconds: float = 0.0,
    ) -> None:
        self._mode = mode
        self._delay = delay_seconds
        self._status = GatewayStatus.DISCONNECTED
        self.published_events: List[IDSEvent] = []
        self._publish_ok: int = 0
        self._publish_fail: int = 0

    async def connect(self) -> None:
        if self._mode == "failing":
            self._status = GatewayStatus.ERROR
            logger.debug("MockGatewayAdapter: simulated connection failure")
        else:
            self._status = GatewayStatus.CONNECTED
            logger.debug(f"MockGatewayAdapter connected (mode={self._mode})")

    async def disconnect(self) -> None:
        self._status = GatewayStatus.DISCONNECTED
        logger.debug("MockGatewayAdapter disconnected")

    async def publish(self, event: IDSEvent) -> bool:
        if self._mode == "failing":
            self._publish_fail += 1
            logger.debug(f"MockGatewayAdapter: simulated publish failure for {event.id}")
            return False

        if self._delay > 0:
            await asyncio.sleep(self._delay)

        self.published_events.append(event)
        self._publish_ok += 1
        logger.debug(
            f"MockGatewayAdapter: published {event.id} "
            f"[{event.severity.value}] {event.detector_name}"
        )
        return True

    def reset(self) -> None:
        """Svuota gli eventi pubblicati (utile tra test)."""
        self.published_events.clear()
        self._publish_ok = 0
        self._publish_fail = 0

    @property
    def status(self) -> GatewayStatus:
        return self._status

    def get_stats(self) -> Dict[str, Any]:
        return {
            "status": self._status.value,
            "mode": self._mode,
            "publish_ok": self._publish_ok,
            "publish_fail": self._publish_fail,
            "events_stored": len(self.published_events),
        }
