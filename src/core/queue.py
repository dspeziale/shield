"""
AsyncEventQueue — coda asincrona con buffering, overflow protection
e supporto multi-consumer.

Flusso:
    Detectors → put_nowait_or_drop() → AsyncQueue → _drain_loop() → handlers

I consumer si registrano come DrainHandler (coroutine async) e vengono
chiamati in sequenza per ogni evento drenato. Se la coda è piena,
i nuovi eventi vengono scartati e contati in `dropped`.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import List, Optional

from src.core.event import IDSEvent

logger = logging.getLogger(__name__)

# Type alias: qualsiasi coroutine che accetta un IDSEvent
DrainHandler = Callable[[IDSEvent], Awaitable[None]]


class AsyncEventQueue:
    """
    Coda FIFO asincrona con protezione dall'overflow e multi-consumer.

    Parametri:
        max_size: dimensione massima del buffer (eventi)
        drain_interval: secondi tra i cicli di drain
    """

    def __init__(
        self,
        max_size: int = 10_000,
        drain_interval: float = 0.1,
    ) -> None:
        self._queue: asyncio.Queue[IDSEvent] = asyncio.Queue(maxsize=max_size)
        self._drain_interval = drain_interval
        self._handlers: List[DrainHandler] = []
        self._running = False
        self._drain_task: Optional[asyncio.Task] = None

        # Contatori metriche
        self.enqueued: int = 0
        self.dropped: int = 0
        self.processed: int = 0

    # ─── Consumer registration ───────────────────────────────────────────────

    def add_handler(self, handler: DrainHandler) -> None:
        """Registra un consumer che riceverà ogni evento drenato."""
        self._handlers.append(handler)
        logger.debug(f"Registered drain handler: {getattr(handler, '__name__', str(handler))}")

    def remove_handler(self, handler: DrainHandler) -> None:
        """Rimuove un consumer precedentemente registrato."""
        self._handlers.remove(handler)

    # ─── Enqueue ─────────────────────────────────────────────────────────────

    def put_nowait_or_drop(self, event: IDSEvent) -> bool:
        """
        Enqueue non-bloccante.

        Returns:
            True  — evento accodato
            False — coda piena, evento scartato
        """
        try:
            self._queue.put_nowait(event)
            self.enqueued += 1
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            logger.warning(
                "event_dropped",
                extra={
                    "detector": event.detector_name,
                    "queue_size": self._queue.qsize(),
                    "dropped_total": self.dropped,
                },
            )
            return False

    async def put(self, event: IDSEvent) -> None:
        """Enqueue asincrono — attende se la coda è piena."""
        await self._queue.put(event)
        self.enqueued += 1

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Avvia il drain loop in background."""
        if self._running:
            return
        self._running = True
        self._drain_task = asyncio.create_task(
            self._drain_loop(), name="event-queue-drain"
        )
        logger.info("AsyncEventQueue started", extra={"max_size": self._queue.maxsize})

    async def stop(self) -> None:
        """
        Ferma il drain loop e svuota la coda prima di chiudere.
        Garantisce che tutti gli eventi bufferizzati vengano processati.
        """
        self._running = False
        if self._drain_task and not self._drain_task.done():
            self._drain_task.cancel()
            try:
                await self._drain_task
            except asyncio.CancelledError:
                pass
        # Flush finale
        await self._flush_remaining()
        logger.info(
            "AsyncEventQueue stopped",
            extra={
                "enqueued": self.enqueued,
                "processed": self.processed,
                "dropped": self.dropped,
            },
        )

    # ─── Drain logic ─────────────────────────────────────────────────────────

    async def _drain_loop(self) -> None:
        """Loop principale: drena la coda ogni drain_interval secondi."""
        while self._running:
            await self._drain_batch()
            await asyncio.sleep(self._drain_interval)

    async def _drain_batch(self) -> None:
        """Svuota tutti gli eventi attualmente in coda."""
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            await self._dispatch(event)
            self._queue.task_done()
            self.processed += 1

    async def _flush_remaining(self) -> None:
        """Svuota gli eventi residui durante lo shutdown."""
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            await self._dispatch(event)
            self._queue.task_done()
            self.processed += 1

    async def _dispatch(self, event: IDSEvent) -> None:
        """Chiama tutti i consumer registrati per un evento."""
        for handler in self._handlers:
            try:
                await handler(event)
            except Exception as exc:
                logger.error(
                    "drain_handler_error",
                    extra={
                        "handler": getattr(handler, "__name__", str(handler)),
                        "event_id": event.id,
                        "error": str(exc),
                    },
                    exc_info=True,
                )

    # ─── Properties ──────────────────────────────────────────────────────────

    @property
    def depth(self) -> int:
        """Numero di eventi attualmente in coda."""
        return self._queue.qsize()

    def get_stats(self) -> dict:
        return {
            "depth": self.depth,
            "enqueued": self.enqueued,
            "processed": self.processed,
            "dropped": self.dropped,
            "running": self._running,
        }
