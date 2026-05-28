"""
Test per AsyncEventQueue.
"""
from __future__ import annotations

import asyncio
from typing import List

import pytest

from src.core.event import IDSEvent, Severity, new_event
from src.core.queue import AsyncEventQueue


def make_event(source_ip: str = "1.2.3.4") -> IDSEvent:
    return new_event("test", Severity.LOW, source_ip, "test event")


class TestAsyncEventQueue:
    async def test_basic_enqueue_and_drain(self):
        received: List[IDSEvent] = []

        async def handler(event: IDSEvent) -> None:
            received.append(event)

        q = AsyncEventQueue(max_size=10, drain_interval=0.01)
        q.add_handler(handler)
        await q.start()

        evt = make_event()
        q.put_nowait_or_drop(evt)
        await asyncio.sleep(0.05)

        assert len(received) == 1
        assert received[0].id == evt.id

        await q.stop()

    async def test_overflow_drops_event(self):
        q = AsyncEventQueue(max_size=2, drain_interval=100)  # No auto-drain

        # Riempie la coda
        e1, e2, e3 = make_event("1.1.1.1"), make_event("2.2.2.2"), make_event("3.3.3.3")
        r1 = q.put_nowait_or_drop(e1)
        r2 = q.put_nowait_or_drop(e2)
        r3 = q.put_nowait_or_drop(e3)  # Deve essere droppato

        assert r1 is True
        assert r2 is True
        assert r3 is False
        assert q.dropped == 1
        assert q.enqueued == 2

    async def test_depth_property(self):
        q = AsyncEventQueue(max_size=100, drain_interval=100)
        assert q.depth == 0
        q.put_nowait_or_drop(make_event())
        assert q.depth == 1

    async def test_multiple_handlers(self):
        received_a: List[IDSEvent] = []
        received_b: List[IDSEvent] = []

        async def handler_a(event: IDSEvent) -> None:
            received_a.append(event)

        async def handler_b(event: IDSEvent) -> None:
            received_b.append(event)

        q = AsyncEventQueue(max_size=10, drain_interval=0.01)
        q.add_handler(handler_a)
        q.add_handler(handler_b)
        await q.start()

        q.put_nowait_or_drop(make_event())
        await asyncio.sleep(0.05)

        assert len(received_a) == 1
        assert len(received_b) == 1

        await q.stop()

    async def test_handler_error_does_not_break_queue(self):
        """Un handler che solleva eccezione non deve bloccare gli altri."""
        received: List[IDSEvent] = []

        async def bad_handler(event: IDSEvent) -> None:
            raise RuntimeError("simulated error")

        async def good_handler(event: IDSEvent) -> None:
            received.append(event)

        q = AsyncEventQueue(max_size=10, drain_interval=0.01)
        q.add_handler(bad_handler)
        q.add_handler(good_handler)
        await q.start()

        q.put_nowait_or_drop(make_event())
        await asyncio.sleep(0.05)

        assert len(received) == 1  # good_handler ha ricevuto l'evento

        await q.stop()

    async def test_stop_flushes_remaining(self):
        """Stop deve drenare gli eventi residui prima di chiudere."""
        received: List[IDSEvent] = []

        async def handler(event: IDSEvent) -> None:
            received.append(event)

        q = AsyncEventQueue(max_size=10, drain_interval=999)  # drain lento
        q.add_handler(handler)
        # Non avvio il drain loop
        await q.start()

        for i in range(5):
            q.put_nowait_or_drop(make_event(f"10.0.0.{i}"))

        await q.stop()

        assert len(received) == 5

    async def test_get_stats(self):
        q = AsyncEventQueue(max_size=5, drain_interval=100)
        q.put_nowait_or_drop(make_event())
        stats = q.get_stats()

        assert stats["depth"] == 1
        assert stats["enqueued"] == 1
        assert stats["dropped"] == 0
