"""
Test per gateway adapters.
"""
from __future__ import annotations

import pytest

from src.core.event import IDSEvent, Severity, new_event
from src.gateway.base import GatewayStatus
from src.gateway.mock_adapter import MockGatewayAdapter


def make_event() -> IDSEvent:
    return new_event(
        detector_name="test_detector",
        severity=Severity.HIGH,
        source_ip="192.168.1.1",
        summary="Test event",
        tags=["test"],
    )


class TestMockGatewayAdapter:
    async def test_connect_sets_status(self):
        adapter = MockGatewayAdapter()
        assert adapter.status == GatewayStatus.DISCONNECTED
        await adapter.connect()
        assert adapter.status == GatewayStatus.CONNECTED

    async def test_disconnect_sets_status(self):
        adapter = MockGatewayAdapter()
        await adapter.connect()
        await adapter.disconnect()
        assert adapter.status == GatewayStatus.DISCONNECTED

    async def test_publish_success(self):
        adapter = MockGatewayAdapter()
        await adapter.connect()

        event = make_event()
        result = await adapter.publish(event)

        assert result is True
        assert len(adapter.published_events) == 1
        assert adapter.published_events[0].id == event.id

    async def test_publish_multiple_events(self):
        adapter = MockGatewayAdapter()
        await adapter.connect()

        events = [make_event() for _ in range(5)]
        for evt in events:
            await adapter.publish(evt)

        assert len(adapter.published_events) == 5

    async def test_failing_mode(self):
        adapter = MockGatewayAdapter(mode="failing")
        await adapter.connect()

        result = await adapter.publish(make_event())
        assert result is False
        assert len(adapter.published_events) == 0

    async def test_reset_clears_events(self):
        adapter = MockGatewayAdapter()
        await adapter.connect()
        await adapter.publish(make_event())

        adapter.reset()
        assert len(adapter.published_events) == 0
        assert adapter._publish_ok == 0

    async def test_context_manager(self):
        async with MockGatewayAdapter() as adapter:
            assert adapter.status == GatewayStatus.CONNECTED
            await adapter.publish(make_event())
        assert adapter.status == GatewayStatus.DISCONNECTED

    async def test_get_stats(self):
        adapter = MockGatewayAdapter()
        await adapter.connect()
        await adapter.publish(make_event())

        stats = adapter.get_stats()
        assert stats["publish_ok"] == 1
        assert stats["publish_fail"] == 0
        assert stats["status"] == "connected"

    async def test_event_serialization(self):
        """Verifica che gli eventi pubblicati siano correttamente serializzabili."""
        adapter = MockGatewayAdapter()
        await adapter.connect()

        event = new_event(
            detector_name="port_scan_detector",
            severity=Severity.CRITICAL,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.254",
            summary="Critical scan",
            raw_data={"ports": [22, 80, 443]},
            tags=["scan", "critical"],
        )
        await adapter.publish(event)

        stored = adapter.published_events[0]
        json_data = stored.to_json_dict()

        assert json_data["severity"] == "critical"
        assert json_data["detector_name"] == "port_scan_detector"
        assert json_data["raw_data"]["ports"] == [22, 80, 443]
        assert "scan" in json_data["tags"]
        assert isinstance(json_data["timestamp"], str)
