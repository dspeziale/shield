"""
Fixtures condivise per l'intera suite di test.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.config import AppConfig
from src.core.event import IDSEvent, Severity, new_event
from src.gateway.mock_adapter import MockGatewayAdapter


# ─── Config fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def default_config() -> AppConfig:
    """Configurazione di default per i test."""
    return AppConfig.default()


# ─── Event fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def sample_event() -> IDSEvent:
    """Evento IDS di esempio."""
    return new_event(
        detector_name="test_detector",
        severity=Severity.HIGH,
        source_ip="192.168.1.50",
        destination_ip="192.168.1.1",
        summary="Test event",
        raw_data={"test": True},
        tags=["test", "network"],
    )


@pytest.fixture
def event_factory():
    """Factory per creare eventi con parametri personalizzati."""
    def _make(
        detector_name: str = "test_detector",
        severity: Severity = Severity.MEDIUM,
        source_ip: str = "192.168.1.1",
        **kwargs,
    ) -> IDSEvent:
        return new_event(
            detector_name=detector_name,
            severity=severity,
            source_ip=source_ip,
            summary=f"Event from {source_ip}",
            **kwargs,
        )
    return _make


# ─── Gateway fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
async def mock_gateway() -> MockGatewayAdapter:
    """Mock gateway connesso."""
    adapter = MockGatewayAdapter()
    await adapter.connect()
    return adapter


@pytest.fixture
async def failing_gateway() -> MockGatewayAdapter:
    """Mock gateway che fallisce sempre."""
    adapter = MockGatewayAdapter(mode="failing")
    await adapter.connect()
    return adapter


# ─── Emitter fixture ──────────────────────────────────────────────────────────

@pytest.fixture
def collected_events() -> List[IDSEvent]:
    """Lista che raccoglie gli eventi emessi."""
    return []


@pytest.fixture
def async_emitter(collected_events: List[IDSEvent]):
    """Emitter async che raccoglie eventi nella lista."""
    async def _emitter(event: IDSEvent) -> None:
        collected_events.append(event)
    return _emitter


# ─── Scapy mock helpers ───────────────────────────────────────────────────────

def make_tcp_packet(
    src: str = "192.168.1.10",
    dst: str = "192.168.1.1",
    dport: int = 80,
    sport: int = 12345,
    length: int = 64,
) -> MagicMock:
    """Crea un mock di pacchetto scapy TCP."""
    pkt = MagicMock()

    ip = MagicMock()
    ip.src = src
    ip.dst = dst

    tcp = MagicMock()
    tcp.dport = dport
    tcp.sport = sport

    # Configura haslayer
    def haslayer(layer):
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.l2 import ARP
            return layer in (IP, TCP)
        except ImportError:
            return layer.__name__ in ("IP", "TCP")

    pkt.haslayer = haslayer
    pkt.__getitem__ = lambda self, layer: ip if getattr(layer, '__name__', str(layer)) == 'IP' else tcp
    pkt.__len__ = lambda self: length

    # Versione semplificata: attributi diretti
    pkt._ip = ip
    pkt._tcp = tcp
    return pkt


def make_arp_packet(
    psrc: str = "192.168.1.10",
    hwsrc: str = "aa:bb:cc:dd:ee:01",
    pdst: str = "192.168.1.1",
    op: int = 1,
) -> MagicMock:
    """Crea un mock di pacchetto scapy ARP."""
    pkt = MagicMock()

    arp = MagicMock()
    arp.psrc = psrc
    arp.hwsrc = hwsrc
    arp.pdst = pdst
    arp.op = op

    def haslayer(layer):
        try:
            from scapy.layers.l2 import ARP
            return layer == ARP
        except ImportError:
            return getattr(layer, '__name__', str(layer)) == 'ARP'

    pkt.haslayer = haslayer
    pkt._arp = arp
    return pkt
