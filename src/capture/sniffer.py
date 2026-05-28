"""
PacketSniffer — capture di pacchetti di rete tramite scapy.

Scapy non è nativo-async, quindi lo eseguiamo in un thread dedicato
e facciamo bridge verso asyncio tramite `loop.call_soon_threadsafe()`.

Funzionamento:
    1. Il thread sniffer chiama scapy.sniff() in modo bloccante
    2. Per ogni pacchetto catturato: chiama callback nel thread
    3. Il callback usa call_soon_threadsafe per inserire il pacchetto
       nella asyncio queue del motore principale
    4. Il graceful stop usa threading.Event per terminare il thread

Auto-detect interfaccia:
    Se interface="auto", seleziona la prima interfaccia non-loopback
    con traffico attivo. Su Windows richiede Npcap installato.

Mock mode:
    Se use_mock=True, genera pacchetti sintetici periodicamente
    (utile per sviluppo/test senza root/Npcap).
"""
from __future__ import annotations

import asyncio
import logging
import random
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Type alias per callback pacchetto
PacketCallback = Callable[[Any], None]


def _detect_interface() -> str:
    """
    Auto-detect della prima interfaccia di rete non-loopback.

    Returns:
        Nome dell'interfaccia (es. "eth0", "Wi-Fi") o "eth0" come fallback.
    """
    try:
        import scapy.config
        from scapy.arch import get_if_list

        ifaces = [i for i in get_if_list() if "lo" not in i.lower()]
        if ifaces:
            logger.info(f"Auto-detected network interface: {ifaces[0]}")
            return ifaces[0]
    except Exception as exc:
        logger.warning(f"Interface auto-detect failed: {exc}")

    fallback = "Wi-Fi" if sys.platform == "win32" else "eth0"
    logger.info(f"Using fallback interface: {fallback}")
    return fallback


class PacketSniffer:
    """
    Wrapper async attorno a scapy.sniff() con bridge verso asyncio.

    Parametri:
        interface:    nome interfaccia di rete ("auto" per auto-detect)
        bpf_filter:   filtro BPF scapy (es. "not port 22")
        promiscuous:  abilita modalità promiscua
        loop:         event loop asyncio su cui fare bridge
        use_mock:     se True usa generatore sintetico (no root/Npcap)
    """

    def __init__(
        self,
        interface: str = "auto",
        bpf_filter: str = "",
        promiscuous: bool = True,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        use_mock: bool = False,
    ) -> None:
        self._interface = _detect_interface() if interface == "auto" else interface
        self._bpf_filter = bpf_filter
        self._promiscuous = promiscuous
        self._loop = loop or asyncio.get_event_loop()
        self._use_mock = use_mock

        self._stop_event = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sniffer")
        self._callbacks: list[PacketCallback] = []
        self._running = False

        # Statistiche
        self.packets_captured: int = 0

    def add_callback(self, cb: PacketCallback) -> None:
        """Registra un callback che riceve ogni pacchetto (chiamato nel loop asyncio)."""
        self._callbacks.append(cb)

    async def start(self) -> None:
        """Avvia il thread di sniffing in background."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        if self._use_mock:
            logger.info("PacketSniffer starting in MOCK mode (synthetic packets)")
            self._executor.submit(self._mock_sniff_loop)
        else:
            logger.info(
                f"PacketSniffer starting on interface '{self._interface}' "
                f"(filter='{self._bpf_filter}', promisc={self._promiscuous})"
            )
            self._executor.submit(self._sniff_loop)

    async def stop(self) -> None:
        """Segnala lo stop al thread di sniffing e attende la terminazione."""
        self._running = False
        self._stop_event.set()
        # Breve attesa per permettere al thread di uscire pulitamente
        await asyncio.sleep(0.5)
        self._executor.shutdown(wait=True, cancel_futures=True)
        logger.info(f"PacketSniffer stopped. Packets captured: {self.packets_captured}")

    def _sniff_loop(self) -> None:
        """Loop di sniffing reale (eseguito nel thread worker)."""
        try:
            from scapy.sendrecv import sniff as scapy_sniff
        except ImportError:
            logger.error(
                "scapy not installed. Install with: pip install scapy\n"
                "On Windows, also install Npcap from https://npcap.com"
            )
            return

        # ── Fix Windows/Npcap: registra Ether per DLT_EN10MB (linktype=1) ──────
        # Su Windows con Npcap, la Wi-Fi viene catturata con frame Ethernet (DLT=1).
        # Scapy può non trovare il layer se scapy.layers.l2 non è ancora importato
        # al momento dell'apertura del socket → warning "Unable to guess datalink type".
        # L'import esplicito forza la registrazione in conf.l2types.
        if sys.platform == "win32":
            try:
                import scapy.layers.l2  # noqa: F401 — side-effect: registra Ether/DLT_EN10MB
                import scapy.layers.inet  # noqa: F401 — registra IP/TCP/UDP
                from scapy.config import conf as scapy_conf
                from scapy.layers.l2 import Ether

                # Registrazione esplicita come safety-net
                scapy_conf.l2types.register(1, Ether)      # DLT_EN10MB
                scapy_conf.l2types.register_num2layer(1, Ether)
                scapy_conf.use_npcap = True
                logger.debug("Scapy Npcap layer types registered (Ether/DLT_EN10MB)")
            except Exception as exc:
                logger.warning(f"Scapy layer pre-registration failed (non-fatal): {exc}")

        logger.debug(f"Sniffer thread started on {self._interface}")

        def packet_handler(pkt: Any) -> None:
            if self._stop_event.is_set():
                return
            self.packets_captured += 1
            # Bridge: dispatch al loop asyncio da thread sincrono
            self._loop.call_soon_threadsafe(self._dispatch_packet, pkt)

        try:
            scapy_sniff(
                iface=self._interface,
                filter=self._bpf_filter or None,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
                promisc=self._promiscuous,
            )
        except Exception as exc:
            logger.error(f"Sniffer error: {exc}", exc_info=True)

    def _mock_sniff_loop(self) -> None:
        """
        Generatore di pacchetti sintetici per sviluppo/test.

        Genera pacchetti scapy fittizi a ~10 pkt/s senza richiedere
        privilegi di rete o Npcap.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.l2 import ARP, Ether
            from scapy.packet import Packet
        except ImportError:
            logger.error("scapy not available for mock mode")
            return

        logger.debug("Mock sniffer thread started")

        local_ips = [f"192.168.1.{i}" for i in range(2, 20)]
        random.seed(42)

        while not self._stop_event.is_set():
            # Genera pacchetto casuale
            src = random.choice(local_ips)
            dst = random.choice(local_ips)
            pkt_type = random.choices(
                ["tcp", "udp", "arp"], weights=[70, 20, 10]
            )[0]

            if pkt_type == "tcp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst)
                    / TCP(dport=random.choice([22, 80, 443, 8080, 3389, 445]))
                )
            elif pkt_type == "udp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst)
                    / UDP(dport=random.choice([53, 67, 123, 161]))
                )
            else:
                pkt = (
                    Ether()
                    / ARP(
                        psrc=src,
                        pdst=dst,
                        hwsrc="aa:bb:cc:dd:ee:01",
                    )
                )

            self.packets_captured += 1
            self._loop.call_soon_threadsafe(self._dispatch_packet, pkt)
            time.sleep(0.1)  # ~10 pkt/s

    def _dispatch_packet(self, pkt: Any) -> None:
        """Chiama tutti i callback registrati con il pacchetto (nel loop asyncio)."""
        for cb in self._callbacks:
            try:
                cb(pkt)
            except Exception as exc:
                logger.error(f"Packet callback error: {exc}", exc_info=True)
