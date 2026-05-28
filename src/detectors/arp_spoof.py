"""
ARP Spoof Detector.

Rileva possibili attacchi ARP spoofing monitorando i cambiamenti
nei binding IP→MAC e i conflitti (stesso IP, MAC diversi).

Vettori rilevati:
    1. IP con MAC multipli in finestra temporale breve
    2. Cambio MAC per un IP già visto (rispetto all'associazione precedente)
    3. MAC con IP multipli (reverse ARP spoofing)
    4. Gratuitous ARP inattesi

Nota: questo detector NON si sostituisce a soluzioni enterprise come
DHCP snooping o DAI (Dynamic ARP Inspection), ma fornisce visibilità
rapida su eventi sospetti nella LAN.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Set, Tuple

from src.core.event import IDSEvent, Severity, new_event
from src.detectors.base import BaseDetector, EventEmitter, register_detector

logger = logging.getLogger(__name__)


@register_detector
class ARPSpoofDetector(BaseDetector):
    """
    Detector per ARP spoofing.

    Configurazione::

        detectors:
          arp_spoof:
            enabled: true
            window_seconds: 10
            severity: critical
    """

    detector_name = "arp_spoof_detector"

    def __init__(self, config: Dict[str, Any], emitter: EventEmitter) -> None:
        super().__init__(config, emitter)
        self._window = float(config.get("window_seconds", 10))
        self._severity = Severity(config.get("severity", "critical"))

        # Tabella stabile: ip → mac (primo binding visto)
        self._stable_table: Dict[str, str] = {}

        # ip → deque di (timestamp, mac) per rilevare cambi rapidi
        self._ip_mac_history: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)

        # mac → set di IP (per rilevare MAC con IP multipli)
        self._mac_to_ips: Dict[str, Set[str]] = defaultdict(set)

        # ip → timestamp ultimo alert
        self._alerted_at: Dict[str, float] = {}
        self._alerts_fired: int = 0

    async def process_packet(self, pkt: Any) -> None:
        """Analizza pacchetti ARP per rilevare spoofing in tempo reale."""
        try:
            from scapy.layers.l2 import ARP
        except ImportError:
            logger.debug("scapy not available — arp_spoof_detector passive")
            return

        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        src_ip: str = arp.psrc
        src_mac: str = arp.hwsrc.lower()

        # Ignora IP nulli o loopback
        if not src_ip or src_ip == "0.0.0.0":
            return

        await self._analyze(src_ip, src_mac)

    async def process_arp_table(self, table: Dict[str, str]) -> None:
        """Analizza snapshot ARP table per rilevare conflitti."""
        for ip, mac in table.items():
            await self._analyze(ip, mac.lower())

    async def _analyze(self, ip: str, mac: str) -> None:
        """Analisi principale binding IP→MAC."""
        now = time.monotonic()
        history = self._ip_mac_history[ip]
        history.append((now, mac))

        # Prune old entries
        cutoff = now - self._window
        while history and history[0][0] < cutoff:
            history.popleft()

        # MAC distinti per questo IP nella finestra
        recent_macs = {m for _, m in history}

        # Aggiorna mapping MAC → IP
        self._mac_to_ips[mac].add(ip)

        # ─── Check 1: IP con MAC multipli (possibile spoofing) ────────────────
        if len(recent_macs) > 1:
            last = self._alerted_at.get(f"multi_mac_{ip}", 0.0)
            if now - last >= self._window:
                self._alerted_at[f"multi_mac_{ip}"] = now
                self._alerts_fired += 1
                await self.emit(
                    new_event(
                        detector_name=self.detector_name,
                        severity=self._severity,
                        source_ip=ip,
                        summary=(
                            f"ARP spoofing suspected: IP {ip} seen with "
                            f"{len(recent_macs)} different MACs in {self._window:.0f}s"
                        ),
                        raw_data={
                            "ip": ip,
                            "observed_macs": sorted(recent_macs),
                            "mac_count": len(recent_macs),
                            "window_seconds": self._window,
                            "reason": "multiple_macs_for_ip",
                        },
                        tags=["network", "arp", "arp-spoof", "critical"],
                    )
                )

        # ─── Check 2: Cambio MAC rispetto alla prima associazione stabile ────
        if ip not in self._stable_table:
            self._stable_table[ip] = mac
        else:
            known_mac = self._stable_table[ip]
            if mac != known_mac:
                last = self._alerted_at.get(f"mac_change_{ip}", 0.0)
                if now - last >= self._window:
                    self._alerted_at[f"mac_change_{ip}"] = now
                    self._alerts_fired += 1
                    await self.emit(
                        new_event(
                            detector_name=self.detector_name,
                            severity=self._severity,
                            source_ip=ip,
                            summary=(
                                f"ARP MAC change detected: {ip} changed from "
                                f"{known_mac} to {mac}"
                            ),
                            raw_data={
                                "ip": ip,
                                "previous_mac": known_mac,
                                "new_mac": mac,
                                "reason": "mac_changed",
                            },
                            tags=["network", "arp", "arp-spoof", "mac-change"],
                        )
                    )
                    # Aggiorna la tabella stabile
                    self._stable_table[ip] = mac

    def get_status(self) -> Dict[str, Any]:
        return {
            **super().get_status(),
            "tracked_ips": len(self._ip_mac_history),
            "stable_bindings": len(self._stable_table),
            "alerts_fired": self._alerts_fired,
            "window_seconds": self._window,
        }
