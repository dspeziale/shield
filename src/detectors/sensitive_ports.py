"""
Sensitive Ports Detector.

Rileva tentativi ripetuti verso porte sensibili (SSH, RDP, SMB, DB, ecc.)
da un singolo IP sorgente in una finestra scorrevole.

Porte sensibili predefinite:
    22   — SSH
    23   — Telnet
    135  — RPC
    139  — NetBIOS
    445  — SMB
    1433 — SQL Server
    3306 — MySQL
    3389 — RDP
    5432 — PostgreSQL
    5900 — VNC

Algoritmo:
    Per ogni pacchetto TCP verso una porta sensibile:
    1. Registra (timestamp, dst_port) per l'IP sorgente
    2. Prune delle entry fuori dalla finestra
    3. Se tentativi >= min_attempts → alert
    4. Anti-spam: un alert per IP per finestra
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Set, Tuple

from src.core.event import IDSEvent, Severity, new_event
from src.detectors.base import BaseDetector, EventEmitter, register_detector

logger = logging.getLogger(__name__)

# Porte predefinite con descrizione human-readable
DEFAULT_SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
}


@register_detector
class SensitivePortsDetector(BaseDetector):
    """
    Detector per tentativi verso porte sensibili.

    Configurazione::

        detectors:
          sensitive_ports:
            enabled: true
            ports: [22, 23, 3389, 5900, 445, 135, 139, 1433, 3306, 5432]
            window_seconds: 60
            min_attempts: 5
            severity: high
    """

    detector_name = "sensitive_ports_detector"

    def __init__(self, config: Dict[str, Any], emitter: EventEmitter) -> None:
        super().__init__(config, emitter)
        self._window = float(config.get("window_seconds", 60))
        self._min_attempts = int(config.get("min_attempts", 5))
        self._severity = Severity(config.get("severity", "high"))

        # Costruisce set di porte monitorare
        raw_ports = config.get("ports", list(DEFAULT_SENSITIVE_PORTS.keys()))
        self._sensitive_ports: Set[int] = set(raw_ports)

        # ip_src → deque di (timestamp, dst_port)
        self._tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        # ip_src → timestamp ultimo alert
        self._alerted_at: Dict[str, float] = {}
        self._alerts_fired: int = 0

    async def process_packet(self, pkt: Any) -> None:
        """Rileva tentativi verso porte sensibili."""
        try:
            from scapy.layers.inet import IP, TCP
        except ImportError:
            logger.debug("scapy not available — sensitive_ports_detector passive")
            return

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        dst_port = int(tcp.dport)

        # Filtra solo le porte sensibili
        if dst_port not in self._sensitive_ports:
            return

        src_ip: str = ip.src
        dst_ip: str = ip.dst
        now = time.monotonic()

        window = self._tracker[src_ip]
        window.append((now, dst_port))

        # Prune
        cutoff = now - self._window
        while window and window[0][0] < cutoff:
            window.popleft()

        attempt_count = len(window)
        distinct_ports = {p for _, p in window}

        if attempt_count >= self._min_attempts:
            last = self._alerted_at.get(src_ip, 0.0)
            if now - last >= self._window:
                self._alerted_at[src_ip] = now
                self._alerts_fired += 1

                # Descrizioni leggibili delle porte
                port_descriptions = {
                    p: DEFAULT_SENSITIVE_PORTS.get(p, str(p))
                    for p in distinct_ports
                }

                await self.emit(
                    new_event(
                        detector_name=self.detector_name,
                        severity=self._severity,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        summary=(
                            f"Multiple attempts to sensitive ports from {src_ip}: "
                            f"{attempt_count} attempts in {self._window:.0f}s "
                            f"(ports: {', '.join(str(p) for p in sorted(distinct_ports))})"
                        ),
                        raw_data={
                            "attempt_count": attempt_count,
                            "distinct_ports": sorted(distinct_ports),
                            "port_descriptions": port_descriptions,
                            "window_seconds": self._window,
                            "threshold": self._min_attempts,
                        },
                        tags=["network", "brute-force", "sensitive-port", "scan"],
                    )
                )

    async def process_arp_table(self, table: Dict[str, str]) -> None:
        pass

    def get_status(self) -> Dict[str, Any]:
        return {
            **super().get_status(),
            "monitored_ports": sorted(self._sensitive_ports),
            "tracked_ips": len(self._tracker),
            "alerted_ips": len(self._alerted_at),
            "alerts_fired": self._alerts_fired,
            "window_seconds": self._window,
            "min_attempts": self._min_attempts,
        }
