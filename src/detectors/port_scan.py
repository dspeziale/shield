"""
Port Scan Detector.

Rileva scansioni di porte tracciando il numero di porte distinte
contattate da un singolo IP sorgente in una finestra scorrevole.

Algoritmo:
    Per ogni pacchetto TCP/UDP:
    1. Registra (timestamp, dst_port) per l'IP sorgente
    2. Prune delle entry più vecchie di window_seconds
    3. Se le porte distinte >= min_ports → emetti alert
    4. Anti-spam: un solo alert per IP per finestra temporale
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Tuple

from src.core.event import IDSEvent, Severity, new_event
from src.detectors.base import BaseDetector, EventEmitter, register_detector

logger = logging.getLogger(__name__)


@register_detector
class PortScanDetector(BaseDetector):
    """
    Detector per scansioni di porte.

    Configurazione::

        detectors:
          port_scan:
            enabled: true
            window_seconds: 10
            min_ports: 10
            severity: high
    """

    detector_name = "port_scan_detector"

    def __init__(self, config: Dict[str, Any], emitter: EventEmitter) -> None:
        super().__init__(config, emitter)
        self._window = float(config.get("window_seconds", 10))
        self._min_ports = int(config.get("min_ports", 10))
        self._severity = Severity(config.get("severity", "high"))

        # ip_src → deque di (monotonic_ts, dst_port)
        self._tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        # ip_src → timestamp dell'ultimo alert (anti-spam)
        self._alerted_at: Dict[str, float] = {}
        # Contatori
        self._alerts_fired: int = 0

    async def process_packet(self, pkt: Any) -> None:
        """Analizza pacchetti IP/TCP e IP/UDP per rilevare port scan."""
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError:
            logger.debug("scapy not available — port_scan_detector passive")
            return

        if not pkt.haslayer(IP):
            return

        # Considera solo TCP e UDP
        if pkt.haslayer(TCP):
            dst_port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            dst_port = int(pkt["UDP"].dport)
        else:
            return

        ip = pkt[IP]
        src_ip: str = ip.src
        dst_ip: str = ip.dst
        now = time.monotonic()

        window = self._tracker[src_ip]
        window.append((now, dst_port))

        # Prune entries outside the window
        cutoff = now - self._window
        while window and window[0][0] < cutoff:
            window.popleft()

        # Conta porte distinte nella finestra
        distinct_ports = {port for _, port in window}
        port_count = len(distinct_ports)

        if port_count >= self._min_ports:
            # Anti-spam: un alert per IP per window
            last = self._alerted_at.get(src_ip, 0.0)
            if now - last >= self._window:
                self._alerted_at[src_ip] = now
                self._alerts_fired += 1
                await self.emit(
                    new_event(
                        detector_name=self.detector_name,
                        severity=self._severity,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        summary=(
                            f"Possible port scan: {port_count} distinct ports "
                            f"in {self._window:.0f}s from {src_ip}"
                        ),
                        raw_data={
                            "distinct_ports": sorted(distinct_ports),
                            "port_count": port_count,
                            "window_seconds": self._window,
                            "destination_ip": dst_ip,
                        },
                        tags=["network", "scan", "port-scan"],
                    )
                )

    async def process_arp_table(self, table: Dict[str, str]) -> None:
        pass  # Non rilevante per questo detector

    def get_status(self) -> Dict[str, Any]:
        return {
            **super().get_status(),
            "tracked_ips": len(self._tracker),
            "alerted_ips": len(self._alerted_at),
            "alerts_fired": self._alerts_fired,
            "window_seconds": self._window,
            "min_ports_threshold": self._min_ports,
        }
