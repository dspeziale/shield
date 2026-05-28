"""
Traffic Volume Detector.

Rileva traffico anomalo per volume monitorando pacchetti al secondo (PPS)
e byte al secondo (BPS) per singolo IP sorgente in una finestra scorrevole.

Algoritmo:
    Per ogni pacchetto IP:
    1. Registra (timestamp, byte_len) per l'IP sorgente
    2. Prune delle entry fuori dalla finestra
    3. Calcola pps e bps nella finestra
    4. Se pps >= threshold_pps OR bps >= threshold_bps → alert
    5. Anti-spam: un alert per IP ogni window_seconds
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
class TrafficVolumeDetector(BaseDetector):
    """
    Detector per traffico anomalo per volume.

    Configurazione::

        detectors:
          traffic_volume:
            enabled: true
            window_seconds: 60
            threshold_pps: 5000
            threshold_bps: 10000000
            severity: medium
    """

    detector_name = "traffic_volume_detector"

    def __init__(self, config: Dict[str, Any], emitter: EventEmitter) -> None:
        super().__init__(config, emitter)
        self._window = float(config.get("window_seconds", 60))
        self._threshold_pps = int(config.get("threshold_pps", 5000))
        self._threshold_bps = int(config.get("threshold_bps", 10_000_000))
        self._severity = Severity(config.get("severity", "medium"))

        # ip_src → deque di (monotonic_ts, pkt_bytes)
        self._tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        # ip_src → timestamp ultimo alert
        self._alerted_at: Dict[str, float] = {}
        self._alerts_fired: int = 0

    async def process_packet(self, pkt: Any) -> None:
        """Traccia volume di traffico per IP sorgente."""
        try:
            from scapy.layers.inet import IP
        except ImportError:
            logger.debug("scapy not available — traffic_volume_detector passive")
            return

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip: str = ip.src
        pkt_len: int = len(pkt)
        now = time.monotonic()

        window = self._tracker[src_ip]
        window.append((now, pkt_len))

        # Prune old entries
        cutoff = now - self._window
        while window and window[0][0] < cutoff:
            window.popleft()

        # Calcola metriche nella finestra
        packet_count = len(window)
        byte_count = sum(b for _, b in window)

        # Calcola rate effettivo basato sulla finestra reale
        if len(window) >= 2:
            actual_window = window[-1][0] - window[0][0]
            if actual_window > 0:
                pps = packet_count / actual_window
                bps = byte_count / actual_window
            else:
                return
        else:
            return

        if pps >= self._threshold_pps or bps >= self._threshold_bps:
            last = self._alerted_at.get(src_ip, 0.0)
            if now - last >= self._window:
                self._alerted_at[src_ip] = now
                self._alerts_fired += 1

                reason = []
                if pps >= self._threshold_pps:
                    reason.append(f"pps={pps:.0f} (threshold={self._threshold_pps})")
                if bps >= self._threshold_bps:
                    reason.append(f"bps={bps:.0f} ({bps/1e6:.1f} Mbit/s)")

                await self.emit(
                    new_event(
                        detector_name=self.detector_name,
                        severity=self._severity,
                        source_ip=src_ip,
                        summary=(
                            f"Anomalous traffic from {src_ip}: {', '.join(reason)}"
                        ),
                        raw_data={
                            "pps": round(pps, 2),
                            "bps": round(bps, 2),
                            "mbps": round(bps / 1e6, 3),
                            "packets_in_window": packet_count,
                            "bytes_in_window": byte_count,
                            "window_seconds": self._window,
                            "threshold_pps": self._threshold_pps,
                            "threshold_bps": self._threshold_bps,
                        },
                        tags=["network", "traffic", "anomaly", "volume"],
                    )
                )

    async def process_arp_table(self, table: Dict[str, str]) -> None:
        pass

    def get_status(self) -> Dict[str, Any]:
        return {
            **super().get_status(),
            "tracked_ips": len(self._tracker),
            "alerts_fired": self._alerts_fired,
            "window_seconds": self._window,
            "threshold_pps": self._threshold_pps,
            "threshold_bps": self._threshold_bps,
        }
