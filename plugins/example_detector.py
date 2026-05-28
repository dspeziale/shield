"""
ExampleDetector — template per plugin detector custom.

Copia questo file, rinominalo (es. dns_tunnel_detector.py)
e implementa la logica di detection nella classe.

Questo esempio rileva pacchetti ICMP e genera un evento LOW
ogni N pacchetti (solo per dimostrare il pattern).
"""
from __future__ import annotations

import time
from typing import Any, Dict

from src.core.event import Severity, new_event
from src.detectors.base import BaseDetector, EventEmitter, register_detector


@register_detector
class ExampleDetector(BaseDetector):
    """
    Detector di esempio — conta pacchetti ICMP e genera un alert periodico.

    NON usare in produzione — è solo un template dimostrativo.

    Configurazione nel config.yaml (opzionale — usa default se assente)::

        # Nessuna sezione specifica: il plugin usa i default.
        # Per personalizzare, aggiungere alla sezione detectors:
        # detectors:
        #   example_detector:
        #     enabled: true
        #     alert_every: 100
    """

    detector_name = "example_detector"

    def __init__(self, config: Dict[str, Any], emitter: EventEmitter) -> None:
        super().__init__(config, emitter)
        self._alert_every = int(config.get("alert_every", 100))
        self._icmp_count: int = 0
        self._last_alert: float = 0.0

    async def process_packet(self, pkt: Any) -> None:
        """Conta pacchetti ICMP e genera un evento ogni N pacchetti."""
        try:
            from scapy.layers.inet import ICMP, IP
        except ImportError:
            return

        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            return

        self._icmp_count += 1
        ip = pkt[IP]

        if self._icmp_count % self._alert_every == 0:
            await self.emit(
                new_event(
                    detector_name=self.detector_name,
                    severity=Severity.LOW,
                    source_ip=ip.src,
                    destination_ip=ip.dst,
                    summary=f"[EXAMPLE] {self._icmp_count} ICMP packets counted",
                    raw_data={
                        "icmp_total": self._icmp_count,
                        "alert_every": self._alert_every,
                    },
                    tags=["example", "icmp", "demo"],
                )
            )

    def get_status(self) -> Dict[str, Any]:
        return {
            **super().get_status(),
            "icmp_packets_seen": self._icmp_count,
            "alert_every": self._alert_every,
        }
