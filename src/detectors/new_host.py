"""
New Host Detector.

Rileva host nuovi o inattesi sulla LAN confrontando la ARP table
corrente con la whitelist gestita da WhitelistManager.

Logica:
    1. Riceve un riferimento a WhitelistManager (iniettato dall'engine)
    2. Per ogni ARP packet / ARP table snapshot:
       - IP non in whitelist → alert NEW_IP (una sola volta per sessione)
       - IP in whitelist con MAC diverso da quello atteso → alert MAC_MISMATCH
    3. clear_ip_alerts(ip) permette di azzerare lo stato di alert per un IP
       (usato quando l'IP viene aggiunto alla whitelist via API)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Set

from src.core.event import IDSEvent, Severity, new_event
from src.core.whitelist import WhitelistManager
from src.detectors.base import BaseDetector, EventEmitter, register_detector

logger = logging.getLogger(__name__)


@register_detector
class NewHostDetector(BaseDetector):
    """
    Detector per nuovi host sulla LAN.

    Riceve un WhitelistManager dal motore IDS. Se non è fornito, carica
    direttamente il file known_hosts_file (modalità legacy, solo lettura).

    Configurazione::

        detectors:
          new_host:
            enabled: true
            known_hosts_file: "config/known_hosts.yaml"
            severity: medium
    """

    detector_name = "new_host_detector"

    def __init__(
        self,
        config: Dict[str, Any],
        emitter: EventEmitter,
        whitelist_manager: Optional[WhitelistManager] = None,
    ) -> None:
        super().__init__(config, emitter)
        self._known_hosts_file = config.get("known_hosts_file", "config/known_hosts.yaml")
        self._severity = Severity(config.get("severity", "medium"))

        # WhitelistManager iniettato dall'engine (preferred)
        self._whitelist: Optional[WhitelistManager] = whitelist_manager

        # Deduplicazione in-sessione (azzerabili via clear_ip_alerts)
        self._seen_ips: Set[str] = set()
        self._alerted_ips: Set[str] = set()
        self._alerts_fired: int = 0

    async def start(self) -> None:
        """
        Se nessun WhitelistManager è stato iniettato, ne crea uno locale
        (solo lettura, non supporta add/remove runtime).
        """
        if self._whitelist is None:
            from src.core.whitelist import WhitelistManager as WM
            self._whitelist = WM(self._known_hosts_file)
            await self._whitelist.load()
            logger.warning(
                "NewHostDetector: nessun WhitelistManager iniettato — "
                "whitelist in sola lettura (add/remove via API non disponibile)"
            )
        else:
            logger.info(
                f"NewHostDetector: usando WhitelistManager condiviso "
                f"({self._whitelist.count} host noti)"
            )

    # ── Packet / ARP processing ───────────────────────────────────────────────

    async def process_packet(self, pkt: Any) -> None:
        """Analizza pacchetti ARP per rilevare nuovi host in tempo reale."""
        try:
            from scapy.layers.l2 import ARP
        except ImportError:
            return

        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        src_ip: str = arp.psrc
        src_mac: str = arp.hwsrc.lower()

        if src_ip and src_ip != "0.0.0.0":
            await self._check_host(src_ip, src_mac)

    async def process_arp_table(self, table: Dict[str, str]) -> None:
        """Analizza la ARP table di sistema per rilevare nuovi host."""
        for ip, mac in table.items():
            await self._check_host(ip, mac.lower())

    async def _check_host(self, ip: str, mac: str) -> None:
        """
        Controlla se un host è noto; emette alert se inatteso.

        - IP non in whitelist → NEW_IP (medium, una volta per sessione)
        - IP in whitelist con MAC sbagliato → MAC_MISMATCH (high)
        """
        if not self._whitelist:
            return

        # Dedup rapido: se già alertato in questa sessione, skip
        if ip in self._alerted_ips:
            return

        self._seen_ips.add(ip)

        if not self._whitelist.is_whitelisted(ip):
            # IP sconosciuto
            self._alerted_ips.add(ip)
            self._alerts_fired += 1
            await self.emit(
                new_event(
                    detector_name=self.detector_name,
                    severity=self._severity,
                    source_ip=ip,
                    summary=f"New host discovered on LAN: {ip} ({mac})",
                    raw_data={"ip": ip, "mac": mac, "reason": "unknown_ip"},
                    tags=["network", "new-host", "arp"],
                )
            )
            return

        # IP in whitelist: controlla MAC se specificato
        expected_mac = self._whitelist.get_expected_mac(ip)
        if expected_mac is not None and mac != expected_mac:
            self._alerted_ips.add(ip)
            self._alerts_fired += 1
            await self.emit(
                new_event(
                    detector_name=self.detector_name,
                    severity=Severity.HIGH,
                    source_ip=ip,
                    summary=(
                        f"Known IP {ip} seen with unexpected MAC "
                        f"{mac} (expected {expected_mac})"
                    ),
                    raw_data={
                        "ip": ip,
                        "observed_mac": mac,
                        "expected_mac": expected_mac,
                        "reason": "mac_mismatch",
                    },
                    tags=["network", "new-host", "mac-mismatch", "arp"],
                )
            )

    # ── Whitelist control ─────────────────────────────────────────────────────

    def clear_ip_alerts(self, ip: str) -> None:
        """
        Rimuove un IP dall'elenco degli alertati in questa sessione.

        Chiamare dopo aver aggiunto l'IP alla whitelist via API:
        il detector non considererà più quell'IP come "già alertato"
        e la prossima occorrenza sarà silenziosamente ignorata
        (perché ora è in whitelist).
        """
        self._alerted_ips.discard(ip)
        self._seen_ips.discard(ip)
        logger.debug(f"NewHostDetector: alert state cleared for {ip}")

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        return {
            **super().get_status(),
            "known_hosts": self._whitelist.count if self._whitelist else 0,
            "seen_ips": len(self._seen_ips),
            "alerted_ips": len(self._alerted_ips),
            "alerts_fired": self._alerts_fired,
            "known_hosts_file": self._known_hosts_file,
        }
