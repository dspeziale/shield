"""
BaseDetector — interfaccia astratta per tutti i detector IDS.

Ogni detector:
1. Eredita da BaseDetector
2. Definisce il class attribute `detector_name` (stringa unica)
3. Implementa `process_packet()` e opzionalmente `process_arp_table()`
4. Emette eventi tramite `self.emit(event)` — il callback è iniettato dal motore

Il decorator @register_detector registra automaticamente il detector
nel registry globale, abilitando il caricamento dinamico (plugin system).
"""
from __future__ import annotations

import abc
import logging
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar, Dict, Optional, Type

from src.core.event import IDSEvent

logger = logging.getLogger(__name__)

# Tipo del callback di emissione eventi
EventEmitter = Callable[[IDSEvent], Awaitable[None]]

# Registry globale: detector_name → class
_DETECTOR_REGISTRY: Dict[str, Type["BaseDetector"]] = {}


def register_detector(cls: Type["BaseDetector"]) -> Type["BaseDetector"]:
    """
    Decorator di classe che registra un detector nel registry globale.

    Uso::

        @register_detector
        class MyDetector(BaseDetector):
            detector_name = "my_detector"
            ...
    """
    name = getattr(cls, "detector_name", None)
    if not name:
        raise AttributeError(f"Detector {cls.__name__} must define 'detector_name'")
    if name in _DETECTOR_REGISTRY:
        logger.warning(f"Overwriting registered detector: {name}")
    _DETECTOR_REGISTRY[name] = cls
    logger.debug(f"Registered detector: {name} ({cls.__module__}.{cls.__name__})")
    return cls


def get_detector_registry() -> Dict[str, Type["BaseDetector"]]:
    """Ritorna una copia del registry globale dei detector."""
    return dict(_DETECTOR_REGISTRY)


class BaseDetector(abc.ABC):
    """
    Classe base astratta per tutti i detector IDS.

    I detector sono stateful: mantengono sliding windows, contatori
    e tabelle IP/MAC internamente. Sono async per natura: process_packet()
    viene chiamata per ogni pacchetto catturato, process_arp_table()
    periodicamente.

    L'emissione di eventi avviene tramite self.emit() che chiama
    il callback iniettato dal motore (AsyncEventQueue.put_nowait_or_drop).
    """

    detector_name: ClassVar[str]  # Obbligatorio nelle sottoclassi

    def __init__(self, config: Dict[str, Any], emitter: EventEmitter) -> None:
        """
        Args:
            config:  dizionario di configurazione specifico del detector
            emitter: callback async per emettere IDSEvent
        """
        self._config = config
        self._emitter = emitter
        self._enabled: bool = bool(config.get("enabled", True))

    @property
    def enabled(self) -> bool:
        """True se il detector è attivo."""
        return self._enabled

    async def emit(self, event: IDSEvent) -> None:
        """
        Emette un evento attraverso la pipeline.
        No-op se il detector è disabilitato.
        """
        if self._enabled:
            logger.debug(
                "event_emitted",
                extra={
                    "detector": self.detector_name,
                    "severity": event.severity.value,
                    "src": event.source_ip,
                },
            )
            await self._emitter(event)

    @abc.abstractmethod
    async def process_packet(self, pkt: Any) -> None:
        """
        Analizza un singolo pacchetto catturato.

        Args:
            pkt: pacchetto scapy (o mock nei test)
        """
        ...

    async def process_arp_table(self, table: Dict[str, str]) -> None:
        """
        Analizza uno snapshot della ARP table.

        Format: {ip_address: mac_address}
        Default: no-op. Override nei detector che lavorano su ARP.

        Args:
            table: mapping IP → MAC dell'ARP table corrente
        """

    async def start(self) -> None:
        """Lifecycle: chiamato all'avvio del motore. Override per init."""

    async def stop(self) -> None:
        """Lifecycle: chiamato allo shutdown. Override per pulizia risorse."""

    def get_status(self) -> Dict[str, Any]:
        """Stato del detector per la status API. Estendere nelle sottoclassi."""
        return {
            "name": self.detector_name,
            "enabled": self._enabled,
        }
