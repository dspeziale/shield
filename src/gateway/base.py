"""
AbstractGatewayAdapter — interfaccia astratta per il message gateway.

Isola completamente la dipendenza da Hermes.Agent dal resto del codice.
Per integrare un diverso sistema di messaggistica (MQTT, Kafka, REST, ecc.)
basta implementare questa interfaccia e configurare l'adapter in config.yaml.

Punti di integrazione Hermes.Agent
===================================

TODO-HERMES-1: Endpoint WebSocket
    Sostituire base_url+publish_path con l'URL reale del Hermes message gateway.
    Default: ws://localhost:8080/ws/events

TODO-HERMES-2: Schema messaggio
    Se Hermes si aspetta un envelope specifico (es. {"type": "ids_event", "payload": {...}})
    adattare il metodo _serialize() nell'adapter.

TODO-HERMES-3: Autenticazione
    Implementare l'autenticazione SDK-nativa Hermes se disponibile.
    Attualmente usa header X-Api-Key nel handshake WebSocket.

TODO-HERMES-4: Topic/Channel
    Se Hermes supporta topic/channel, passare il topic nel metodo publish()
    o configurarlo in config.yaml sotto hermes.publish_path.

TODO-HERMES-5: SDK nativo
    Se Hermes.Agent ha un SDK Python ufficiale, sostituire l'implementazione
    HTTP/WebSocket con le chiamate SDK mantenendo questa interfaccia.
"""
from __future__ import annotations

import abc
import enum
from typing import Any, Dict, Optional

from src.core.event import IDSEvent


class GatewayStatus(str, enum.Enum):
    """Stato della connessione al gateway."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    DISABLED = "disabled"


class AbstractGatewayAdapter(abc.ABC):
    """
    Interfaccia astratta per l'adapter del message gateway.

    Tutti gli adapter devono implementare i metodi astratti.
    Le implementazioni concrete gestiscono internamente
    connessione, retry, serializzazione e autenticazione.
    """

    @abc.abstractmethod
    async def connect(self) -> None:
        """
        Stabilisce la connessione al gateway.
        Deve essere idempotente (chiamabile più volte senza effetti collaterali).
        """
        ...

    @abc.abstractmethod
    async def disconnect(self) -> None:
        """
        Chiude la connessione al gateway in modo pulito.
        """
        ...

    @abc.abstractmethod
    async def publish(self, event: IDSEvent) -> bool:
        """
        Pubblica un evento IDS nel gateway.

        Args:
            event: evento strutturato da pubblicare

        Returns:
            True se pubblicato con successo, False altrimenti.
            Non solleva eccezioni (le gestisce internamente).
        """
        ...

    @property
    @abc.abstractmethod
    def status(self) -> GatewayStatus:
        """Stato corrente della connessione."""
        ...

    @abc.abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Statistiche di pubblicazione (successi, errori, retry, ecc.)."""
        ...

    async def __aenter__(self) -> "AbstractGatewayAdapter":
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.disconnect()
