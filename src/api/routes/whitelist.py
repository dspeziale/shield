"""
Whitelist API endpoints.

    GET    /whitelist                        — lista tutti gli host in whitelist
    POST   /whitelist                        — aggiunge un host
    GET    /whitelist/{ip}                   — dettagli di un host
    PUT    /whitelist/{ip}                   — aggiorna mac/description
    DELETE /whitelist/{ip}                   — rimuove un host
    POST   /whitelist/ack/{event_id}         — whitelist da evento (ack alert)

Esempi curl::

    # Lista
    curl http://localhost:8765/whitelist

    # Aggiungi
    curl -X POST http://localhost:8765/whitelist \\
         -H "Content-Type: application/json" \\
         -d '{"ip":"192.168.1.50","mac":"aa:bb:cc:dd:ee:ff","description":"Laptop Marco"}'

    # Aggiorna descrizione
    curl -X PUT http://localhost:8765/whitelist/192.168.1.50 \\
         -H "Content-Type: application/json" \\
         -d '{"description":"MacBook Pro Marco"}'

    # Rimuovi
    curl -X DELETE http://localhost:8765/whitelist/192.168.1.50

    # Ack da evento (whitelist il source_ip dell'evento)
    curl -X POST "http://localhost:8765/whitelist/ack/evt-abc123?description=Stampante+HP"
"""
from __future__ import annotations

from collections import deque
from typing import Any, Deque, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from src.core.event import IDSEvent
from src.core.whitelist import WhitelistManager

router = APIRouter(prefix="/whitelist", tags=["whitelist"])

# ── Stato iniettato da server.py ─────────────────────────────────────────────

_whitelist_manager: Optional[WhitelistManager] = None
_event_store: Optional[Deque[IDSEvent]] = None
_detectors: Optional[List[Any]] = None


def set_whitelist_manager(manager: WhitelistManager) -> None:
    global _whitelist_manager
    _whitelist_manager = manager


def set_whitelist_dependencies(
    manager: WhitelistManager,
    event_store: Deque[IDSEvent],
    detectors: List[Any],
) -> None:
    """Inietta tutte le dipendenze necessarie alle route."""
    global _whitelist_manager, _event_store, _detectors
    _whitelist_manager = manager
    _event_store = event_store
    _detectors = detectors


# ── Pydantic models ───────────────────────────────────────────────────────────

class AddHostRequest(BaseModel):
    ip: str = Field(description="Indirizzo IPv4 da aggiungere")
    mac: Optional[str] = Field(
        default=None,
        description="MAC address atteso (es. aa:bb:cc:dd:ee:ff). "
                    "Ometti o lascia null per accettare qualsiasi MAC.",
    )
    description: str = Field(
        default="",
        description="Etichetta leggibile del dispositivo",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        parts = v.split(".")
        if len(parts) != 4:
            raise ValueError(f"IP non valido: {v!r}")
        try:
            for p in parts:
                n = int(p)
                if not (0 <= n <= 255):
                    raise ValueError
        except ValueError:
            raise ValueError(f"IP non valido: {v!r}")
        return v

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = v.strip().lower().replace("-", ":").replace(".", ":")
        parts = v.split(":")
        if len(parts) != 6:
            raise ValueError(f"MAC non valido: {v!r} (formato atteso: aa:bb:cc:dd:ee:ff)")
        for p in parts:
            if len(p) != 2 or not all(c in "0123456789abcdef" for c in p):
                raise ValueError(f"MAC non valido: {v!r}")
        return v


class UpdateHostRequest(BaseModel):
    mac: Optional[str] = Field(
        default=None,
        description="Nuovo MAC atteso. Passa '' (stringa vuota) per rimuovere il vincolo.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Nuova descrizione. Ometti per non modificare.",
    )

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if v == "":
            return ""  # rimuovi vincolo MAC
        v = v.lower().replace("-", ":").replace(".", ":")
        parts = v.split(":")
        if len(parts) != 6:
            raise ValueError(f"MAC non valido: {v!r}")
        return v


# ── GET /whitelist ─────────────────────────────────────────────────────────────

@router.get(
    "",
    summary="Lista whitelist",
    response_description="Tutti gli host in whitelist, ordinati per IP",
)
async def list_whitelist() -> Dict[str, Any]:
    """
    Ritorna l'elenco completo degli host in whitelist.

    Gli host in whitelist non generano alert quando rilevati sulla LAN.
    """
    _check_available()
    entries = _whitelist_manager.list_all()
    return {
        "total": len(entries),
        "entries": [e.to_dict() for e in entries],
    }


# ── POST /whitelist ────────────────────────────────────────────────────────────

@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Aggiungi host alla whitelist",
)
async def add_host(req: AddHostRequest) -> Dict[str, Any]:
    """
    Aggiunge un host alla whitelist e persiste su known_hosts.yaml.

    Se l'IP esiste già, lo sovrascrive.
    Dopo l'aggiunta, lo storico degli alert per quell'IP viene azzerato:
    il detector non lo considererà più come "già alertato" in questa sessione.
    """
    _check_available()
    entry = await _whitelist_manager.add(
        ip=req.ip,
        mac=req.mac,
        description=req.description,
        added_by="api",
    )
    # Azzera lo stato alert nel detector (l'IP è ora noto)
    _clear_detector_alerts(req.ip)
    return {
        "added": True,
        "entry": entry.to_dict(),
    }


# ── GET /whitelist/{ip} ────────────────────────────────────────────────────────

@router.get(
    "/{ip}",
    summary="Dettagli host in whitelist",
)
async def get_host(ip: str) -> Dict[str, Any]:
    """Ritorna i dettagli di un singolo host in whitelist."""
    _check_available()
    entry = _whitelist_manager.get(ip)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{ip}' non trovato in whitelist",
        )
    return entry.to_dict()


# ── PUT /whitelist/{ip} ────────────────────────────────────────────────────────

@router.put(
    "/{ip}",
    summary="Aggiorna host in whitelist",
)
async def update_host(ip: str, req: UpdateHostRequest) -> Dict[str, Any]:
    """
    Aggiorna mac e/o description di un host esistente.

    - Per aggiornare solo la description: ometti `mac`
    - Per rimuovere il vincolo MAC: passa `mac: ""`
    """
    _check_available()
    entry = await _whitelist_manager.update(
        ip=ip,
        mac=req.mac,
        description=req.description,
    )
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{ip}' non trovato in whitelist",
        )
    return {
        "updated": True,
        "entry": entry.to_dict(),
    }


# ── DELETE /whitelist/{ip} ─────────────────────────────────────────────────────

@router.delete(
    "/{ip}",
    summary="Rimuovi host dalla whitelist",
)
async def remove_host(ip: str) -> Dict[str, Any]:
    """
    Rimuove un host dalla whitelist e persiste su known_hosts.yaml.

    Dopo la rimozione, il prossimo pacchetto ARP da quell'IP genererà
    un nuovo alert (come se fosse un host sconosciuto).
    """
    _check_available()
    removed = await _whitelist_manager.remove(ip)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{ip}' non trovato in whitelist",
        )
    return {"removed": True, "ip": ip}


# ── POST /whitelist/ack/{event_id} ─────────────────────────────────────────────

@router.post(
    "/ack/{event_id}",
    status_code=status.HTTP_201_CREATED,
    summary="Whitelist da evento (ack alert)",
)
async def ack_event(
    event_id: str,
    description: str = Query(
        default="",
        description="Descrizione del dispositivo. "
                    "Se omessa, viene usato il summary dell'evento.",
    ),
) -> Dict[str, Any]:
    """
    Aggiunge alla whitelist il `source_ip` dell'evento specificato.

    Utile per gestire gli alert di tipo `new_host_detector`:
    vedi un alert per un IP che riconosci (es. il tuo telefono),
    chiami questo endpoint con l'event_id e l'IP viene automaticamente
    aggiunto alla whitelist.

    Il MAC rilevato nell'evento (se disponibile nel `raw_data`) viene usato
    come MAC atteso, così futuri cambi MAC generano alert.
    """
    _check_available()

    if _event_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Event store non disponibile",
        )

    # Cerca l'evento nello store in-memory
    event: Optional[IDSEvent] = None
    for e in _event_store:
        if e.id == event_id:
            event = e
            break

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evento '{event_id}' non trovato (potrebbe non essere più in memoria)",
        )

    ip = event.source_ip
    mac = event.raw_data.get("mac") if event.raw_data else None
    desc = description.strip() or f"Acked: {event.summary}"

    entry = await _whitelist_manager.add(
        ip=ip,
        mac=mac or None,
        description=desc,
        added_by="api:ack",
    )
    _clear_detector_alerts(ip)

    return {
        "whitelisted": True,
        "entry": entry.to_dict(),
        "from_event": {
            "id": event.id,
            "detector": event.detector_name,
            "summary": event.summary,
            "timestamp": event.timestamp.isoformat(),
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_available() -> None:
    """Solleva 503 se il manager non è ancora inizializzato."""
    if _whitelist_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Whitelist manager non disponibile",
        )


def _clear_detector_alerts(ip: str) -> None:
    """
    Azzera lo stato alert per un IP in tutti i detector che lo supportano.
    Chiamare dopo add/ack per evitare che il detector salti il check
    perché l'IP era già in _alerted_ips.
    """
    if _detectors is None:
        return
    for det in _detectors:
        if hasattr(det, "clear_ip_alerts"):
            det.clear_ip_alerts(ip)
