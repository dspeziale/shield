"""
Events API endpoints.

    GET /events              — lista ultimi N eventi con filtri
    GET /events/{event_id}   — singolo evento per ID
"""
from __future__ import annotations

from collections import deque
from typing import Any, Deque, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status

from src.core.event import IDSEvent, Severity

router = APIRouter(prefix="/events", tags=["events"])

# Ring buffer degli eventi in memoria (iniettato da server.py)
_event_store: Deque[IDSEvent] = deque(maxlen=1000)


def get_event_store() -> Deque[IDSEvent]:
    """Ritorna il riferimento allo store degli eventi."""
    return _event_store


def set_event_store(store: Deque[IDSEvent]) -> None:
    """Inietta il ring buffer degli eventi."""
    global _event_store
    _event_store = store


def add_event(event: IDSEvent) -> None:
    """Aggiunge un evento allo store (chiamato dal drain handler)."""
    _event_store.append(event)


@router.get(
    "",
    summary="Lista eventi recenti",
    response_description="Lista filtrata degli ultimi eventi IDS",
)
async def list_events(
    severity: Optional[str] = Query(
        default=None,
        description="Filtra per severity: low, medium, high, critical",
    ),
    detector: Optional[str] = Query(
        default=None,
        description="Filtra per nome detector",
    ),
    source_ip: Optional[str] = Query(
        default=None,
        description="Filtra per IP sorgente",
    ),
    tag: Optional[str] = Query(
        default=None,
        description="Filtra per tag",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
        description="Numero massimo di eventi da ritornare",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Numero di eventi da saltare (paginazione)",
    ),
) -> Dict[str, Any]:
    """
    Ritorna gli ultimi eventi IDS con supporto a filtri e paginazione.

    Gli eventi sono ordinati dal più recente al più vecchio.
    """
    # Prende tutti gli eventi e inverte (più recenti prima)
    events: List[IDSEvent] = list(reversed(_event_store))

    # Applica filtri
    if severity:
        try:
            sev = Severity(severity.lower())
            events = [e for e in events if e.severity == sev]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid severity: {severity}. Valid: {[s.value for s in Severity]}",
            )

    if detector:
        events = [e for e in events if e.detector_name == detector]

    if source_ip:
        events = [e for e in events if e.source_ip == source_ip]

    if tag:
        events = [e for e in events if tag in e.tags]

    total = len(events)
    paginated = events[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": [e.to_json_dict() for e in paginated],
    }


@router.get(
    "/{event_id}",
    summary="Singolo evento per ID",
    response_description="Evento IDS con l'ID specificato",
)
async def get_event(event_id: str) -> Dict[str, Any]:
    """
    Ritorna un singolo evento IDS identificato dal suo ID.

    Ritorna 404 se l'evento non è più in memoria (ring buffer limitato).
    """
    for event in _event_store:
        if event.id == event_id:
            return event.to_json_dict()

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Event '{event_id}' not found in memory store",
    )
