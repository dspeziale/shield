"""
IDSEvent — modello dati centrale per tutti gli eventi di detection.

Ogni evento ha un ID univoco, timestamp UTC, severity, indirizzi IP
sorgente/destinazione, nome del detector che lo ha prodotto, sommario
leggibile, dati grezzi strutturati e tag per il filtraggio downstream.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Livelli di gravità degli eventi IDS."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Peso numerico per ordinamento/confronto."""
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class IDSEvent(BaseModel):
    """
    Evento strutturato prodotto da un detector IDS.

    Esempio::

        event = IDSEvent(
            severity=Severity.HIGH,
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            detector_name="port_scan_detector",
            summary="Possible port scan detected",
            raw_data={"ports": [22, 80, 443]},
            tags=["network", "scan"],
        )
    """

    id: str = Field(
        default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}",
        description="Identificatore univoco dell'evento",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp UTC di generazione dell'evento",
    )
    severity: Severity = Field(description="Gravità dell'evento")
    source_ip: str = Field(description="Indirizzo IP sorgente")
    destination_ip: Optional[str] = Field(
        default=None, description="Indirizzo IP destinazione (se noto)"
    )
    detector_name: str = Field(description="Nome del detector che ha generato l'evento")
    summary: str = Field(description="Descrizione leggibile dell'evento")
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Payload grezzo specifico del detector",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tag per filtraggio e categorizzazione",
    )

    model_config = {
        "populate_by_name": True,
    }

    def to_json_dict(self) -> Dict[str, Any]:
        """Serializza in dict JSON-serializable (timestamp come stringa ISO-8601)."""
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.value
        return d

    def __str__(self) -> str:
        return (
            f"[{self.severity.value.upper()}] {self.detector_name}: "
            f"{self.summary} ({self.source_ip})"
        )


def new_event(
    detector_name: str,
    severity: Severity,
    source_ip: str,
    summary: str,
    destination_ip: Optional[str] = None,
    raw_data: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None,
) -> IDSEvent:
    """
    Factory function per la creazione rapida di IDSEvent.

    Evita la verbosità del costruttore diretto e garantisce
    che raw_data e tags non siano None.
    """
    return IDSEvent(
        detector_name=detector_name,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        summary=summary,
        raw_data=raw_data or {},
        tags=tags or [],
    )
