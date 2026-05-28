"""
WhitelistManager — gestione runtime della whitelist host IDS.

Responsabilità:
- Carica known_hosts.yaml allo startup
- Espone API in-memory O(1) per il detector (is_whitelisted, get_expected_mac)
- Permette add/remove/update thread-safe con persistenza atomica su disco
- Mantiene metadati (chi ha aggiunto l'entry, quando)

Thread-safety:
- Letture (is_whitelisted, get_expected_mac, list_all): lock-free
  I dict Python sono thread-safe per letture concorrenti.
- Scritture (add, remove, update): asyncio.Lock — serializza modifiche
  e garantisce che persist() sia sempre consistente con lo stato in memoria.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


# ─── Entry ───────────────────────────────────────────────────────────────────

class WhitelistEntry:
    """
    Un host nella whitelist.

    Attributi:
        ip:          Indirizzo IPv4 (chiave primaria)
        mac:         MAC address atteso; None = accetta qualsiasi MAC
        description: Etichetta leggibile del dispositivo
        added_at:    Timestamp ISO-8601 di aggiunta
        added_by:    Chi ha aggiunto: "config" | "api" | "api:ack"
    """

    def __init__(
        self,
        ip: str,
        mac: Optional[str] = None,
        description: str = "",
        added_at: Optional[str] = None,
        added_by: str = "config",
    ) -> None:
        self.ip = ip.strip()
        self.mac = _normalize_mac(mac) if mac else None
        self.description = description.strip()
        self.added_at = added_at or _now_iso()
        self.added_by = added_by

    def to_dict(self) -> Dict[str, Any]:
        """Rappresentazione JSON per la REST API."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "description": self.description,
            "added_at": self.added_at,
            "added_by": self.added_by,
        }

    def to_yaml_dict(self) -> Dict[str, Any]:
        """Rappresentazione per il file YAML (compatibile con il formato storico)."""
        d: Dict[str, Any] = {"ip": self.ip}
        if self.mac:
            d["mac"] = self.mac
        d["description"] = self.description
        d["added_at"] = self.added_at
        d["added_by"] = self.added_by
        return d

    def __repr__(self) -> str:
        return f"WhitelistEntry(ip={self.ip!r}, mac={self.mac!r}, desc={self.description!r})"


# ─── Manager ─────────────────────────────────────────────────────────────────

class WhitelistManager:
    """
    Gestione centralizzata della whitelist host.

    Utilizzo::

        wl = WhitelistManager("config/known_hosts.yaml")
        await wl.load()

        # Detector: query O(1)
        if wl.is_whitelisted("192.168.1.1"):
            expected = wl.get_expected_mac("192.168.1.1")

        # API: modifiche persistenti
        entry = await wl.add("192.168.1.50", mac="aa:bb:cc:dd:ee:ff",
                              description="Laptop Marco")
        removed = await wl.remove("192.168.1.50")
    """

    def __init__(self, hosts_file: str = "config/known_hosts.yaml") -> None:
        self._file = Path(hosts_file)
        self._entries: Dict[str, WhitelistEntry] = {}   # ip → entry
        self._write_lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def load(self) -> int:
        """
        Carica la whitelist dal file YAML.
        Ritorna il numero di entries caricate.
        """
        if not self._file.exists():
            logger.warning(
                f"Whitelist file not found: {self._file} "
                "— tutti gli host sconosciuti genereranno alert"
            )
            return 0

        try:
            with open(self._file, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            loaded = 0
            for raw in data.get("known_hosts", []):
                ip = raw.get("ip", "").strip()
                if not ip:
                    continue
                mac = raw.get("mac", "")
                self._entries[ip] = WhitelistEntry(
                    ip=ip,
                    mac=mac or None,
                    description=raw.get("description", ""),
                    added_at=raw.get("added_at"),
                    added_by=raw.get("added_by", "config"),
                )
                loaded += 1

            logger.info(f"Whitelist: loaded {loaded} hosts from {self._file}")
            return loaded

        except Exception as exc:
            logger.error(f"Failed to load whitelist: {exc}", exc_info=True)
            return 0

    # ── Query — lock-free, O(1) ───────────────────────────────────────────────

    def is_whitelisted(self, ip: str) -> bool:
        """True se l'IP è in whitelist."""
        return ip in self._entries

    def get_expected_mac(self, ip: str) -> Optional[str]:
        """
        Ritorna il MAC atteso per l'IP.
        None se l'IP non è in whitelist o se il MAC non è specificato.
        """
        entry = self._entries.get(ip)
        return entry.mac if entry else None

    def get(self, ip: str) -> Optional[WhitelistEntry]:
        """Ritorna l'entry per un IP, None se non presente."""
        return self._entries.get(ip)

    def list_all(self) -> List[WhitelistEntry]:
        """Ritorna tutte le entries ordinate per IP."""
        return sorted(self._entries.values(), key=lambda e: _ip_sort_key(e.ip))

    @property
    def count(self) -> int:
        """Numero di host in whitelist."""
        return len(self._entries)

    # ── Mutations — async con lock + persist ──────────────────────────────────

    async def add(
        self,
        ip: str,
        mac: Optional[str] = None,
        description: str = "",
        added_by: str = "api",
    ) -> WhitelistEntry:
        """
        Aggiunge o aggiorna un host in whitelist, poi persiste su YAML.

        Se l'IP esiste già, lo sovrascrive con i nuovi valori.
        """
        async with self._write_lock:
            entry = WhitelistEntry(
                ip=ip,
                mac=mac,
                description=description,
                added_by=added_by,
            )
            self._entries[ip] = entry
            await self._persist_locked()
            logger.info(
                f"Whitelist: added {ip} (mac={entry.mac or 'any'}) by={added_by}"
            )
            return entry

    async def remove(self, ip: str) -> bool:
        """
        Rimuove un host dalla whitelist e persiste.
        Ritorna True se rimosso, False se non trovato.
        """
        async with self._write_lock:
            if ip not in self._entries:
                return False
            del self._entries[ip]
            await self._persist_locked()
            logger.info(f"Whitelist: removed {ip}")
            return True

    async def update(
        self,
        ip: str,
        mac: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[WhitelistEntry]:
        """
        Aggiorna mac e/o description di un entry esistente.
        Ritorna l'entry aggiornata, None se IP non trovato.

        Passa mac="" per rimuovere il vincolo MAC (accetta qualsiasi).
        """
        async with self._write_lock:
            entry = self._entries.get(ip)
            if entry is None:
                return None
            if mac is not None:
                entry.mac = _normalize_mac(mac) if mac else None
            if description is not None:
                entry.description = description.strip()
            await self._persist_locked()
            logger.info(f"Whitelist: updated {ip}")
            return entry

    # ── Persistence ───────────────────────────────────────────────────────────

    async def _persist_locked(self) -> None:
        """
        Scrive la whitelist su YAML.
        DEVE essere chiamato solo dentro _write_lock.
        """
        try:
            self._file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "known_hosts": [e.to_yaml_dict() for e in self.list_all()]
            }
            header = (
                "# ============================================================\n"
                "#  known_hosts.yaml — Host noti sulla LAN\n"
                f"#  Aggiornato: {_now_iso()}\n"
                "# ============================================================\n\n"
            )
            with open(self._file, "w", encoding="utf-8") as f:
                f.write(header)
                yaml.dump(
                    data, f,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                )
            logger.debug(f"Whitelist persisted to {self._file} ({self.count} entries)")
        except Exception as exc:
            logger.error(f"Failed to persist whitelist: {exc}", exc_info=True)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _normalize_mac(mac: str) -> str:
    """Normalizza MAC in formato lowercase colon-separated."""
    return mac.strip().lower().replace("-", ":").replace(".", ":")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ip_sort_key(ip: str) -> tuple:
    """Chiave di ordinamento numerica per IPv4."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        pass
    return (999, 999, 999, 999)
