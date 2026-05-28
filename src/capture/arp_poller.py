"""
ARP Table Poller — polling periodico della ARP table di sistema.

Legge la ARP table del sistema operativo a intervalli configurabili
e la fornisce ai detector interessati (NewHostDetector, ARPSpoofDetector).

Supporto OS:
    - Linux:   legge /proc/net/arp (formato più affidabile)
    - Windows: esegue `arp -a` e parsa l'output
    - macOS:   esegue `arp -a` (formato BSD)

Il risultato è un dict {ip: mac} normalizzato (MAC in formato aa:bb:cc:dd:ee:ff).
"""
from __future__ import annotations

import asyncio
import logging
import platform
import re
import subprocess
import sys
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

# Type alias per il callback ARP
ARPTableCallback = Callable[[Dict[str, str]], None]


class ARPPoller:
    """
    Poller periodico della ARP table di sistema.

    Parametri:
        interval_seconds: intervallo tra i poll (default 30)
        loop:             event loop asyncio
    """

    def __init__(
        self,
        interval_seconds: int = 30,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._interval = interval_seconds
        self._loop = loop or asyncio.get_event_loop()
        self._callbacks: list[ARPTableCallback] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_table: Dict[str, str] = {}

    def add_callback(self, cb: ARPTableCallback) -> None:
        """Registra un callback che riceve la ARP table aggiornata."""
        self._callbacks.append(cb)

    async def start(self) -> None:
        """Avvia il polling periodico in background."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name="arp-poller")
        logger.info(f"ARPPoller started (interval={self._interval}s)")

    async def stop(self) -> None:
        """Ferma il polling."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("ARPPoller stopped")

    async def _poll_loop(self) -> None:
        """Loop principale di polling."""
        while self._running:
            table = await self._get_arp_table()
            if table:
                self._last_table = table
                self._dispatch(table)
            await asyncio.sleep(self._interval)

    def _dispatch(self, table: Dict[str, str]) -> None:
        """Chiama tutti i callback con la ARP table corrente."""
        for cb in self._callbacks:
            try:
                cb(table)
            except Exception as exc:
                logger.error(f"ARP table callback error: {exc}", exc_info=True)

    async def _get_arp_table(self) -> Dict[str, str]:
        """
        Legge la ARP table del sistema operativo in modo async.

        Returns:
            dict {ip: mac} con MAC normalizzato (lowercase, separatori ':')
        """
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._read_arp_table_sync)
        except Exception as exc:
            logger.error(f"Failed to read ARP table: {exc}")
            return {}

    def _read_arp_table_sync(self) -> Dict[str, str]:
        """Lettura sincrona della ARP table (eseguita in executor)."""
        os_name = platform.system().lower()

        if os_name == "linux":
            return self._read_linux_proc_arp()
        elif os_name == "windows":
            return self._read_windows_arp()
        else:
            # macOS e altri POSIX
            return self._read_posix_arp()

    def _read_linux_proc_arp(self) -> Dict[str, str]:
        """Legge /proc/net/arp (Linux)."""
        result: Dict[str, str] = {}
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                next(f)  # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "0x2":  # 0x2 = complete entry
                        ip = parts[0]
                        mac = parts[3].lower()
                        if mac != "00:00:00:00:00:00":
                            result[ip] = mac
        except Exception as exc:
            logger.debug(f"Failed to read /proc/net/arp: {exc}")
        return result

    def _read_windows_arp(self) -> Dict[str, str]:
        """Legge la ARP table su Windows tramite `arp -a`."""
        result: Dict[str, str] = {}
        try:
            output = subprocess.check_output(
                ["arp", "-a"],
                stderr=subprocess.DEVNULL,
                timeout=5,
                text=True,
                encoding="cp850",  # Windows codepage
            )
            # Pattern: "  192.168.1.1          00-11-22-33-44-55     dynamic"
            pattern = re.compile(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
                r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
                r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})"
            )
            for match in pattern.finditer(output):
                ip = match.group(1)
                mac = match.group(2).lower().replace("-", ":")
                if not ip.endswith(".255"):  # Esclude broadcast
                    result[ip] = mac
        except Exception as exc:
            logger.debug(f"Windows arp -a failed: {exc}")
        return result

    def _read_posix_arp(self) -> Dict[str, str]:
        """Legge la ARP table su macOS/BSD tramite `arp -a`."""
        result: Dict[str, str] = {}
        try:
            output = subprocess.check_output(
                ["arp", "-a"],
                stderr=subprocess.DEVNULL,
                timeout=5,
                text=True,
            )
            # macOS: "gateway (192.168.1.1) at 00:11:22:33:44:55 on en0 ..."
            pattern = re.compile(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]{17})"
            )
            for match in pattern.finditer(output):
                ip = match.group(1)
                mac = match.group(2).lower()
                result[ip] = mac
        except Exception as exc:
            logger.debug(f"POSIX arp -a failed: {exc}")
        return result

    @property
    def last_table(self) -> Dict[str, str]:
        """Ultima ARP table letta."""
        return dict(self._last_table)
