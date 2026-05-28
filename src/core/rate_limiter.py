"""
Token Bucket Rate Limiter — async, lock-based.

Algoritmo token-bucket:
- Capacità massima = burst_size token
- Ricarica a max_per_second token/secondo
- acquire() consuma 1 token; ritorna False (senza bloccare) se il bucket è vuoto

Uso tipico::

    limiter = TokenBucketRateLimiter(max_per_second=100, burst_size=200)
    async def handle_event(event):
        if not await limiter.acquire():
            return  # rate exceeded — scarta o ritarda
        await publish(event)
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional


class TokenBucketRateLimiter:
    """
    Rate limiter a token-bucket asincrono.

    Parametri:
        max_per_second: rate massimo a regime (token/s)
        burst_size: capacità del bucket (default = max_per_second)
        enabled: se False, tutte le acquire() passano senza limitazione
    """

    def __init__(
        self,
        max_per_second: float,
        burst_size: Optional[float] = None,
        enabled: bool = True,
    ) -> None:
        if max_per_second <= 0:
            raise ValueError("max_per_second must be > 0")

        self._rate = max_per_second
        self._capacity = float(burst_size) if burst_size is not None else float(max_per_second)
        self._tokens = self._capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self.enabled = enabled

        # Statistiche
        self.allowed: int = 0
        self.rejected: int = 0

    async def acquire(self, n: float = 1.0) -> bool:
        """
        Tenta di consumare `n` token.

        Returns:
            True  — richiesta autorizzata
            False — rate superato, richiesta rifiutata (non-blocking)
        """
        if not self.enabled:
            self.allowed += 1
            return True

        async with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                self.allowed += 1
                return True
            self.rejected += 1
            return False

    def _refill(self) -> None:
        """Aggiunge token proporzionalmente al tempo trascorso dall'ultimo refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        added = elapsed * self._rate
        self._tokens = min(self._capacity, self._tokens + added)
        self._last_refill = now

    @property
    def current_tokens(self) -> float:
        """Token correnti nel bucket (valore approssimativo, non thread-safe)."""
        return self._tokens

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "rate_per_second": self._rate,
            "burst_size": self._capacity,
            "current_tokens": round(self._tokens, 2),
            "allowed_total": self.allowed,
            "rejected_total": self.rejected,
        }
