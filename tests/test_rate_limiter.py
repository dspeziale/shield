"""
Test per TokenBucketRateLimiter.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from src.core.rate_limiter import TokenBucketRateLimiter


class TestTokenBucketRateLimiter:
    async def test_allows_within_rate(self):
        limiter = TokenBucketRateLimiter(max_per_second=100, burst_size=100)
        # Dovrebbe permettere 10 richieste senza problemi
        for _ in range(10):
            result = await limiter.acquire()
            assert result is True

    async def test_rejects_when_bucket_empty(self):
        """Con burst_size=1 e rate basso, la seconda richiesta immediata deve fallire."""
        limiter = TokenBucketRateLimiter(max_per_second=1.0, burst_size=1)
        r1 = await limiter.acquire()
        r2 = await limiter.acquire()  # Immediata: bucket è vuoto

        assert r1 is True
        assert r2 is False

    async def test_disabled_always_allows(self):
        limiter = TokenBucketRateLimiter(max_per_second=0.001, enabled=False)
        for _ in range(100):
            result = await limiter.acquire()
            assert result is True

    async def test_refill_over_time(self):
        """Verifica che il bucket si ricarichi nel tempo."""
        limiter = TokenBucketRateLimiter(max_per_second=100, burst_size=100)
        # Svuota il bucket
        for _ in range(100):
            await limiter.acquire()

        # Attendi ricarica parziale
        await asyncio.sleep(0.05)  # 0.05s × 100/s = 5 token

        # Ora dovrebbe permettere almeno alcune richieste
        allowed_count = 0
        for _ in range(10):
            if await limiter.acquire():
                allowed_count += 1

        assert allowed_count > 0

    async def test_stats_tracking(self):
        limiter = TokenBucketRateLimiter(max_per_second=1.0, burst_size=2)
        await limiter.acquire()  # allowed
        await limiter.acquire()  # allowed (burst)
        await limiter.acquire()  # rejected

        stats = limiter.get_stats()
        assert stats["allowed_total"] == 2
        assert stats["rejected_total"] == 1

    async def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            TokenBucketRateLimiter(max_per_second=0)

    async def test_concurrent_acquires(self):
        """Verifica comportamento con acquire concorrenti."""
        limiter = TokenBucketRateLimiter(max_per_second=50, burst_size=50)

        results = await asyncio.gather(
            *[limiter.acquire() for _ in range(50)]
        )
        allowed = sum(1 for r in results if r)
        # Tutti e 50 dovrebbero passare (= burst_size)
        assert allowed == 50
