FROM python:3.12-slim

LABEL maintainer="hermes-ids"
LABEL description="Hermes IDS — Intrusion Detection System per LAN locale"

# ── System deps per scapy + libpcap ──────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        net-tools \
        iproute2 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python deps (layer separato per cache) ───────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Source code ───────────────────────────────────────────────────────────────
COPY src/         ./src/
COPY plugins/     ./plugins/
COPY ids_report.py .

# ── Directory runtime (montate come volume) ───────────────────────────────────
RUN mkdir -p /app/config /app/data /app/logs

# ── Healthcheck ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8765/health | grep -q '"status"' || exit 1

# ── Avvio ─────────────────────────────────────────────────────────────────────
CMD ["python", "-m", "src.main", "--config", "/app/config/config.yaml"]
