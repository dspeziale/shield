# ============================================================
#  Dockerfile — Hermes-IDS
#
#  Build multi-stage:
#   1. builder: installa dipendenze in venv
#   2. runtime: copia solo il necessario (immagine slim)
#
#  Nota: NET_RAW e NET_ADMIN sono richiesti per scapy.
#  Aggiungerli in docker-compose.yml o docker run:
#    --cap-add NET_RAW --cap-add NET_ADMIN
#  Oppure: --network host (per sniffing reale)
# ============================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Installa dipendenze di sistema necessarie per scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Crea venv
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Installa dipendenze Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="hermes-ids"
LABEL description="IDS locale integrato con Hermes.Agent"
LABEL version="0.1.0"

WORKDIR /app

# Dipendenze runtime di sistema per scapy/libpcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copia venv da builder
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

# Copia sorgenti
COPY src/ ./src/
COPY plugins/ ./plugins/
COPY config/ ./config/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Non eseguire come root (usiamo cap NET_RAW invece)
RUN useradd -r -s /bin/false idsuser
# Per scapy servono capabilities, non root
# Il container deve essere avviato con --cap-add NET_RAW NET_ADMIN

# Porte esposte
EXPOSE 8765   # API REST
EXPOSE 9090   # Prometheus metrics

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/health')" \
    || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--config", "config/config.yaml"]
