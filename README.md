# 🛡️ Hermes-IDS

**Intrusion Detection System locale integrato con Hermes.Agent**

Servizio Python 3.12 standalone che monitora la rete LAN, rileva anomalie e
pubblica eventi strutturati al message gateway di [Hermes.Agent](https://github.com/your-org/hermes)
tramite WebSocket.

---

## Architettura

```
Network Interface
      │
      ▼
 PacketSniffer (thread scapy)
 ARPPoller (async, OS arp table)
      │  asyncio bridge
      ▼
┌─────────────────────────────────┐
│       Detector Engine           │
│  ┌─────────────────────────┐    │
│  │ PortScanDetector        │    │
│  │ NewHostDetector         │    │
│  │ TrafficVolumeDetector   │    │
│  │ SensitivePortsDetector  │    │
│  │ ARPSpoofDetector        │    │
│  │ [Plugins...]            │    │
│  └─────────────────────────┘    │
└──────────────┬──────────────────┘
               │
               ▼
     RateLimiter (token-bucket)
               │
               ▼
     AsyncEventQueue (buffer)
               │
       ┌───────┴──────────┐
       ▼                  ▼
HermesGatewayAdapter   EventStore
(WebSocket + retry)    (ring buffer)
       │                  │
       ▼                  ▼
Hermes.Agent      FastAPI REST API
                  Prometheus /metrics
```

---

## Funzionalità

### Detectors built-in

| Detector | Cosa rileva | Severity |
|---|---|---|
| `port_scan_detector` | Scansioni porte (N porte distinte in finestra) | HIGH |
| `new_host_detector` | Nuovi host sulla LAN (non in whitelist) | MEDIUM |
| `traffic_volume_detector` | Traffico anomalo per PPS/BPS | MEDIUM |
| `sensitive_ports_detector` | Tentativi ripetuti su SSH, RDP, SMB, DB | HIGH |
| `arp_spoof_detector` | Cambio MAC, IP con MAC multipli | CRITICAL |

### Infrastruttura

- **Coda async** con buffer e overflow protection
- **Rate limiter** token-bucket (es. 100 eventi/s)
- **Gateway WebSocket** con retry/backoff esponenziale e reconnect automatico
- **REST API** FastAPI: `/health`, `/ready`, `/events`, `/status`
- **Prometheus metrics** su porta 9090
- **Plugin system**: aggiungi detector custom in `plugins/`
- **Graceful shutdown**: drain completo prima della chiusura

---

## Quick Start

### 1. Requisiti

- Python 3.12+
- **Windows**: [Npcap](https://npcap.com) per packet capture con scapy
- **Linux/Docker**: capabilities `NET_RAW` + `NET_ADMIN`

### 2. Installazione

```bash
# Clona il repository
git clone <repo-url> hermes-ids
cd hermes-ids

# (Consigliato) Ambiente virtuale
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

# Installa dipendenze
pip install -r requirements.txt
```

### 3. Configurazione

```bash
# Copia e personalizza il file di configurazione
cp .env.example .env
# Edita .env con le tue credenziali Hermes

# Personalizza known_hosts
# Edita config/known_hosts.yaml con gli IP/MAC noti della tua LAN
```

### 4. Avvio (modalità mock — senza root/Npcap)

```bash
# Modalità sviluppo: pacchetti sintetici, gateway mock
python -m src.main --config config/config.yaml --mock-capture --no-hermes
```

### 5. Avvio (modalità reale)

```bash
# Windows: esegui come Amministratore (richiesto da Npcap)
# Linux: sudo o capabilities NET_RAW

python -m src.main --config config/config.yaml
```

### 6. Verifica

```bash
# Health check
curl http://localhost:8765/health

# Readiness
curl http://localhost:8765/ready

# Ultimi eventi
curl http://localhost:8765/events

# Stato completo
curl http://localhost:8765/status

# Metriche Prometheus
curl http://localhost:9090/metrics

# Filtra per severity
curl "http://localhost:8765/events?severity=high&limit=10"

# Filtra per detector
curl "http://localhost:8765/events?detector=port_scan_detector"
```

---

## Docker

### Build e avvio

```bash
# Avvia IDS + Prometheus
docker compose up --build

# Con Grafana
docker compose --profile monitoring up --build

# Solo IDS in mock mode (per test)
docker compose run --rm hermes-ids --mock-capture --no-hermes
```

### Configurazione Docker

Edita le variabili in `.env`:

```env
HERMES_API_KEY=your-key
HERMES_BASE_URL=ws://hermes-agent:8080
CAPTURE_INTERFACE=eth0
LOG_LEVEL=INFO
```

### Note sicurezza Docker

Per il packet capture reale il container necessita di:
```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```
Oppure `network_mode: host` su Linux.

---

## Configurazione (config/config.yaml)

```yaml
service:
  log_level: INFO          # DEBUG | INFO | WARNING | ERROR
  log_format: json         # json | console

capture:
  interface: auto          # "auto" rileva automaticamente
  bpf_filter: ""           # Filtro BPF (es. "not port 22")
  arp_poll_interval: 30    # Secondi tra poll ARP table

rate_limiter:
  enabled: true
  max_events_per_second: 100
  burst_size: 200

hermes:
  enabled: true
  adapter: websocket
  base_url: ws://localhost:8080
  publish_path: /ws/events
  api_key: ""              # O via env HERMES_API_KEY

api:
  port: 8765

metrics:
  port: 9090
```

Vedi [config/config.yaml](config/config.yaml) per la configurazione completa.

---

## REST API Reference

### `GET /health`
Liveness probe.
```json
{"status": "ok", "timestamp": "2026-05-27T10:00:00Z", "service": "hermes-ids"}
```

### `GET /ready`
Readiness probe — 200 se tutto ok, 503 se non pronto.

### `GET /events`
Lista eventi recenti.

**Query params:**
- `severity` — low | medium | high | critical
- `detector` — nome detector (es. `port_scan_detector`)
- `source_ip` — IP sorgente
- `tag` — tag
- `limit` — max eventi (default 100, max 1000)
- `offset` — paginazione

**Esempio risposta:**
```json
{
  "total": 3,
  "events": [
    {
      "id": "evt-abc123456789",
      "timestamp": "2026-05-27T10:00:00Z",
      "severity": "high",
      "source_ip": "192.168.1.50",
      "destination_ip": "192.168.1.1",
      "detector_name": "port_scan_detector",
      "summary": "Possible port scan: 15 distinct ports in 10s from 192.168.1.50",
      "raw_data": {"distinct_ports": [22, 80, 443, ...], "port_count": 15},
      "tags": ["network", "scan", "port-scan"]
    }
  ]
}
```

### `GET /events/{id}`
Singolo evento. 404 se non in memoria.

### `GET /status`
Stato completo: queue, gateway, detectors, sniffer, rate limiter.

### `GET /metrics`
Prometheus text format.

---

## Plugin System

Aggiungi detector custom in `plugins/`:

```python
# plugins/my_detector.py
from src.core.event import Severity, new_event
from src.detectors.base import BaseDetector, register_detector

@register_detector
class MyDetector(BaseDetector):
    detector_name = "my_detector"

    async def process_packet(self, pkt):
        # Analizza il pacchetto scapy
        # ...
        await self.emit(new_event(
            detector_name=self.detector_name,
            severity=Severity.MEDIUM,
            source_ip="1.2.3.4",
            summary="Custom detection",
        ))
```

Il plugin viene caricato automaticamente all'avvio se `plugins.enabled: true`.

---

## Integrazione Hermes.Agent

Il servizio si connette al gateway Hermes via **WebSocket**.

### Configurazione

```yaml
hermes:
  base_url: ws://hermes-agent-host:8080
  publish_path: /ws/events
  api_key: your-key
```

### Punti TODO per integrazione completa

Nel file [`src/gateway/hermes_adapter.py`](src/gateway/hermes_adapter.py):

| TODO | Descrizione |
|---|---|
| `TODO-HERMES-1` | URL reale del WebSocket gateway |
| `TODO-HERMES-2` | Schema envelope del messaggio (se diverso da IDSEvent diretto) |
| `TODO-HERMES-3` | Autenticazione SDK-nativa Hermes |
| `TODO-HERMES-4` | Topic/channel routing se supportato |
| `TODO-HERMES-5` | Sostituzione con SDK Python ufficiale Hermes |

### Schema evento pubblicato

```json
{
  "id": "evt-abc123",
  "timestamp": "2026-05-27T10:00:00Z",
  "severity": "high",
  "source_ip": "192.168.1.50",
  "destination_ip": "192.168.1.1",
  "detector_name": "port_scan_detector",
  "summary": "Possible port scan detected",
  "raw_data": {"distinct_ports": [22, 80, 443], "port_count": 3},
  "tags": ["network", "scan"]
}
```

---

## Prometheus Metrics

| Metrica | Tipo | Descrizione |
|---|---|---|
| `ids_events_total` | Counter | Eventi per `detector` + `severity` |
| `ids_events_dropped_total` | Counter | Overflow queue |
| `ids_queue_depth` | Gauge | Profondità coda corrente |
| `ids_packets_captured_total` | Counter | Pacchetti catturati |
| `ids_gateway_publish_total` | Counter | Pubblicazioni per `outcome` (success/failure) |
| `ids_gateway_connected` | Gauge | 1=connesso, 0=disconnesso |
| `ids_rate_limiter_total` | Counter | Rate limiter per `decision` (allowed/rejected) |

---

## Test

```bash
# Tutti i test
pytest tests/ -v

# Con coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Solo un modulo
pytest tests/test_event.py -v
pytest tests/test_detectors.py -v
pytest tests/test_gateway.py -v
```

---

## Struttura del progetto

```
hermes/
├── src/
│   ├── core/           # Config, Event model, Queue, RateLimiter
│   ├── detectors/      # Detector engine + 5 detector built-in
│   ├── capture/        # PacketSniffer (scapy) + ARPPoller
│   ├── gateway/        # HermesGatewayAdapter + MockAdapter
│   ├── api/            # FastAPI routes + Prometheus metrics
│   └── main.py         # Entrypoint + orchestrazione
├── plugins/            # Detector custom (caricamento automatico)
├── tests/              # Test suite pytest
├── config/             # config.yaml + known_hosts.yaml
├── docker/             # Dockerfile + entrypoint + prometheus.yml
├── docker-compose.yml
└── README.md
```

---

## Roadmap evolutiva

### v0.2 — Detection avanzata
- `DNSTunnelDetector`: query DNS anomale (alto volume, payload grande)
- `ICMPFloodDetector`: ICMP flooding
- `SSHBruteForceDetector`: tracking sessioni SSH fallite
- Persistenza eventi su SQLite per storico oltre il ring buffer

### v0.3 — Analisi LLM
- Integrazione [Claude API](https://anthropic.com) per analisi contestuale degli eventi
- Correlazione multi-detector: "burst di port scan + ARP spoof = possibile pivot"
- Sommari intelligenti degli incidenti in linguaggio naturale

### v0.4 — Rule Engine
- Regole YAML per correlazione eventi: `IF [event_A] AND [event_B] WITHIN 30s → alert`
- Soppressione eventi ridondanti (deduplication)
- Whitelist temporali (es. "ignora scansioni da IP X in orario manutenzione")

### v0.5 — Dashboard e Alerting
- Board Grafana preconfigurato con panel IDS
- Integrazione alert su Slack/Teams/email
- Visualizzazione topologia di rete live

### v1.0 — Distributed Mode
- Multi-sensor: coordinamento tra istanze IDS su segmenti diversi
- Aggregazione centralizzata su Hermes.Agent
- Supporto IPv6

---

## Sicurezza

- Il servizio è pensato per essere eseguito su rete locale affidabile
- Le API REST non hanno autenticazione di default (aggiungere per produzione)
- L'API key Hermes non deve essere nel config.yaml → usare env `HERMES_API_KEY`
- In Docker: usare capabilities puntuali (`NET_RAW`) invece di `--privileged`
- Il file `known_hosts.yaml` non deve contenere dati sensibili

---

## Licenza

MIT — vedi LICENSE
