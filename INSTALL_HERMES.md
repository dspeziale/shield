# 🔗 Guida: Installare hermes-ids dal CLI di Hermes.Agent

Questa guida spiega come integrare il servizio **hermes-ids** con
**Hermes.Agent v0.13+** usando il CLI ufficiale `hermes`.

---

## Come funziona l'integrazione

```
┌──────────────┐   HTTP POST    ┌──────────────────────┐
│  hermes-ids  │ ─────────────► │  Hermes.Agent        │
│  (porta 8765)│  /webhooks/    │  webhook gateway     │
│              │  ids-events    │  (porta 8644)        │
└──────────────┘                └──────────┬───────────┘
                                           │
                                    agent analysis
                                           │
                             ┌─────────────▼──────────┐
                             │  Telegram / Discord    │
                             │  (notifiche real-time) │
                             └────────────────────────┘
```

Ogni evento IDS (port scan, nuovo host, ARP spoof, ecc.) viene:
1. Rilevato da hermes-ids
2. Inviato come HTTP POST al webhook di Hermes.Agent
3. Processato dall'agente LLM (analisi contestuale opzionale)
4. Notificato su Telegram / Discord / altro canale configurato

---

## Prerequisiti

- Hermes.Agent ≥ v0.13 installato e funzionante
- `hermes status` mostra il gateway come *running*
- Python 3.11+ con `pip`
- **Windows**: [Npcap](https://npcap.com) installato (per packet capture)
- **Linux/macOS**: permessi `NET_RAW` o esecuzione come root

Verifica versione Hermes:
```
hermes --version
# Hermes Agent v0.13.0 (2026.5.7)
```

---

## Step 1 — Abilita la piattaforma webhook in Hermes

Il webhook permette a servizi esterni (come hermes-ids) di inviare eventi
al gateway di Hermes.

```bash
hermes config set platforms.webhook.enabled true
hermes config set platforms.webhook.extra.host "127.0.0.1"
hermes config set platforms.webhook.extra.port 8644
```

Oppure edita direttamente il file di configurazione:
```bash
hermes config edit
```

Aggiungi sotto `platforms:`:
```yaml
platforms:
  webhook:
    enabled: true
    extra:
      host: "127.0.0.1"
      port: 8644
      secret: ""          # opzionale — verrà generato auto al restart
```

Riavvia il gateway per applicare la modifica:
```bash
hermes gateway restart
```

Verifica che il webhook sia attivo:
```bash
hermes webhook list
# → dovrebbe mostrare la piattaforma webhook come enabled
```

---

## Step 2 — Registra la subscription per gli eventi IDS

Crea il webhook che riceverà gli eventi da hermes-ids:

```bash
hermes webhook subscribe ids-events \
  --prompt "🚨 IDS Alert [{severity}] {summary} — sorgente: {source_ip} — detector: {detector_name}" \
  --description "Riceve eventi di sicurezza dall'IDS locale hermes-ids" \
  --deliver telegram
```

**Parametri chiave:**
- `ids-events` — nome del route (l'URL sarà `/webhooks/ids-events`)
- `--prompt` — template del messaggio inviato all'agente/Telegram
  - `{severity}`, `{summary}`, `{source_ip}`, `{detector_name}` sono
    campi del payload IDS
- `--deliver telegram` — notifica su Telegram (rimuovi se non configurato)

**Varianti:**

Solo log (nessuna notifica, utile per test):
```bash
hermes webhook subscribe ids-events \
  --prompt "IDS [{severity}] {summary} from {source_ip}" \
  --deliver log
```

Con analisi LLM completa (l'agente valuta ogni evento):
```bash
hermes webhook subscribe ids-events \
  --prompt "Analizza questo evento IDS e dimmi se è un falso positivo o una minaccia reale: [{severity}] {summary} da {source_ip}. Detector: {detector_name}. Tags: {tags}" \
  --deliver telegram
```

Solo delivery diretta senza LLM (più veloce, zero costo):
```bash
hermes webhook subscribe ids-events \
  --prompt "🚨 [{severity}] {summary} — {source_ip} → {destination_ip}" \
  --deliver telegram \
  --deliver-only
```

Verifica la registrazione:
```bash
hermes webhook list
# ids-events   GET/POST /webhooks/ids-events   → telegram
```

---

## Step 3 — Installa le dipendenze Python di hermes-ids

```bash
cd C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes

# (Consigliato) Ambiente virtuale
python -m venv .venv
.venv\Scripts\activate

# Installa dipendenze
pip install -r requirements.txt
```

---

## Step 4 — Configura hermes-ids per Hermes.Agent

Edita [`config/config.yaml`](config/config.yaml) — sezione `hermes`:

```yaml
hermes:
  enabled: true
  adapter: webhook                        # ← usa HTTP webhook (non websocket)
  base_url: "http://127.0.0.1:8644"      # porta del gateway Hermes
  publish_path: "/webhooks/ids-events"   # nome del route registrato al Step 2
  api_key: ""                             # se hai configurato un secret webhook
  timeout_seconds: 10
  retry:
    max_attempts: 5
    min_wait_seconds: 1
    max_wait_seconds: 30
    multiplier: 2.0
  reconnect:
    enabled: true
    interval_seconds: 15
```

Oppure usa variabili d'ambiente (copia `.env.example` in `.env`):
```env
HERMES_BASE_URL=http://127.0.0.1:8644
```

---

## Step 5 — Personalizza known_hosts (opzionale)

Aggiungi gli host noti della tua LAN in [`config/known_hosts.yaml`](config/known_hosts.yaml)
per evitare falsi positivi dal `NewHostDetector`:

```yaml
known_hosts:
  - ip: 192.168.1.1
    mac: "xx:xx:xx:xx:xx:xx"
    description: "Router"
  - ip: 192.168.1.10
    mac: "yy:yy:yy:yy:yy:yy"
    description: "Il mio PC"
```

---

## Step 6 — Avvia hermes-ids

### Windows (richiede Npcap + Run as Administrator per packet capture)

```bash
# Avvio normale (sniffing reale — richiede Npcap + admin)
python -m src.main --config config/config.yaml

# Avvio in modalità mock (nessun Npcap, nessun admin — per test)
python -m src.main --config config/config.yaml --mock-capture
```

### Linux / macOS

```bash
# Con sudo (packet capture)
sudo python -m src.main --config config/config.yaml

# Con capabilities (senza sudo)
sudo setcap cap_net_raw+ep $(which python3)
python -m src.main --config config/config.yaml
```

### Docker (raccomandato per Linux)

```bash
docker compose up --build
```

---

## Step 7 — Verifica l'integrazione

### 7a. Testa il webhook manualmente

```bash
# Invia un evento di test al webhook Hermes
hermes webhook test ids-events \
  --payload '{"severity":"high","summary":"Test IDS alert","source_ip":"192.168.1.99","detector_name":"test","destination_ip":"192.168.1.1","tags":"test, network","event_id":"evt-test-001","timestamp":"2026-05-27T10:00:00Z"}'
```

Dovresti ricevere la notifica su Telegram/Discord con il messaggio dal template.

### 7b. Controlla l'API REST di hermes-ids

```bash
# Stato generale
curl http://localhost:8765/health
curl http://localhost:8765/status

# Ultimi eventi rilevati
curl http://localhost:8765/events

# Solo eventi HIGH o CRITICAL
curl "http://localhost:8765/events?severity=high"
curl "http://localhost:8765/events?severity=critical"

# Per detector specifico
curl "http://localhost:8765/events?detector=arp_spoof_detector"
```

### 7c. Controlla le metriche Prometheus

```bash
curl http://localhost:9090/metrics | grep ids_
```

Output atteso:
```
ids_events_total{detector="port_scan_detector",severity="high"} 3.0
ids_gateway_publish_total{outcome="success"} 3.0
ids_gateway_connected 1.0
ids_packets_captured_total 12847.0
```

---

## Step 8 — Imposta hermes-ids come cron Hermes (opzionale)

Per ricevere un **report periodico** degli eventi IDS su Telegram (es. ogni ora):

```bash
hermes cron create "1h" \
  --name "ids-hourly-report" \
  --deliver telegram \
  "Interroga l'API REST all'indirizzo http://localhost:8765/events e fornisci un sommario degli ultimi eventi IDS degli ultimi 60 minuti. Raggruppa per severity e detector. Se ci sono eventi CRITICAL o HIGH segnalali chiaramente."
```

Per un check ogni 15 minuti solo se ci sono eventi critici:
```bash
hermes cron create "15m" \
  --name "ids-critical-check" \
  --deliver telegram \
  --no-agent \
  --script "scripts/ids_critical_check.py"
```

Crea lo script `~/.hermes/scripts/ids_critical_check.py` (o nella dir Hermes):

```python
#!/usr/bin/env python3
"""Script per hermes cron --no-agent: stampa solo se ci sono eventi critici."""
import urllib.request, json, sys

try:
    with urllib.request.urlopen("http://localhost:8765/events?severity=critical&limit=10") as r:
        data = json.loads(r.read())
    
    if data["total"] > 0:
        events = data["events"][:5]
        lines = [f"🚨 {data['total']} CRITICAL IDS event(s) in the last hour:"]
        for e in events:
            lines.append(f"  • [{e['detector_name']}] {e['summary']} — {e['source_ip']}")
        print("\n".join(lines))
    # Se total=0, nessun output → hermes --no-agent non invia nulla
except Exception as ex:
    print(f"IDS API unreachable: {ex}")
```

---

## Avvio automatico con il gateway Hermes (Windows)

Per avviare hermes-ids insieme a Hermes.Agent usando gli **hook** di Hermes,
aggiungi un hook `gateway:start` nel config:

```yaml
# C:\Users\marco.bellomo\AppData\Local\hermes\config.yaml
hooks:
  gateway:start:
    - cmd: >
        cmd /c start /min "hermes-ids"
        python -m src.main
        --config C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes\config\config.yaml
      workdir: C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes
      timeout: 5
      background: true
```

Poi riavvia il gateway:
```bash
hermes gateway restart
```

Hermes lancerà hermes-ids automaticamente ad ogni avvio del gateway.

Verifica che l'hook sia registrato:
```bash
hermes hooks list
```

---

## Troubleshooting

### ❌ Il webhook non riceve gli eventi

```bash
# 1. Controlla che il gateway Hermes sia running
hermes gateway status

# 2. Controlla che la piattaforma webhook sia abilitata
hermes webhook list

# 3. Testa il webhook direttamente
hermes webhook test ids-events --payload '{"severity":"low","summary":"ping","source_ip":"1.2.3.4","detector_name":"test"}'

# 4. Controlla i log di Hermes
hermes logs --tail 50 --filter gateway
```

### ❌ hermes-ids non si connette al webhook

```bash
# Verifica che la porta 8644 sia in ascolto
netstat -an | findstr "8644"

# Testa il POST manualmente
curl -X POST http://127.0.0.1:8644/webhooks/ids-events \
  -H "Content-Type: application/json" \
  -d '{"severity":"test","summary":"hello","source_ip":"127.0.0.1","detector_name":"test"}'
```

### ❌ Scapy / Npcap non funziona su Windows

```bash
# 1. Scarica e installa Npcap da https://npcap.com
# 2. Verifica che Npcap sia installato
python -c "from scapy.all import get_if_list; print(get_if_list())"

# 3. Esegui come Amministratore oppure usa mock mode per test
python -m src.main --config config/config.yaml --mock-capture
```

### ❌ Troppi falsi positivi

Aggiusta le soglie in `config/config.yaml`:
```yaml
detectors:
  port_scan:
    min_ports: 20          # aumenta la soglia (default 10)
    window_seconds: 5      # riduci la finestra
  sensitive_ports:
    min_attempts: 10       # più tentativi prima di alertare
  traffic_volume:
    threshold_pps: 10000   # soglia più alta
```

---

## Riepilogo comandi CLI Hermes

```bash
# Setup webhook (una sola volta)
hermes config set platforms.webhook.enabled true
hermes config set platforms.webhook.extra.host "127.0.0.1"
hermes config set platforms.webhook.extra.port 8644
hermes gateway restart

# Registra subscription eventi IDS
hermes webhook subscribe ids-events \
  --prompt "🚨 IDS [{severity}] {summary} — {source_ip}" \
  --deliver telegram \
  --deliver-only

# Verifica
hermes webhook list
hermes webhook test ids-events \
  --payload '{"severity":"high","summary":"Test","source_ip":"192.168.1.99","detector_name":"port_scan_detector","destination_ip":"192.168.1.1","tags":"test","event_id":"evt-001","timestamp":"2026-05-27T10:00:00Z"}'

# Cron report orario (opzionale)
hermes cron create "1h" --name "ids-hourly-report" --deliver telegram \
  "Controlla http://localhost:8765/events e riassumi gli ultimi eventi IDS."

# Avvia hermes-ids
python -m src.main --config config/config.yaml

# Stato e log
hermes gateway status
curl http://localhost:8765/status
hermes logs --tail 100
```
