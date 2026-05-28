#!/usr/bin/env bash
# ============================================================
#  install.sh — Installa hermes-ids su un nuovo PC Linux
#  Uso: bash install.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
err()  { echo -e "${RED}✗${NC} $*"; exit 1; }

echo ""
echo "  ============================================"
echo "   hermes-ids — Installazione"
echo "  ============================================"
echo ""

# ── 1. Verifica Docker ───────────────────────────────────────
if command -v docker &>/dev/null; then
    ok "Docker trovato: $(docker --version)"
else
    warn "Docker non trovato. Installo..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    ok "Docker installato. RIAVVIA la sessione o lancia: newgrp docker"
fi

# ── 2. Verifica Docker Compose ───────────────────────────────
if docker compose version &>/dev/null 2>&1; then
    ok "Docker Compose trovato"
elif command -v docker-compose &>/dev/null; then
    ok "docker-compose trovato (legacy)"
else
    warn "Installo Docker Compose plugin..."
    sudo apt-get install -y docker-compose-plugin 2>/dev/null || \
    sudo yum install -y docker-compose-plugin 2>/dev/null || \
    warn "Installa manualmente: https://docs.docker.com/compose/install/"
fi

# ── 3. Crea .env se non esiste ───────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    warn ".env creato da .env.example. Devi configurarlo prima di avviare!"
    echo ""
    echo "  Modifica .env con i tuoi valori:"
    echo ""

    # Rileva interfacce disponibili
    echo "  Interfacce di rete disponibili:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "    " $2}' | grep -v lo
    echo ""

    echo "  Campi obbligatori in .env:"
    echo "    CAPTURE_INTERFACE    = interfaccia da monitorare (es. eth0)"
    echo "    HERMES_EVENTS_SECRET = campo 'secret' voce 'ids-events'"
    echo "    HERMES_REPORT_SECRET = campo 'secret' voce 'ids-report'"
    echo ""
    echo "  Dove trovare i secret:"
    echo "    Apri questo file sul PC Windows dove gira Hermes:"
    echo ""
    echo "      C:\\Users\\<utente>\\AppData\\Local\\hermes\\webhook_subscriptions.json"
    echo ""
    echo "    Esempio percorso completo:"
    echo "      C:\\Users\\marco.bellomo\\AppData\\Local\\hermes\\webhook_subscriptions.json"
    echo ""
    echo "    Struttura del file:"
    echo "      {"
    echo "        \"ids-events\": { \"secret\": \"<-- HERMES_EVENTS_SECRET\" },"
    echo "        \"ids-report\": { \"secret\": \"<-- HERMES_REPORT_SECRET\" }"
    echo "      }"
    echo ""
    echo "  Poi lancia: bash install.sh"
    exit 0
fi

ok ".env trovato"

# ── 4. Verifica campi obbligatori in .env ────────────────────
source .env 2>/dev/null || true

if [ -z "${HERMES_EVENTS_SECRET:-}" ]; then
    err "HERMES_EVENTS_SECRET non impostato in .env"
fi
if [ -z "${HERMES_REPORT_SECRET:-}" ]; then
    err "HERMES_REPORT_SECRET non impostato in .env"
fi
if [ -z "${CAPTURE_INTERFACE:-}" ]; then
    err "CAPTURE_INTERFACE non impostato in .env"
fi

ok "Configurazione .env valida"

# ── 5. Crea directory ────────────────────────────────────────
mkdir -p config data logs
ok "Directory create: config/ data/ logs/"

# ── 6. known_hosts.yaml ──────────────────────────────────────
if [ ! -f config/known_hosts.yaml ]; then
    cat > config/known_hosts.yaml << 'YAML'
# ============================================================
#  known_hosts.yaml — Host noti sulla LAN (whitelist)
#  Aggiungi i dispositivi fidati per evitare falsi positivi.
#  Gestibile anche via API: POST http://localhost:8765/whitelist
# ============================================================
known_hosts: []
YAML
    ok "config/known_hosts.yaml creato (vuoto)"
fi

# ── 7. Build immagine Docker ─────────────────────────────────
echo ""
echo "Build immagine Docker..."
docker compose build --no-cache
ok "Immagine hermes-ids costruita"

# ── 8. Avvio ─────────────────────────────────────────────────
echo ""
echo "Avvio servizio..."
docker compose up -d
ok "hermes-ids avviato!"

# ── 9. Health check ──────────────────────────────────────────
echo ""
echo "Attendo startup (15s)..."
sleep 15

if curl -sf http://localhost:8765/health | grep -q '"status"'; then
    ok "API raggiungibile: http://localhost:8765"
else
    warn "API non ancora risponde — attendi qualche secondo e riprova:"
    echo "  curl http://localhost:8765/health"
fi

echo ""
echo "  ============================================"
echo "   hermes-ids installato e avviato!"
echo "  ============================================"
echo ""
echo "  Comandi utili:"
echo "    docker compose logs -f          # log in tempo reale"
echo "    docker compose ps               # stato servizio"
echo "    docker compose restart          # riavvia"
echo "    docker compose down             # ferma"
echo "    docker compose up -d --build    # aggiorna e riavvia"
echo ""
echo "  API locale:"
echo "    curl http://localhost:8765/health"
echo "    curl http://localhost:8765/events"
echo "    curl http://localhost:8765/whitelist"
echo ""
