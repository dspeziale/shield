#!/usr/bin/env bash
# ============================================================
#  register_mcp.sh — Registra hermes-ids come MCP server in Hermes
#  Eseguire UNA VOLTA dopo aver installato hermes-ids.
#
#  Uso: bash register_mcp.sh
#
#  Il MCP server viene eseguito nel container Docker hermes-ids.
#  Hermes parlerà con esso via stdin/stdout.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
err()  { echo -e "${RED}✗${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Carica .env se esiste ────────────────────────────────────
if [ -f "$SCRIPT_DIR/.env" ]; then
    # shellcheck disable=SC1091
    set -o allexport
    source "$SCRIPT_DIR/.env"
    set +o allexport
    ok ".env caricato"
fi

# ── Valori con default ────────────────────────────────────────
IDS_BASE_URL="${IDS_BASE_URL:-http://localhost:8765}"
HERMES_GATEWAY_URL="${HERMES_GATEWAY_URL:-http://127.0.0.1:8644}"
HERMES_REPORT_SECRET="${HERMES_REPORT_SECRET:-}"

echo ""
echo "  ============================================"
echo "   Registrazione MCP server hermes-ids"
echo "  ============================================"
echo ""

# ── Modalità: container o locale ─────────────────────────────
# Se hermes-ids è in Docker, eseguiamo il MCP server dentro il container.
# Se è locale (sviluppo), usiamo python direttamente.

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "hermes-ids"; then
    # Il container è in esecuzione — usa docker exec
    MCP_COMMAND="docker"
    MCP_ARGS="exec -i hermes-ids python /app/ids_mcp_server.py"
    echo "  Modalità: Docker (container hermes-ids)"
elif command -v python3 &>/dev/null && [ -f "$SCRIPT_DIR/ids_mcp_server.py" ]; then
    # Locale — usa python3
    MCP_COMMAND="python3"
    MCP_ARGS="$SCRIPT_DIR/ids_mcp_server.py"
    echo "  Modalità: Python locale"
else
    err "Nessun container hermes-ids attivo e Python non trovato. Avvia il container prima."
fi

echo "  IDS URL: $IDS_BASE_URL"
echo "  Gateway: $HERMES_GATEWAY_URL"
echo ""

# ── Verifica hermes CLI ────────────────────────────────────────
if ! command -v hermes &>/dev/null; then
    err "Hermes CLI non trovato. Installalo prima di continuare."
fi

# ── Registra in Hermes ────────────────────────────────────────
hermes mcp add hermes-ids \
    --command "$MCP_COMMAND" \
    --args "$MCP_ARGS" \
    --env "IDS_BASE_URL=$IDS_BASE_URL" \
    --env "HERMES_GATEWAY_URL=$HERMES_GATEWAY_URL" \
    --env "HERMES_REPORT_SECRET=$HERMES_REPORT_SECRET"

echo ""
ok "MCP server hermes-ids registrato!"
echo ""
echo "  Riavvia Hermes per attivare il server MCP."
echo "  Poi chiedi all'agent: 'mostrami gli ultimi eventi IDS'"
echo ""
