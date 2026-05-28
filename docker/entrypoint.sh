#!/bin/sh
# ============================================================
#  entrypoint.sh — Docker entrypoint per hermes-ids
# ============================================================

set -e

echo "Starting Hermes-IDS v0.1.0"
echo "Interface: ${CAPTURE_INTERFACE:-auto}"
echo "Log level: ${LOG_LEVEL:-INFO}"

# Attendi che Hermes sia disponibile (se configurato)
if [ -n "$HERMES_BASE_URL" ]; then
    echo "Waiting for Hermes gateway at $HERMES_BASE_URL..."
    # Retry semplice
    MAX_RETRIES=10
    i=0
    while [ $i -lt $MAX_RETRIES ]; do
        # Prova connessione WebSocket (solo TCP handshake)
        if nc -z "$(echo $HERMES_BASE_URL | sed 's|ws://||' | cut -d: -f1)" \
               "$(echo $HERMES_BASE_URL | sed 's|ws://||' | cut -d: -f2 | cut -d/ -f1)" 2>/dev/null; then
            echo "Hermes gateway reachable"
            break
        fi
        i=$((i+1))
        echo "Retry $i/$MAX_RETRIES..."
        sleep 2
    done
fi

# Avvia il servizio
exec python -m src.main "$@"
