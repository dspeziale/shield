#!/usr/bin/env python3
"""
ids_report.py — Query IDS e invia report diretto su Telegram via webhook ids-report.

Non richiede LLM: lo script legge l'API locale e invia il testo formattato
direttamente a Telegram tramite il webhook Hermes con deliver_only=true.

Uso:
    python ids_report.py               # ultimi 20 eventi
    python ids_report.py --limit 50    # ultimi 50 eventi
    python ids_report.py --severity high    # solo high/critical
    python ids_report.py --health-only      # solo stato servizio
"""
import argparse
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

# ── Configurazione ─────────────────────────────────────────────────────────────

IDS_BASE     = "http://localhost:8765"
WEBHOOK_URL  = "http://127.0.0.1:8644/webhooks/ids-report"
SECRET       = "dwANZTla_goOHfAXrk_Sb66qcw8zd1HCvuZidq3fO1c"

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# ── HTTP helpers (stdlib only, no deps) ────────────────────────────────────────

def _get(path: str) -> dict:
    url = f"{IDS_BASE}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        raise ConnectionError(f"IDS non raggiungibile su {IDS_BASE}: {e.reason}") from e


def _post_to_telegram(message: str) -> bool:
    """Manda messaggio direttamente su Telegram via webhook ids-report."""
    body = json.dumps({"message": message}).encode("utf-8")
    sig  = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    req  = urllib.request.Request(
        WEBHOOK_URL,
        data=body,
        headers={
            "Content-Type":        "application/json",
            "X-Hub-Signature-256": f"sha256={sig}",
            "User-Agent":          "hermes-ids-report/0.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 201, 202, 204)
    except urllib.error.HTTPError as e:
        print(f"[ERROR] Webhook HTTP {e.code}: {e.read()[:200]}", file=sys.stderr)
        return False
    except urllib.error.URLError as e:
        print(f"[ERROR] Webhook non raggiungibile: {e.reason}", file=sys.stderr)
        return False


# ── Formattazione ──────────────────────────────────────────────────────────────

def _sev_emoji(s: str) -> str:
    return SEVERITY_EMOJI.get(s.lower(), "⚪")


def _format_report(events: list, status: dict, health: dict) -> str:
    now  = datetime.now(timezone.utc).strftime("%d/%m %H:%M UTC")
    ids_ok = health.get("status") == "ok"
    status_icon = "✅" if ids_ok else "❌"

    # Contatori per severity
    counts: dict = {}
    for ev in events:
        s = ev.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    sev_line = "  ".join(
        f"{_sev_emoji(s)}×{counts[s]}"
        for s in SEV_ORDER
        if s in counts
    ) or "nessuno"

    # Detectors attivi
    dets = status.get("detectors", [])
    det_names = ", ".join(d.get("name", "?").replace("_detector", "") for d in dets) if dets else "—"

    lines = [
        f"📊 *IDS Report* — {now}",
        f"{status_icon} Servizio: {'OK' if ids_ok else 'ERRORE'}  |  Detector: {len(dets)}",
        f"Ultimi {len(events)} eventi: {sev_line}",
        "─" * 28,
    ]

    if not events:
        lines.append("  (nessun evento recente)")
    else:
        for ev in events[:15]:
            sev  = ev.get("severity", "info")
            ts   = ev.get("timestamp", "")[:16].replace("T", " ")
            det  = ev.get("detector_name", "").replace("_detector", "")
            src  = ev.get("source_ip") or "?"
            summ = ev.get("summary", "")[:70]
            lines.append(f"{_sev_emoji(sev)} [{ts[5:]}] {det}")
            lines.append(f"   {src} — {summ}")

        if len(events) > 15:
            lines.append(f"  … +{len(events) - 15} altri (usa --limit per vedere di più)")

    return "\n".join(lines)


def _format_health_only(health: dict, status: dict) -> str:
    now     = datetime.now(timezone.utc).strftime("%d/%m %H:%M UTC")
    ids_ok  = health.get("status") == "ok"
    icon    = "✅" if ids_ok else "❌"
    dets    = status.get("detectors", [])
    q_depth = status.get("queue", {}).get("depth", 0)
    gw      = status.get("gateway", {}).get("status", "unknown")

    lines = [
        f"🛡 *IDS Status* — {now}",
        f"{icon} Servizio: {'OK' if ids_ok else 'ERRORE'}",
        f"Detector attivi: {len(dets)}",
        f"Queue depth: {q_depth}",
        f"Gateway: {gw}",
    ]
    for d in dets:
        name = d.get("name", "?").replace("_detector", "")
        ok   = "✅" if d.get("enabled") else "⏸"
        lines.append(f"  {ok} {name}")
    return "\n".join(lines)


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="IDS report → Telegram")
    parser.add_argument("--limit",       type=int,  default=20,    help="Numero max eventi (default 20)")
    parser.add_argument("--severity",    default=None,              help="Filtra per severity: critical|high|medium|low")
    parser.add_argument("--health-only", action="store_true",       help="Solo stato servizio, nessun evento")
    parser.add_argument("--dry-run",     action="store_true",       help="Stampa su stdout senza inviare")
    args = parser.parse_args()

    # Raccoglie dati dall'IDS
    try:
        health = _get("/health")
        status = _get("/status")
    except ConnectionError as e:
        msg = f"⚠️ IDS non raggiungibile\n{e}"
        print(msg, file=sys.stderr)
        if not args.dry_run:
            _post_to_telegram(msg)
        return 1

    if args.health_only:
        msg = _format_health_only(health, status)
    else:
        path = f"/events?limit={args.limit}"
        if args.severity:
            path += f"&severity={args.severity}"
        try:
            data   = _get(path)
            events = data.get("events", [])
        except ConnectionError as e:
            events = []
        msg = _format_report(events, status, health)

    if args.dry_run:
        print(msg)
        return 0

    ok = _post_to_telegram(msg)
    if ok:
        events_shown = 0 if args.health_only else len(data.get("events", []))
        print(f"✅ Report inviato a Telegram  ({events_shown} eventi)")
        return 0
    else:
        print("❌ Invio fallito — controlla che il gateway Hermes sia attivo", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
