#!/usr/bin/env python3
"""
ids_mcp_server.py — MCP server per hermes-ids.

Espone le API IDS come tool nativi per il modello LLM via protocollo MCP
(JSON-RPC 2.0 su stdio). Nessun terminal, nessun curl: il modello chiama
direttamente get_events(), whitelist_add(), ecc.

Registrazione in Hermes (eseguire UNA VOLTA):
    Windows:  register_mcp.bat
    Linux:    bash register_mcp.sh

Variabili d'ambiente:
    IDS_BASE_URL         URL dell'API IDS    (default: http://localhost:8765)
    HERMES_REPORT_SECRET Secret webhook ids-report per send_report_now
    HERMES_GATEWAY_URL   URL del gateway     (default: http://127.0.0.1:8644)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

# ── Configurazione ─────────────────────────────────────────────────────────────
IDS_BASE     = os.environ.get("IDS_BASE_URL", "http://localhost:8765")
GW_BASE      = os.environ.get("HERMES_GATEWAY_URL", "http://127.0.0.1:8644")
RPT_SECRET   = os.environ.get("HERMES_REPORT_SECRET", "")
RPT_PATH     = "/webhooks/ids-report"

SEV_EMOJI    = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
SEV_ORDER    = ["critical", "high", "medium", "low", "info"]


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(path: str) -> Any:
    with urllib.request.urlopen(f"{IDS_BASE}{path}", timeout=5) as r:
        return json.loads(r.read())


def _post(path: str, body: dict) -> Any:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{IDS_BASE}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _put(path: str, body: dict) -> Any:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{IDS_BASE}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="PUT",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _delete(path: str) -> Any:
    req = urllib.request.Request(f"{IDS_BASE}{path}", method="DELETE")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _ids_unavailable(exc: Exception) -> str:
    return f"❌ IDS non raggiungibile su {IDS_BASE}\nErrore: {exc}\nAssicurati che hermes-ids sia avviato."


# ── Tool implementations ───────────────────────────────────────────────────────

def tool_get_events(limit: int = 20, severity: str | None = None,
                    detector: str | None = None) -> str:
    """Restituisce gli ultimi eventi IDS."""
    try:
        path = f"/events?limit={min(limit, 100)}"
        if severity:
            path += f"&severity={severity}"
        if detector:
            path += f"&detector={detector}"
        data   = _get(path)
        events = data.get("events", [])
    except Exception as e:
        return _ids_unavailable(e)

    if not events:
        return "✅ Nessun evento recente nell'IDS."

    counts: dict = {}
    for ev in events:
        s = ev.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    sev_line = "  ".join(
        f"{SEV_EMOJI.get(s,'?')}×{counts[s]}" for s in SEV_ORDER if s in counts
    )
    lines = [f"📋 Ultimi {len(events)} eventi IDS: {sev_line}", ""]

    for ev in events:
        sev  = ev.get("severity", "info")
        ts   = ev.get("timestamp", "")[:16].replace("T", " ")
        det  = ev.get("detector_name", "").replace("_detector", "")
        src  = ev.get("source_ip") or "?"
        summ = ev.get("summary", "")[:80]
        eid  = ev.get("id", "")[:12]
        lines.append(f"{SEV_EMOJI.get(sev,'?')} [{ts}] {det}")
        lines.append(f"   {src} — {summ}")
        lines.append(f"   event_id: {eid}")
        lines.append("")

    return "\n".join(lines).rstrip()


def tool_get_status() -> str:
    """Restituisce lo stato del servizio IDS."""
    try:
        health  = _get("/health")
        status  = _get("/status")
    except Exception as e:
        return _ids_unavailable(e)

    ok     = health.get("status") == "ok"
    icon   = "✅" if ok else "❌"
    dets   = status.get("detectors", [])
    q      = status.get("queue", {})

    lines = [
        f"{icon} IDS {'operativo' if ok else 'ERRORE'}",
        f"Detector attivi: {len(dets)}",
        f"Queue depth: {q.get('depth', 0)}  |  Dropped: {q.get('dropped', 0)}",
        "",
    ]
    for d in dets:
        name = d.get("name", "?").replace("_detector", "")
        en   = "✅" if d.get("enabled") else "⏸"
        lines.append(f"  {en} {name}")

    return "\n".join(lines)


def tool_whitelist_list() -> str:
    """Lista tutti gli host nella whitelist."""
    try:
        data = _get("/whitelist")
    except Exception as e:
        return _ids_unavailable(e)

    entries = data.get("entries", [])
    if not entries:
        return "📋 Whitelist vuota."

    lines = [f"📋 Whitelist — {len(entries)} host:"]
    for e in entries:
        ip   = e.get("ip", "?")
        desc = e.get("description", "")
        mac  = e.get("mac") or "qualsiasi"
        by   = e.get("added_by", "")
        lines.append(f"  ✅ {ip}  ({desc})  mac={mac}  by={by}")

    return "\n".join(lines)


def tool_whitelist_add(ip: str, description: str = "", mac: str = "") -> str:
    """Aggiunge un IP alla whitelist (non genererà più alert)."""
    if not ip:
        return "❌ Parametro 'ip' obbligatorio."
    try:
        body: dict = {"ip": ip, "description": description}
        if mac:
            body["mac"] = mac
        result = _post("/whitelist", body)
        entry  = result.get("entry", {})
        desc   = entry.get("description", description)
        return f"✅ {ip} aggiunto alla whitelist.\nDescrizione: {desc}\nMAC atteso: {entry.get('mac') or 'qualsiasi'}"
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode()
        return f"❌ Errore {e.code}: {body_txt[:200]}"
    except Exception as e:
        return _ids_unavailable(e)


def tool_whitelist_remove(ip: str, confirm: bool = False) -> str:
    """
    Rimuove un IP dalla whitelist. Richiede confirm=true per eseguire.
    ATTENZIONE: dopo la rimozione il dispositivo genererà nuovamente alert.
    """
    if not ip:
        return "❌ Parametro 'ip' obbligatorio."

    if not confirm:
        return (
            f"⚠️ CONFERMA RICHIESTA\n\n"
            f"Stai per rimuovere {ip} dalla whitelist.\n"
            f"Dopo la rimozione, questo dispositivo genererà nuovamente alert IDS.\n\n"
            f"Chiedi all'utente se è sicuro, poi richiama con confirm=true."
        )

    try:
        _delete(f"/whitelist/{ip}")
        return f"✅ {ip} rimosso dalla whitelist. Il prossimo pacchetto ARP da quell'IP genererà un alert."
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"❌ {ip} non trovato in whitelist."
        return f"❌ Errore {e.code}: {e.read().decode()[:200]}"
    except Exception as e:
        return _ids_unavailable(e)


def tool_whitelist_ack(event_id: str, description: str = "",
                       confirm: bool = False) -> str:
    """
    Aggiunge alla whitelist l'IP sorgente di un alert (ack).
    Richiede confirm=true per eseguire. Usa event_id dall'output di get_events.
    """
    if not event_id:
        return "❌ Parametro 'event_id' obbligatorio. Usa get_events() per ottenere l'ID."

    # Prima mostra i dettagli dell'evento senza conferma
    if not confirm:
        try:
            ev_data = _get(f"/events/{event_id}")
            src_ip  = ev_data.get("source_ip", "?")
            summary = ev_data.get("summary", "")
        except Exception:
            src_ip  = "?"
            summary = "(evento non trovato in memoria)"

        return (
            f"⚠️ CONFERMA RICHIESTA\n\n"
            f"Stai per aggiungere alla whitelist:\n"
            f"  IP: {src_ip}\n"
            f"  Evento: {summary}\n"
            f"  Descrizione whitelist: {description or '(da evento)'}\n\n"
            f"Dopo l'aggiunta, questo IP non genererà più alert.\n"
            f"Chiedi all'utente se è sicuro, poi richiama con confirm=true."
        )

    try:
        path = f"/whitelist/ack/{event_id}"
        if description:
            import urllib.parse
            path += f"?description={urllib.parse.quote(description)}"
        result = _post(path, {})
        entry  = result.get("entry", {})
        return (
            f"✅ Whitelist aggiornata dall'evento {event_id[:12]}.\n"
            f"IP: {entry.get('ip', '?')}\n"
            f"Descrizione: {entry.get('description', '')}\n"
            f"MAC atteso: {entry.get('mac') or 'qualsiasi'}"
        )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"❌ Evento {event_id[:12]} non trovato (potrebbe non essere più in memoria)."
        return f"❌ Errore {e.code}: {e.read().decode()[:200]}"
    except Exception as e:
        return _ids_unavailable(e)


def tool_whitelist_update(ip: str, description: str | None = None,
                          mac: str | None = None) -> str:
    """Aggiorna descrizione e/o MAC atteso di un host in whitelist."""
    if not ip:
        return "❌ Parametro 'ip' obbligatorio."
    try:
        body: dict = {}
        if description is not None:
            body["description"] = description
        if mac is not None:
            body["mac"] = mac
        result = _put(f"/whitelist/{ip}", body)
        entry  = result.get("entry", {})
        return f"✅ {ip} aggiornato.\nDescrizione: {entry.get('description','')}\nMAC: {entry.get('mac') or 'qualsiasi'}"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"❌ {ip} non trovato in whitelist."
        return f"❌ Errore {e.code}: {e.read().decode()[:200]}"
    except Exception as e:
        return _ids_unavailable(e)


def tool_send_report_now() -> str:
    """Invia subito un report IDS su Telegram (senza aspettare il timer)."""
    if not RPT_SECRET:
        return "❌ HERMES_REPORT_SECRET non configurato. Imposta la variabile d'ambiente."

    try:
        health  = _get("/health")
        status  = _get("/status")
        data    = _get("/events?limit=15")
        events  = data.get("events", [])
    except Exception as e:
        return _ids_unavailable(e)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%d/%m %H:%M UTC")
    ok  = health.get("status") == "ok"

    counts: dict = {}
    for ev in events:
        s = ev.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    sev_line = "  ".join(
        f"{SEV_EMOJI.get(s,'?')}×{counts[s]}" for s in SEV_ORDER if s in counts
    ) or "nessuno"

    msg_lines = [
        f"📊 IDS Report — {now}",
        f"{'✅' if ok else '❌'} Servizio OK  |  Ultimi {len(events)} eventi: {sev_line}",
        "─" * 26,
    ]
    for ev in events[:10]:
        sev  = ev.get("severity", "info")
        ts   = ev.get("timestamp", "")[:16].replace("T"," ")
        det  = ev.get("detector_name","").replace("_detector","")
        src  = ev.get("source_ip") or "?"
        summ = ev.get("summary","")[:60]
        msg_lines.append(f"{SEV_EMOJI.get(sev,'?')} [{ts[5:]}] {det}")
        msg_lines.append(f"   {src} — {summ}")

    message = "\n".join(msg_lines)
    body    = json.dumps({"message": message}).encode()
    sig     = hmac.new(RPT_SECRET.encode(), body, hashlib.sha256).hexdigest()
    req     = urllib.request.Request(
        f"{GW_BASE}{RPT_PATH}", data=body,
        headers={"Content-Type": "application/json",
                 "X-Hub-Signature-256": f"sha256={sig}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status in (200, 201, 202, 204):
                return f"✅ Report inviato su Telegram ({len(events)} eventi)."
            return f"❌ Webhook HTTP {r.status}"
    except Exception as e:
        return f"❌ Invio fallito: {e}"


# ── Tool definitions (schema MCP) ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "get_events",
        "description": "Recupera gli ultimi eventi rilevati dall'IDS. Usalo per 'ci sono eventi?', 'ultimi alert', 'cosa è successo sulla rete'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit":    {"type": "integer", "description": "Numero massimo di eventi (default 20, max 100)", "default": 20},
                "severity": {"type": "string",  "description": "Filtra per severity: critical | high | medium | low"},
                "detector": {"type": "string",  "description": "Filtra per detector: port_scan_detector | new_host_detector | arp_spoof_detector | traffic_volume_detector | sensitive_ports_detector"},
            },
        },
    },
    {
        "name": "get_status",
        "description": "Restituisce lo stato del servizio IDS: health, detector attivi, queue. Usalo per 'IDS funziona?', 'stato IDS'.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "whitelist_list",
        "description": "Lista tutti gli host nella whitelist (host fidati che non generano alert).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "whitelist_add",
        "description": "Aggiunge un IP alla whitelist. L'host non genererà più alert. NON richiede conferma.",
        "inputSchema": {
            "type": "object",
            "required": ["ip"],
            "properties": {
                "ip":          {"type": "string", "description": "Indirizzo IPv4"},
                "description": {"type": "string", "description": "Nome/descrizione del dispositivo"},
                "mac":         {"type": "string", "description": "MAC address atteso (opzionale, es. aa:bb:cc:dd:ee:ff)"},
            },
        },
    },
    {
        "name": "whitelist_remove",
        "description": "Rimuove un IP dalla whitelist. RICHIEDE CONFERMA: chiama prima senza confirm per mostrare avvertimento, poi con confirm=true dopo approvazione utente.",
        "inputSchema": {
            "type": "object",
            "required": ["ip"],
            "properties": {
                "ip":      {"type": "string",  "description": "Indirizzo IPv4 da rimuovere"},
                "confirm": {"type": "boolean", "description": "Impostare true SOLO dopo che l'utente ha confermato", "default": False},
            },
        },
    },
    {
        "name": "whitelist_ack",
        "description": "Aggiunge alla whitelist l'IP sorgente di un alert. RICHIEDE CONFERMA. Ottieni event_id da get_events.",
        "inputSchema": {
            "type": "object",
            "required": ["event_id"],
            "properties": {
                "event_id":    {"type": "string",  "description": "ID dell'evento (da get_events)"},
                "description": {"type": "string",  "description": "Descrizione da assegnare all'host"},
                "confirm":     {"type": "boolean", "description": "Impostare true SOLO dopo che l'utente ha confermato", "default": False},
            },
        },
    },
    {
        "name": "whitelist_update",
        "description": "Aggiorna descrizione o MAC atteso di un host già in whitelist.",
        "inputSchema": {
            "type": "object",
            "required": ["ip"],
            "properties": {
                "ip":          {"type": "string", "description": "Indirizzo IPv4"},
                "description": {"type": "string", "description": "Nuova descrizione"},
                "mac":         {"type": "string", "description": "Nuovo MAC atteso. Passa stringa vuota '' per accettare qualsiasi MAC."},
            },
        },
    },
    {
        "name": "send_report_now",
        "description": "Invia immediatamente un report IDS su Telegram senza aspettare il timer automatico.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ── Tool dispatcher ─────────────────────────────────────────────────────────────

_TOOL_MAP = {
    "get_events":       tool_get_events,
    "get_status":       tool_get_status,
    "whitelist_list":   tool_whitelist_list,
    "whitelist_add":    tool_whitelist_add,
    "whitelist_remove": tool_whitelist_remove,
    "whitelist_ack":    tool_whitelist_ack,
    "whitelist_update": tool_whitelist_update,
    "send_report_now":  tool_send_report_now,
}


def call_tool(name: str, args: dict) -> str:
    fn = _TOOL_MAP.get(name)
    if fn is None:
        return f"❌ Tool '{name}' non trovato."
    try:
        return fn(**{k: v for k, v in args.items() if v is not None})
    except TypeError as e:
        return f"❌ Parametri non validi: {e}"
    except Exception as e:
        return f"❌ Errore interno: {e}"


# ── MCP Protocol (JSON-RPC 2.0 su stdio) ───────────────────────────────────────

def _reply(req_id: Any, result: Any) -> None:
    msg = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def _error_reply(req_id: Any, code: int, message: str) -> None:
    msg = json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def handle_message(raw: str) -> None:
    try:
        req = json.loads(raw)
    except json.JSONDecodeError:
        return

    method  = req.get("method", "")
    req_id  = req.get("id")
    params  = req.get("params", {}) or {}

    # Notification (no id, no response)
    if req_id is None:
        return

    if method == "initialize":
        _reply(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities":    {"tools": {}},
            "serverInfo":      {"name": "hermes-ids", "version": "0.1.0"},
        })

    elif method == "tools/list":
        _reply(req_id, {"tools": TOOLS})

    elif method == "tools/call":
        name   = params.get("name", "")
        args   = params.get("arguments", {}) or {}
        result = call_tool(name, args)
        _reply(req_id, {"content": [{"type": "text", "text": result}]})

    elif method == "ping":
        _reply(req_id, {})

    else:
        _error_reply(req_id, -32601, f"Method not found: {method}")


def main() -> None:
    # Redirecta stderr su file per evitare interferenze con il protocollo stdio
    log_path = os.environ.get("MCP_LOG_FILE", os.devnull)
    sys.stderr = open(log_path, "a", encoding="utf-8")

    for line in sys.stdin:
        line = line.strip()
        if line:
            handle_message(line)


if __name__ == "__main__":
    main()
