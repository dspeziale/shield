#Requires -Version 5.1
<#
.SYNOPSIS
    install.ps1 — Installa hermes-ids su Windows con Docker Desktop.

.DESCRIPTION
    Script PowerShell per installazione guidata di hermes-ids su Windows.
    Controlla i prerequisiti, configura .env, costruisce il container Docker,
    avvia il servizio e registra il server MCP in Hermes.

.EXAMPLE
    # Esegui come utente normale (NON come Administrator)
    .\install.ps1

    # Se PowerShell blocca l'esecuzione:
    powershell -ExecutionPolicy Bypass -File .\install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Ok   { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "  [KO] $msg" -ForegroundColor Red; exit 1 }
function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host "   hermes-ids — Installazione Windows"         -ForegroundColor Cyan
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Verifica Docker Desktop ───────────────────────────────────────────────
Write-Step "Verifica Docker Desktop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Warn "Docker non trovato."
    Write-Host ""
    Write-Host "  Installa Docker Desktop da: https://www.docker.com/products/docker-desktop/"
    Write-Host "  Dopo l'installazione riavvia il PC e riesegui questo script."
    Write-Host ""
    exit 1
}

try {
    $dockerVersion = docker --version 2>&1
    Write-Ok "Docker trovato: $dockerVersion"
} catch {
    Write-Err "Docker non risponde. Assicurati che Docker Desktop sia avviato."
}

# ── 2. Verifica Docker Compose ───────────────────────────────────────────────
Write-Step "Verifica Docker Compose"

$composeOk = $false
try {
    docker compose version 2>&1 | Out-Null
    $composeOk = $true
    Write-Ok "Docker Compose disponibile"
} catch { }

if (-not $composeOk) {
    try {
        docker-compose --version 2>&1 | Out-Null
        $composeOk = $true
        Write-Ok "docker-compose (legacy) disponibile"
    } catch { }
}

if (-not $composeOk) {
    Write-Err "Docker Compose non trovato. Aggiorna Docker Desktop alla versione piu' recente."
}

# ── 3. Leggi secret da Hermes (auto) ────────────────────────────────────────
Write-Step "Lettura secret da Hermes"

$autoEventsSecret = ""
$autoReportSecret = ""
$webhookFile = Join-Path $env:LOCALAPPDATA "hermes\webhook_subscriptions.json"

if (Test-Path $webhookFile) {
    try {
        $webhooks = Get-Content $webhookFile -Raw | ConvertFrom-Json
        if ($webhooks.'ids-events') { $autoEventsSecret = $webhooks.'ids-events'.secret }
        if ($webhooks.'ids-report') { $autoReportSecret = $webhooks.'ids-report'.secret }

        if ($autoEventsSecret -and $autoReportSecret) {
            Write-Ok "Secret letti automaticamente da:"
            Write-Host "    $webhookFile"
        } else {
            Write-Warn "File trovato ma una o entrambe le voci (ids-events / ids-report) mancano."
        }
    } catch {
        Write-Warn "Impossibile leggere $webhookFile : $_"
    }
} else {
    Write-Warn "File webhook non trovato: $webhookFile"
    Write-Host "  I secret dovranno essere inseriti manualmente nel file .env"
}

# ── 4. Configurazione .env ───────────────────────────────────────────────────
Write-Step "Configurazione .env"

$envFile = Join-Path $ScriptDir ".env"
$envExample = Join-Path $ScriptDir ".env.example"

if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Warn ".env creato da .env.example"
    } else {
        # Crea .env con i secret già compilati se disponibili
        @"
# hermes-ids configurazione Windows
# Interfaccia di rete da monitorare (es. "Ethernet", "Wi-Fi", "eth0")
CAPTURE_INTERFACE=Ethernet

# URL del gateway Hermes (default: stesso PC)
HERMES_GATEWAY_URL=http://127.0.0.1:8644

# Secret per webhook ids-events
# File sorgente: %LOCALAPPDATA%\hermes\webhook_subscriptions.json  ->  ids-events.secret
HERMES_EVENTS_SECRET=$autoEventsSecret

# Secret per webhook ids-report
# File sorgente: %LOCALAPPDATA%\hermes\webhook_subscriptions.json  ->  ids-report.secret
HERMES_REPORT_SECRET=$autoReportSecret

# Intervallo report Telegram in secondi (default: 600 = 10 minuti)
HERMES_REPORT_INTERVAL=600

# Livello di log: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=INFO
"@ | Set-Content $envFile -Encoding UTF8
        Write-Ok ".env creato"
    }

    # Se .env era già stato creato da .env.example, aggiorna i secret vuoti
} elseif ($autoEventsSecret -or $autoReportSecret) {
    # Aggiorna solo i campi ancora vuoti nel .env esistente
    $envContent = Get-Content $envFile -Raw
    if ($autoEventsSecret -and $envContent -match 'HERMES_EVENTS_SECRET=\s*$') {
        $envContent = $envContent -replace 'HERMES_EVENTS_SECRET=\s*(\r?\n)', "HERMES_EVENTS_SECRET=$autoEventsSecret`$1"
        Write-Ok "HERMES_EVENTS_SECRET aggiornato nel .env"
    }
    if ($autoReportSecret -and $envContent -match 'HERMES_REPORT_SECRET=\s*$') {
        $envContent = $envContent -replace 'HERMES_REPORT_SECRET=\s*(\r?\n)', "HERMES_REPORT_SECRET=$autoReportSecret`$1"
        Write-Ok "HERMES_REPORT_SECRET aggiornato nel .env"
    }
    Set-Content $envFile -Value $envContent -Encoding UTF8 -NoNewline
}

# ── 4. Lettura e validazione .env ─────────────────────────────────────────────
Write-Step "Lettura configurazione da .env"

# Legge il file .env riga per riga
$envVars = @{}
Get-Content $envFile | Where-Object { $_ -match "^\s*[^#].*=" } | ForEach-Object {
    $parts = $_ -split "=", 2
    if ($parts.Count -eq 2) {
        $key   = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"')
        $envVars[$key] = $value
    }
}

# Mostra interfacce di rete disponibili
Write-Host ""
Write-Host "  Interfacce di rete disponibili:"
$ifaces = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -ExpandProperty Name
$ifaces | ForEach-Object { Write-Host "    - $_" }
Write-Host ""

# Verifica campi obbligatori
$missing = @()

if ([string]::IsNullOrEmpty($envVars["HERMES_EVENTS_SECRET"])) {
    $missing += "HERMES_EVENTS_SECRET"
}
if ([string]::IsNullOrEmpty($envVars["HERMES_REPORT_SECRET"])) {
    $missing += "HERMES_REPORT_SECRET"
}
if ([string]::IsNullOrEmpty($envVars["CAPTURE_INTERFACE"])) {
    $missing += "CAPTURE_INTERFACE"
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Warn "Campi obbligatori mancanti in .env:"
    $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "  Modifica il file .env con un editor di testo:"
    Write-Host "    notepad $envFile"
    Write-Host ""
    Write-Host "  Dove trovare i valori:"
    Write-Host "    Apri questo file JSON:"
    Write-Host "      $env:LOCALAPPDATA\hermes\webhook_subscriptions.json"
    Write-Host "    HERMES_EVENTS_SECRET  ->  campo 'secret' nella voce 'ids-events'"
    Write-Host "    HERMES_REPORT_SECRET  ->  campo 'secret' nella voce 'ids-report'"
    Write-Host "    CAPTURE_INTERFACE     ->  uno dei valori sopra (es. Ethernet, Wi-Fi)"
    Write-Host ""

    $open = Read-Host "Apro .env in Notepad adesso? [s/N]"
    if ($open -match "^[sS]$") {
        Start-Process notepad.exe $envFile -Wait
        Write-Host "Riesegui lo script dopo aver salvato .env"
    }
    exit 0
}

Write-Ok "Configurazione .env valida"

# ── 5. Crea directory necessarie ──────────────────────────────────────────────
Write-Step "Creazione directory"

@("config", "data", "logs") | ForEach-Object {
    $dir = Join-Path $ScriptDir $_
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
Write-Ok "Directory create: config\, data\, logs\"

# ── 6. known_hosts.yaml ───────────────────────────────────────────────────────
$knownHostsFile = Join-Path $ScriptDir "config\known_hosts.yaml"
if (-not (Test-Path $knownHostsFile)) {
    @"
# ============================================================
#  known_hosts.yaml — Host noti sulla LAN (whitelist)
#  Aggiungi i dispositivi fidati per evitare falsi positivi.
#  Gestibile anche via API: POST http://localhost:8765/whitelist
# ============================================================
known_hosts: []
"@ | Set-Content $knownHostsFile -Encoding UTF8
    Write-Ok "config\known_hosts.yaml creato"
}

# ── 7. Build Docker ────────────────────────────────────────────────────────────
Write-Step "Build immagine Docker hermes-ids"
Write-Host "  (potrebbe richiedere qualche minuto alla prima esecuzione...)"
Write-Host ""

Push-Location $ScriptDir
try {
    docker compose build --no-cache
    if ($LASTEXITCODE -ne 0) { Write-Err "Build Docker fallita" }
    Write-Ok "Immagine Docker costruita"
} finally {
    Pop-Location
}

# ── 8. Avvio servizio ─────────────────────────────────────────────────────────
Write-Step "Avvio hermes-ids"

Push-Location $ScriptDir
try {
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { Write-Err "Avvio Docker fallito" }
    Write-Ok "Container hermes-ids avviato"
} finally {
    Pop-Location
}

# ── 9. Health check ────────────────────────────────────────────────────────────
Write-Step "Attendo startup (20s)..."
Start-Sleep -Seconds 20

$healthOk = $false
for ($i = 0; $i -lt 5; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8765/health" -TimeoutSec 5
        if ($resp.status -eq "ok") {
            $healthOk = $true
            break
        }
    } catch { }
    if ($i -lt 4) {
        Write-Host "  Attendo altri 5s..."
        Start-Sleep -Seconds 5
    }
}

if ($healthOk) {
    Write-Ok "API raggiungibile: http://localhost:8765"
} else {
    Write-Warn "API non ancora risponde. Verifica i log:"
    Write-Host "    docker compose logs --tail=50"
}

# ── 10. Registrazione MCP (opzionale) ─────────────────────────────────────────
Write-Step "Registrazione server MCP"

$registerScript = Join-Path $ScriptDir "register_mcp.bat"
if (Test-Path $registerScript) {
    if (Get-Command hermes -ErrorAction SilentlyContinue) {
        Write-Host "  Hermes CLI trovato. Registro il server MCP..."
        & cmd /c $registerScript
    } else {
        Write-Warn "Hermes CLI non trovato — salto registrazione MCP."
        Write-Host "  Una volta installato Hermes, esegui:"
        Write-Host "    register_mcp.bat"
    }
} else {
    Write-Warn "register_mcp.bat non trovato"
}

# ── Fine ───────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Green
Write-Host "   hermes-ids installato e avviato!"           -ForegroundColor Green
Write-Host "  ============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Comandi utili:"
Write-Host "    docker compose logs -f            # log in tempo reale"
Write-Host "    docker compose ps                 # stato servizio"
Write-Host "    docker compose restart            # riavvia"
Write-Host "    docker compose down               # ferma"
Write-Host "    docker compose up -d --build      # aggiorna e riavvia"
Write-Host ""
Write-Host "  API locale:"
Write-Host "    curl http://localhost:8765/health"
Write-Host "    curl http://localhost:8765/events"
Write-Host "    curl http://localhost:8765/whitelist"
Write-Host ""
Write-Host "  Premi Invio per chiudere..."
Read-Host | Out-Null
