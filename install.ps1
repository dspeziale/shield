#Requires -Version 5.1
<#
.SYNOPSIS
    install.ps1 - Installa hermes-ids su Windows con Docker Desktop.
.EXAMPLE
    .\install.ps1
    powershell -ExecutionPolicy Bypass -File .\install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Ok   { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "  [KO] $msg" -ForegroundColor Red; exit 1 }
function Write-Step { param($n,$msg) Write-Host "" ; Write-Host "==> Passo $n`: $msg" -ForegroundColor Cyan }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host "   hermes-ids - Installazione Windows"
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host ""

# =========================================================
# 1. Verifica Docker Desktop
# =========================================================
Write-Step 1 "Verifica Docker Desktop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Warn "Docker non trovato."
    Write-Host ""
    Write-Host "  Installa Docker Desktop da: https://www.docker.com/products/docker-desktop/"
    Write-Host "  Dopo l'installazione riavvia il PC e riesegui questo script."
    Write-Host ""
    exit 1
}

try {
    $dockerVersion = & docker --version 2>&1
    Write-Ok "Docker trovato: $dockerVersion"
} catch {
    Write-Err "Docker non risponde. Assicurati che Docker Desktop sia avviato."
}

# =========================================================
# 2. Verifica Docker Compose
# =========================================================
Write-Step 2 "Verifica Docker Compose"

$composeOk = $false
try { & docker compose version 2>&1 | Out-Null ; $composeOk = $true } catch {}
if (-not $composeOk) {
    try { & docker-compose --version 2>&1 | Out-Null ; $composeOk = $true } catch {}
}
if (-not $composeOk) {
    Write-Err "Docker Compose non trovato. Aggiorna Docker Desktop."
}
Write-Ok "Docker Compose disponibile"

# =========================================================
# 3. Leggi secret da Hermes (automatico)
# =========================================================
Write-Step 3 "Lettura secret da Hermes"

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
            Write-Warn "File trovato ma mancano le voci ids-events / ids-report."
        }
    } catch {
        Write-Warn "Impossibile leggere webhook_subscriptions.json: $_"
    }
} else {
    Write-Warn "File non trovato: $webhookFile"
    Write-Host "  I secret dovranno essere inseriti manualmente nel .env"
}

# =========================================================
# 4. Configurazione .env
# =========================================================
Write-Step 4 "Configurazione .env"

$envFile    = Join-Path $ScriptDir ".env"
$envExample = Join-Path $ScriptDir ".env.example"

if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Warn ".env creato da .env.example"
    } else {
        # Crea .env minimale (valori fissi, no interpolazione nel template)
        $envTemplate = @'
# hermes-ids configurazione Windows
CAPTURE_INTERFACE=Ethernet
HERMES_GATEWAY_URL=http://127.0.0.1:8644
HERMES_EVENTS_SECRET=
HERMES_REPORT_SECRET=
HERMES_REPORT_INTERVAL=600
LOG_LEVEL=INFO
'@
        Set-Content $envFile -Value $envTemplate -Encoding UTF8
        Write-Ok ".env creato"
    }
}

# Aggiorna i secret nel .env se li abbiamo letti automaticamente
if ($autoEventsSecret -or $autoReportSecret) {
    $envContent = Get-Content $envFile -Raw
    $changed = $false

    if ($autoEventsSecret -and ($envContent -match 'HERMES_EVENTS_SECRET=\s*[\r\n]')) {
        $envContent = $envContent -replace '(HERMES_EVENTS_SECRET=)([ \t]*)(\r?\n)', "`$1$autoEventsSecret`$3"
        Write-Ok "HERMES_EVENTS_SECRET aggiornato nel .env"
        $changed = $true
    }
    if ($autoReportSecret -and ($envContent -match 'HERMES_REPORT_SECRET=\s*[\r\n]')) {
        $envContent = $envContent -replace '(HERMES_REPORT_SECRET=)([ \t]*)(\r?\n)', "`$1$autoReportSecret`$3"
        Write-Ok "HERMES_REPORT_SECRET aggiornato nel .env"
        $changed = $true
    }
    if ($changed) {
        [System.IO.File]::WriteAllText($envFile, $envContent, [System.Text.Encoding]::UTF8)
    }
}

# =========================================================
# 5. Lettura e validazione .env
# =========================================================
Write-Step 5 "Validazione .env"

$envVars = @{}
Get-Content $envFile | Where-Object { $_ -match "^\s*[^#].+=" } | ForEach-Object {
    $parts = $_ -split "=", 2
    if ($parts.Count -eq 2) {
        $envVars[$parts[0].Trim()] = $parts[1].Trim().Trim('"')
    }
}

Write-Host ""
Write-Host "  Interfacce di rete disponibili:"
Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object {
    Write-Host "    - $($_.Name)"
}
Write-Host ""

$missing = @()
if ([string]::IsNullOrEmpty($envVars["HERMES_EVENTS_SECRET"])) { $missing += "HERMES_EVENTS_SECRET" }
if ([string]::IsNullOrEmpty($envVars["HERMES_REPORT_SECRET"]))  { $missing += "HERMES_REPORT_SECRET" }
if ([string]::IsNullOrEmpty($envVars["CAPTURE_INTERFACE"]))     { $missing += "CAPTURE_INTERFACE" }

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Warn "Campi obbligatori mancanti in .env:"
    $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "  Modifica il file .env:"
    Write-Host "    notepad $envFile"
    Write-Host ""
    Write-Host "  Dove trovare i secret:"
    Write-Host "    $env:LOCALAPPDATA\hermes\webhook_subscriptions.json"
    Write-Host "    HERMES_EVENTS_SECRET  ->  ids-events.secret"
    Write-Host "    HERMES_REPORT_SECRET  ->  ids-report.secret"
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

# =========================================================
# 6. Crea directory
# =========================================================
Write-Step 6 "Creazione directory"

foreach ($d in @("config","data","logs")) {
    $dir = Join-Path $ScriptDir $d
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}
Write-Ok "Directory create: config\, data\, logs\"

# known_hosts.yaml
$knownHostsFile = Join-Path $ScriptDir "config\known_hosts.yaml"
if (-not (Test-Path $knownHostsFile)) {
    Set-Content $knownHostsFile -Value "known_hosts: []" -Encoding UTF8
    Write-Ok "config\known_hosts.yaml creato"
}

# =========================================================
# 7. Build Docker
# =========================================================
Write-Step 7 "Build immagine Docker hermes-ids"
Write-Host "  (potrebbe richiedere qualche minuto alla prima esecuzione...)"

Push-Location $ScriptDir
try {
    & docker compose build --no-cache
    if ($LASTEXITCODE -ne 0) { Write-Err "Build Docker fallita" }
    Write-Ok "Immagine Docker costruita"
} finally {
    Pop-Location
}

# =========================================================
# 8. Avvio servizio
# =========================================================
Write-Step 8 "Avvio hermes-ids"

Push-Location $ScriptDir
try {
    & docker compose up -d
    if ($LASTEXITCODE -ne 0) { Write-Err "Avvio Docker fallito" }
    Write-Ok "Container hermes-ids avviato"
} finally {
    Pop-Location
}

# =========================================================
# 9. Health check
# =========================================================
Write-Step 9 "Health check (attendo 20s)..."
Start-Sleep -Seconds 20

$healthOk = $false
for ($i = 0; $i -lt 5; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8765/health" -TimeoutSec 5
        if ($resp.status -eq "ok") { $healthOk = $true; break }
    } catch {}
    if ($i -lt 4) { Write-Host "  Attendo altri 5s..."; Start-Sleep -Seconds 5 }
}

if ($healthOk) {
    Write-Ok "API raggiungibile: http://localhost:8765"
} else {
    Write-Warn "API non risponde ancora. Verifica i log:"
    Write-Host "    docker compose logs --tail=50"
}

# =========================================================
# 10. Registrazione MCP (opzionale)
# =========================================================
Write-Step 10 "Registrazione server MCP"

$registerScript = Join-Path $ScriptDir "register_mcp.bat"
if (Test-Path $registerScript) {
    if (Get-Command hermes -ErrorAction SilentlyContinue) {
        Write-Host "  Hermes CLI trovato. Registro il server MCP..."
        & cmd /c $registerScript
    } else {
        Write-Warn "Hermes CLI non trovato - salto registrazione MCP."
        Write-Host "  Dopo aver installato Hermes, esegui: register_mcp.bat"
    }
} else {
    Write-Warn "register_mcp.bat non trovato"
}

# =========================================================
# Fine
# =========================================================
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Green
Write-Host "   hermes-ids installato e avviato!"           -ForegroundColor Green
Write-Host "  ============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Comandi utili:"
Write-Host "    docker compose logs -f         # log in tempo reale"
Write-Host "    docker compose ps              # stato servizio"
Write-Host "    docker compose restart         # riavvia"
Write-Host "    docker compose down            # ferma"
Write-Host "    docker compose up -d --build   # aggiorna e riavvia"
Write-Host ""
Write-Host "  API locale:"
Write-Host "    curl http://localhost:8765/health"
Write-Host "    curl http://localhost:8765/events"
Write-Host "    curl http://localhost:8765/whitelist"
Write-Host ""
Read-Host "  Premi Invio per chiudere"
