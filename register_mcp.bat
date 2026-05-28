@echo off
REM ============================================================
REM  register_mcp.bat — Registra hermes-ids come MCP server in Hermes
REM  Eseguire UNA VOLTA dopo aver installato hermes-ids.
REM
REM  Requisiti:
REM    - Python 3.x nella PATH
REM    - Hermes CLI installato e configurato
REM    - ids_mcp_server.py nella stessa cartella di questo .bat
REM ============================================================

setlocal

REM ── Percorso assoluto di ids_mcp_server.py ──────────────────
set "SCRIPT_DIR=%~dp0"
set "MCP_SCRIPT=%SCRIPT_DIR%ids_mcp_server.py"

if not exist "%MCP_SCRIPT%" (
    echo [ERRORE] ids_mcp_server.py non trovato in: %SCRIPT_DIR%
    pause
    exit /b 1
)

REM ── Carica .env se esiste ────────────────────────────────────
set "ENV_FILE=%SCRIPT_DIR%.env"
if exist "%ENV_FILE%" (
    echo Carico variabili da .env...
    for /f "usebackq tokens=1,2 delims==" %%A in ("%ENV_FILE%") do (
        set "%%A=%%B"
    )
)

REM ── Valori con default ────────────────────────────────────────
if "%IDS_BASE_URL%"==""         set "IDS_BASE_URL=http://localhost:8765"
if "%HERMES_GATEWAY_URL%"==""   set "HERMES_GATEWAY_URL=http://127.0.0.1:8644"
if "%HERMES_REPORT_SECRET%"=="" set "HERMES_REPORT_SECRET=%HERMES_REPORT_SECRET%"

echo.
echo  ============================================
echo   Registrazione MCP server hermes-ids
echo  ============================================
echo.
echo   Script:  %MCP_SCRIPT%
echo   IDS URL: %IDS_BASE_URL%
echo   Gateway: %HERMES_GATEWAY_URL%
echo.

REM ── Registra in Hermes ────────────────────────────────────────
hermes mcp add hermes-ids ^
    --command python ^
    --args "%MCP_SCRIPT%" ^
    --env "IDS_BASE_URL=%IDS_BASE_URL%" ^
    --env "HERMES_GATEWAY_URL=%HERMES_GATEWAY_URL%" ^
    --env "HERMES_REPORT_SECRET=%HERMES_REPORT_SECRET%"

if %errorlevel% neq 0 (
    echo.
    echo [ERRORE] Registrazione fallita. Verifica che Hermes CLI sia installato.
    echo Prova a eseguire: hermes --version
    pause
    exit /b 1
)

echo.
echo  ============================================
echo   MCP server hermes-ids registrato!
echo  ============================================
echo.
echo   Riavvia Hermes perche' il server MCP sia attivo.
echo   Poi chiedi all'agent: "mostrami gli ultimi eventi IDS"
echo.
pause
