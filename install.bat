@echo off
REM ============================================================
REM  install.bat — Installa hermes-ids su Windows
REM  Wrapper per install.ps1 — gestisce ExecutionPolicy
REM
REM  Uso: doppio clic oppure:
REM    install.bat
REM ============================================================

echo.
echo   Avvio installazione hermes-ids...
echo.

REM Verifica che PowerShell sia disponibile
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRORE] PowerShell non trovato. Richiesto PowerShell 5.1 o superiore.
    pause
    exit /b 1
)

REM Esegui install.ps1 bypassando ExecutionPolicy (solo per questo processo)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"

if %errorlevel% neq 0 (
    echo.
    echo [ERRORE] Installazione fallita. Vedi output sopra.
    pause
    exit /b 1
)
