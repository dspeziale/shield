@echo off
:: ============================================================
::  avvia-hermes-ids.bat
::  Avvia hermes-ids con cattura reale (Wi-Fi, Npcap).
::  Se non sei Admin, richiede automaticamente elevazione UAC.
::  Doppio clic → accetta UAC → il servizio parte in una finestra.
:: ============================================================

:: ── Auto-elevazione UAC ──────────────────────────────────────
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Richiesta elevazione amministrativa...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: ── Da qui: siamo Admin ──────────────────────────────────────
title hermes-ids [Wi-Fi - Reale]
cd /d "C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes"

echo.
echo  ============================================
echo   Hermes-IDS v0.1.0  ^|  Modalita': REALE
echo   Interfaccia: Wi-Fi  ^|  IP: 192.168.1.134
echo   API: http://localhost:8765
echo  ============================================
echo.

:: Verifica porta libera
for /f "tokens=5" %%a in ('netstat -ano ^| findstr "0.0.0.0:8765"') do (
    echo [WARN] Porta 8765 gia' occupata dal processo %%a
    echo Chiudi il processo e riprova, oppure premi un tasto per continuare...
    pause >nul
)

echo Avvio cattura pacchetti su Wi-Fi...
echo Premi CTRL+C per fermare il servizio.
echo.

python -m src.main --config config/config.yaml

echo.
echo Servizio terminato.
pause
