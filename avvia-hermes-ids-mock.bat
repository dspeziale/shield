@echo off
:: ============================================================
::  avvia-hermes-ids-mock.bat
::  Avvia hermes-ids in MOCK MODE (no Npcap, no Admin)
::  Utile per test e sviluppo
:: ============================================================

cd /d "C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes"

echo.
echo  ============================================
echo   Hermes-IDS v0.1.0 — MOCK MODE (test)
echo   Pacchetti sintetici, no cattura reale
echo  ============================================
echo.

:: Uccide eventuale istanza precedente
taskkill /f /fi "WINDOWTITLE eq hermes-ids*" >nul 2>&1

echo  Avvio in mock mode...
echo  Premi CTRL+C per fermare il servizio.
echo.

python -m src.main --config config/config.yaml --mock-capture

pause
