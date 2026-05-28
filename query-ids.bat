@echo off
:: ============================================================
::  query-ids.bat
::  Invia un report IDS istantaneo su Telegram.
::  Doppio clic per ricevere subito lo stato nel telefono.
:: ============================================================
cd /d "C:\Users\marco.bellomo\Desktop\JobArea\Codice\Ranger\hermes"

set ARGS=%*
if "%ARGS%"=="" set ARGS=--limit 20

echo Interrogo IDS e invio su Telegram...
python ids_report.py %ARGS%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Report inviato. Controlla Telegram.
) else (
    echo.
    echo ERRORE - Assicurati che:
    echo   1. hermes-ids sia avviato  ^(avvia-hermes-ids.bat^)
    echo   2. Hermes gateway sia attivo  ^(hermes gateway status^)
)

timeout /t 3 >nul
