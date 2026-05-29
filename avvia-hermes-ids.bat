@echo off
REM ============================================================
REM  avvia-hermes-ids.bat
REM  Avvia hermes-ids in Docker (Windows - bridge networking).
REM  Doppio clic per avviare, oppure da terminale.
REM ============================================================

title hermes-ids [Docker - Windows]
cd /d "%~dp0"

echo.
echo  ============================================
echo   Hermes-IDS v0.1.0  ^|  Docker su Windows
echo   API: http://localhost:8765
echo  ============================================
echo.

REM Usa l'override Windows (bridge networking + port mapping)
docker compose -f docker-compose.yml -f docker-compose.windows.yml up -d

if %errorlevel% neq 0 (
    echo.
    echo [ERRORE] Avvio fallito. Verifica che Docker Desktop sia in esecuzione.
    pause
    exit /b 1
)

echo.
echo [OK] hermes-ids avviato!
echo.
echo Attendo startup (15s)...
timeout /t 15 /nobreak >nul

curl -sf http://localhost:8765/health | findstr /C:"status" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] API raggiungibile: http://localhost:8765
) else (
    echo [!!] API non ancora risponde - attendi qualche secondo.
    echo      Verifica: docker logs hermes-ids --tail 30
)

echo.
echo Comandi utili:
echo   docker compose -f docker-compose.yml -f docker-compose.windows.yml logs -f
echo   docker compose -f docker-compose.yml -f docker-compose.windows.yml down
echo.
pause
