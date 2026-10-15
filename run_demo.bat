@echo off
setlocal enabledelayedexpansion
title API Gatekeeper - Demo Runner

echo ==============================================================================
echo                      API GATEKEEPER -- DEMO RUNNER                            
echo       Reverse-Proxy Application Security Gateway for REST APIs                
echo ==============================================================================
echo.

cd /d "%~dp0"

:: 1. Verify Python availability
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Python 3 was not found in PATH.
    echo     Please install Python 3.10+ from python.org and add it to PATH.
    pause
    exit /b 1
)

:: 2. Check virtual environment
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if errorlevel 1 (
        echo [!] Failed to create .venv.
        pause
        exit /b 1
    )
    echo [*] Installing dependencies from requirements.txt...
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

:: 3. Seed DemoShop database
echo [*] Initializing ephemeral database and seeds...
python -m backend.seed
if errorlevel 1 (
    echo [!] Warning: Database seeding encountered an issue.
)

:: 4. Start DemoShop Backend (Internal Port 9000)
echo [*] Starting DemoShop Backend on http://127.0.0.1:9000...
start "DemoShop Backend (:9000)" cmd /k "title DemoShop Backend && cd /d %~dp0 && call .venv\Scripts\activate && uvicorn backend.app:app --host 127.0.0.1 --port 9000"

:: Wait 2 seconds for backend initialization
timeout /t 2 /nobreak >nul

:: 5. Start API Gatekeeper Gateway (Public Port 8000)
echo [*] Starting API Gatekeeper on http://127.0.0.1:8000...
start "API Gatekeeper (:8000)" cmd /k "title API Gatekeeper Gateway && cd /d %~dp0 && call .venv\Scripts\activate && uvicorn gateway.main:app --host 127.0.0.1 --port 8000"

:: Wait 2 seconds for gateway initialization
timeout /t 2 /nobreak >nul

:: 6. Launch browser
echo [*] Opening Security Dashboard in browser...
start http://127.0.0.1:8000/_gk/

echo.
echo ==============================================================================
echo   SERVICES RUNNING:
echo     - Gateway ^& Dashboard: http://127.0.0.1:8000/_gk/
echo     - Upstream Backend:   http://127.0.0.1:9000 (Protected)
echo.
echo   DEMO SHORTCUTS (Run in a new terminal):
echo     - Live Attack Simulator:    python tools\attack_sim.py
echo     - Benign E-Commerce Traffic: python tools\demo_traffic.py
echo     - End-to-End Walkthrough:    python tools\walkthrough_m10.py
echo.
echo   Close this window or the opened console windows to stop services.
echo ==============================================================================
echo.
pause
