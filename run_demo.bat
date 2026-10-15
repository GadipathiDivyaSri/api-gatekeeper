@echo off
echo ============================================
echo   API Gatekeeper - Demo Launcher
echo ============================================
echo.
echo Starting DemoShop Backend (port 9000)...
start "DemoShop Backend" cmd /k "cd /d %~dp0 && call .venv\Scripts\activate && python -m backend.seed && uvicorn backend.app:app --host 127.0.0.1 --port 9000"

echo Waiting for backend to start...
timeout /t 3 /nobreak >nul

echo Starting API Gatekeeper (port 8000)...
start "API Gatekeeper" cmd /k "cd /d %~dp0 && call .venv\Scripts\activate && uvicorn gateway.main:app --host 127.0.0.1 --port 8000"

echo.
echo ============================================
echo   Backend:   http://127.0.0.1:9000
echo   Gateway:   http://127.0.0.1:8000
echo   Dashboard: http://127.0.0.1:8000/_gk/
echo ============================================
echo.
pause
