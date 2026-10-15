@echo off
echo Starting API Gatekeeper on http://127.0.0.1:8000 ...
echo.
call .venv\Scripts\activate
uvicorn gateway.main:app --host 127.0.0.1 --port 8000
