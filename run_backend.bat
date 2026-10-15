@echo off
echo Starting DemoShop Backend on http://127.0.0.1:9000 ...
echo.
call .venv\Scripts\activate
python -m backend.seed
uvicorn backend.app:app --host 127.0.0.1 --port 9000
