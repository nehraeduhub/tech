@echo off
REM Tech Guardians VAPT Portal launcher (Windows)
REM Plug-and-run: creates a local virtualenv on the stick, installs deps, launches.
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python 3 is required but was not found on PATH.
  echo     Install Python 3 from https://www.python.org/downloads/ ^(tick "Add to PATH"^).
  pause
  exit /b 1
)

if not exist ".venv" (
  echo [*] First run: creating virtual environment...
  python -m venv .venv
  call .venv\Scripts\python -m pip install --upgrade pip
  echo [*] Installing dependencies...
  call .venv\Scripts\pip install -r requirements.txt
)

echo [*] Starting Tech Guardians VAPT Portal...
call .venv\Scripts\python app.py
pause
