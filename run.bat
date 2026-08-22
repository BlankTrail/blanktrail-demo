@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv" (
  echo Creating a virtual environment...
  python -m venv .venv || goto :fail
)

call ".venv\Scripts\activate.bat" || goto :fail

python -c "import flask, httpx, truststore" 2>nul
if errorlevel 1 (
  echo Installing dependencies...
  python -m pip install --upgrade pip >nul
  python -m pip install -r requirements.txt || goto :fail
)

python -m blanktrail_demo %*
goto :eof

:fail
echo.
echo Startup failed. Python 3.10 or newer is required.
pause
exit /b 1
