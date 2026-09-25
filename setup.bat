@echo off
title DefenceIQ - Setup & Dependency Installer
cd /d "%~dp0"
echo =====================================================================
echo                DefenceIQ Security Agent - Setup
echo =====================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your system PATH!
    echo Please install Python 3.10+ from https://www.python.org/
    echo NOTE: Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [1/2] Checking Python version...
python --version

echo.
echo [2/2] Installing required Python dependencies...
python -m pip install --upgrade pip
python -m pip install -r agent\requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Some dependencies failed to install. Please check errors above.
    pause
    exit /b %errorlevel%
)

echo.
echo =====================================================================
echo   Setup Complete! Everything is installed and ready.
echo   You can now launch DefenceIQ by double clicking "start_agent.bat".
echo =====================================================================
echo.
pause
