@echo off
title DefenceIQ - Laptop Endpoint Security Agent
color 0A
cls
echo ======================================================================
echo          DEFENCEIQ - ADVANCED ENDPOINT PROTECTION & MONITORING
echo ======================================================================
echo  [+] Host Workstation : %COMPUTERNAME%
echo  [+] Initializing Security Engines & Live Telemetry...
echo ======================================================================
echo.

cd /d "%~dp0"

if exist "dist\DefenceIQ-Laptop-Agent\DefenceIQ-Laptop-Agent.exe" (
    echo [*] Starting DefenceIQ Laptop Executable (Standalone)...
    "dist\DefenceIQ-Laptop-Agent\DefenceIQ-Laptop-Agent.exe"
    goto end
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Starting DefenceIQ Agent via Python...
    python agent\main.py
    goto end
)

color 0C
echo [ERROR] Neither DefenceIQ-Laptop-Agent.exe nor Python was found!
echo Please make sure you are running this from the DefenceIQ folder.
pause
exit /b 1

:end
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] DefenceIQ terminated with code %ERRORLEVEL%.
    pause
)
