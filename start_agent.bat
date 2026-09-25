@echo off
title DefenceIQ Security Agent
cd /d "%~dp0"
echo =====================================================================
echo                 Starting DefenceIQ Security Agent
echo =====================================================================
set PYTHONPATH=.

:: Read pairing token if available
set TOKEN=
if exist pairing_token.key (
    set /p TOKEN=<pairing_token.key
)

if defined TOKEN (
    start "" "http://127.0.0.1:8765/dashboard?token=%TOKEN%"
) else (
    start "" "http://127.0.0.1:8765/dashboard"
)
python agent\main.py
pause

