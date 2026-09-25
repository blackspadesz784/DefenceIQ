@echo off
title Stop DefenceIQ Security Agent
echo Stopping DefenceIQ Security Agent processes...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8765 ^| findstr LISTENING') do (
    echo Terminating PID: %%a
    taskkill /F /PID %%a
)
echo DefenceIQ stopped.
pause
