@echo off
title DefenceIQ - One-Click Deployment
color 0A
cls
echo ======================================================================
echo           DEFENCEIQ - ONE-CLICK AUTORUN & SHORTCUT INSTALLER
echo ======================================================================
echo.

cd /d "%~dp0"
set SCRIPT_DIR=%~dp0
set VBS_TARGET=%SCRIPT_DIR%Start-DefenceIQ-Background.vbs

echo [*] Creating Desktop Shortcut...
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\DefenceIQ.lnk'); $s.TargetPath = 'wscript.exe'; $s.Arguments = '\"%VBS_TARGET%\"'; $s.WorkingDirectory = '%SCRIPT_DIR%'; $s.Save()"

echo [*] Adding DefenceIQ to Windows Startup (Runs silently in background on boot)...
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Startup') + '\DefenceIQ.lnk'); $s.TargetPath = 'wscript.exe'; $s.Arguments = '\"%VBS_TARGET%\"'; $s.WorkingDirectory = '%SCRIPT_DIR%'; $s.Save()"

echo.
echo ======================================================================
echo  [SUCCESS] Deployment complete!
echo  1. Desktop shortcut created: DefenceIQ
echo  2. Windows Startup enabled: Laptop turn on hote hi DefenceIQ automatically
echo     background me chalu ho jayega bina kisi terminal ke!
echo ======================================================================
echo.
pause
