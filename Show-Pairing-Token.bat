@echo off
title DefenceIQ - Pairing Token Manager
color 0B
cls
setlocal enabledelayedexpansion

set "TOKEN=DIQ-EJFW-GC3V"
if exist "pairing_token.key" (
    set /p TOKEN=<pairing_token.key
)

echo ======================================================================
echo             DEFENCEIQ - LAPTOP PAIRING TOKEN MANAGER
echo ======================================================================
echo.
echo   [+] LAPTOP NAME            :  %COMPUTERNAME%
echo   [+] CURRENT PAIRING TOKEN  :  !TOKEN!
echo   [+] DEFAULT SERVER PORT    :  8765
echo.
echo ======================================================================
echo   [1] Ek baar connect hone ke baad yeh hamesha phone se juda rahega.
echo   [2] Aap kahi bhi ho (Wi-Fi, Mobile 4G/5G), connection active rahega.
echo   [3] Yeh tab tak disconnect nahi hoga jab tak aap phone se unpair na karein.
echo ======================================================================
echo.
echo   [N] Press 'N' to generate a BRAND NEW Pairing Token for this laptop
echo   [Enter] Keep current token and exit
echo.
set /p USER_CHOICE="Aapka vikalp (Option) [N / Exit]: "

if /i "%USER_CHOICE%"=="N" (
    cls
    echo Generating brand new pairing token for %COMPUTERNAME%...
    powershell -NoProfile -Command "$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; $tok = 'DIQ-' + (-join ((1..4) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })) + '-' + (-join ((1..4) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })); Set-Content -Path 'pairing_token.key' -Value $tok; Write-Host \"`n======================================================================\" -ForegroundColor Green; Write-Host \"  [+] NAYA PAIRING TOKEN ON THE SPOT GENERATE HO GAYA:\" -ForegroundColor Yellow; Write-Host \"      $tok\" -ForegroundColor Cyan; Write-Host \"======================================================================`n\" -ForegroundColor Green; Write-Host \"  Phone ke Pairing screen me yeh naya token daal kar connect karein!`n\""
    pause
    exit /b
)

exit /b
