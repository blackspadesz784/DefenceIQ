# DefenceIQ - Create Shareable Distribution Zip
# This script bundles the Windows Laptop Agent and the Android Companion APK
# into a clean, lightweight zip package ready to share with anyone.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$ZipFileName = "DefenceIQ-Shareable-Package.zip"
$TempDistDir = Join-Path $ScriptDir "temp_dist_bundle"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   DefenceIQ - Packaging Shareable Distribution Zip       " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

if (Test-Path $ZipFileName) {
    Remove-Item -Path $ZipFileName -Force
}
if (Test-Path $TempDistDir) {
    Remove-Item -Path $TempDistDir -Recurse -Force
}

New-Item -ItemType Directory -Path $TempDistDir | Out-Null

Write-Host "[1/4] Copying Agent core files..." -ForegroundColor Green
Copy-Item -Path "agent" -Destination (Join-Path $TempDistDir "agent") -Recurse
Copy-Item -Path "sentinellayer" -Destination (Join-Path $TempDistDir "sentinellayer") -Recurse

Write-Host "[2/4] Copying Batch launchers & setup scripts..." -ForegroundColor Green
Copy-Item -Path "start_agent.bat" -Destination $TempDistDir
Copy-Item -Path "stop_agent.bat" -Destination $TempDistDir
Copy-Item -Path "setup.bat" -Destination $TempDistDir
Copy-Item -Path "README.md" -Destination $TempDistDir

if (Test-Path "DefenceIQ-Companion.apk") {
    Write-Host "[3/4] Copying Android Companion APK..." -ForegroundColor Green
    Copy-Item -Path "DefenceIQ-Companion.apk" -Destination $TempDistDir
} elseif (Test-Path "android-app\app\build\outputs\apk\debug\app-debug.apk") {
    Write-Host "[3/4] Copying Android Companion APK from build..." -ForegroundColor Green
    Copy-Item -Path "android-app\app\build\outputs\apk\debug\app-debug.apk" -Destination (Join-Path $TempDistDir "DefenceIQ-Companion.apk")
}

Write-Host "[4/4] Compressing into $ZipFileName..." -ForegroundColor Green
Compress-Archive -Path "$TempDistDir\*" -DestinationPath $ZipFileName -Force

Remove-Item -Path $TempDistDir -Recurse -Force

$ZipSizeMB = [math]::Round(((Get-Item $ZipFileName).Length / 1MB), 2)

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " SUCCESS! Shareable package created: $ZipFileName ($ZipSizeMB MB)" -ForegroundColor Green
Write-Host " You can now share '$ZipFileName' with anyone via:" -ForegroundColor White
Write-Host "  - Google Drive / Pendrive / Telegram / WhatsApp" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
