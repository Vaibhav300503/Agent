# Build Agent EXE using PyInstaller

Write-Host "Checking for dependencies..."
pip install -r "$PSScriptRoot\requirements.txt"
pip install pyinstaller

$ProjectRoot = $PSScriptRoot
$SourceFile = "$ProjectRoot\src\service_windows.py"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$DistDir = "$ProjectRoot\dist_$Timestamp"

# Clean previous build
if (Test-Path "$DistDir") { 
    Write-Host "Cleaning previous timestamped build: $DistDir"
    Remove-Item -Path "$DistDir" -Recurse -Force 
}
if (Test-Path "$ProjectRoot\dist") { 
    Write-Host "Cleaning default dist folder..."
    Remove-Item -Path "$ProjectRoot\dist" -Recurse -Force 
}
if (Test-Path "$ProjectRoot\build") { 
    Write-Host "Cleaning default build folder..."
    Remove-Item -Path "$ProjectRoot\build" -Recurse -Force 
}

Write-Host "Building EXE..."
# We use --onedir so config can be external and editable
# Hidden import might be needed for win32timezone or other pywin32 internals
# Using python -m PyInstaller to ensure we use the installed module even if PATH isn't updated
# Adding --collect-all for pywin32 packages significantly increases size but ensures all DLLs and hidden deps are found
python -m PyInstaller --noconfirm --onedir --console --name "SocAgent" --clean `
    --distpath "$DistDir" `
    --paths "$ProjectRoot" `
    --add-data "$ProjectRoot\src;src" `
    --collect-all "pywin32" `
    --collect-all "win32" `
    --collect-all "win32ctypes" `
    --hidden-import "win32timezone" `
    --hidden-import "win32service" `
    --hidden-import "win32event" `
    --hidden-import "servicemanager" `
    --hidden-import "win32serviceutil" `
    --hidden-import "src" `
    --hidden-import "src.config" `
    --hidden-import "src.transport" `
    --hidden-import "src.collectors" `
    --hidden-import "src.collectors.windows" `
    --hidden-import "src.collectors.base" `
    --hidden-import "uuid" `
    --hidden-import "psutil" `
    --hidden-import "watchdog" `
    "$SourceFile"

if (-not $?) {
    Write-Error "Build Failed!"
    exit 1
}

Write-Host "Copying Config..."
$AgentDir = "$DistDir\SocAgent"
New-Item -ItemType Directory -Force -Path "$AgentDir\config" | Out-Null
Copy-Item "$ProjectRoot\config\agent_config.yaml" "$AgentDir\config\"

Write-Host "Creating Interactive Setup Script..."
$SetupBatContent = @"
@echo off
setlocal EnableDelayedExpansion
echo SOC Agent Interactive Installer
echo ============================
echo.

:: Ensure we are running from the script directory
cd /d "%~dp0"

:: Check if Service Exists
sc query SocAgent >nul 2>&1
if %errorlevel% equ 0 (
    echo Service 'SocAgent' is already installed.
    set /p REINSTALL="Do you want to reinstall/update it? (Y/N): "
    if /i "!REINSTALL!" neq "Y" (
        echo Exiting without changes.
        pause
        exit /b
    )
    echo Stopping and Removing old service...
    sc stop SocAgent >nul 2>&1
    timeout /t 2 >nul
    sc delete SocAgent >nul 2>&1
)

echo.
echo Configuration Step
echo ------------------
set /p SERVER_BASE="Enter SOC Server Base URL (e.g. http://192.168.1.10:8080): "

if "%SERVER_BASE%"=="" (
    echo No URL provided. Exiting.
    pause
    exit /b
)

:: Automatically append endpoint if not present
echo "%SERVER_BASE%" | findstr /C:"/api/v1/logs" >nul 2>&1
if %errorlevel% neq 0 (
    :: Remove trailing slash if present
    if "%SERVER_BASE:~-1%"=="/" set "SERVER_BASE=%SERVER_BASE:~0,-1%"
    set "FULL_URL=%SERVER_BASE%/api/v1/logs"
) else (
    set "FULL_URL=%SERVER_BASE%"
)

echo.
set /p AUTH_TOKEN="Enter API Token [Default: secret-token]: "
if "%AUTH_TOKEN%"=="" set "AUTH_TOKEN=secret-token"

echo.
echo Using Server URL: !FULL_URL!
echo Using API Token:  !AUTH_TOKEN!
echo.

echo Updating Configuration...
powershell -Command "(Get-Content config\agent_config.yaml) -replace 'url: .*', 'url: \"!FULL_URL!\"' -replace 'api_token: .*', 'api_token: \"!AUTH_TOKEN!\"' | Set-Content config\agent_config.yaml"

echo Installing Service...
SocAgent.exe install

if %errorlevel% neq 0 (
    echo Failed to install service. Run as Administrator?
    pause
    exit /b
)

echo Starting Service...
sc start SocAgent

echo.
echo Installation Complete!
pause
"@

Set-Content -Path "$AgentDir\setup.bat" -Value $SetupBatContent

Write-Host "Build Complete!"
Write-Host "Installer Package is located at: $AgentDir"
Write-Host "You can zip this folder and distribute it."
Write-Host ""
Write-Host "Would you like to test the installer now? (Requires Administrator)"
$testResponse = Read-Host "Run setup.bat now? (Y/N)"

if ($testResponse -eq 'Y' -or $testResponse -eq 'y') {
    Write-Host "Launching setup.bat..."
    Start-Process -FilePath "$AgentDir\setup.bat" -Verb RunAs -Wait
}
else {
    Write-Host "Skipping test. You can manually run setup.bat later."
}

Read-Host -Prompt "Press Enter to exit..."
