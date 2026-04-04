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
