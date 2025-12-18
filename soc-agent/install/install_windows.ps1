# Check for Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges!"
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = "$ScriptDir\..\src\service_windows.py"

# Ideally, we would compile to EXE or use the python interpreter path
# Assuming Python is in PATH
Write-Host "Installing SOC Agent Service..."
python "$PythonScript" install

if ($?) {
    Write-Host "Service installed successfully."
    Write-Host "Setting service to Auto Start..."
    Set-Service -Name "SocAgent" -StartupType Automatic
    
    Write-Host "Starting Service..."
    Start-Service -Name "SocAgent"
    Write-Host "Done."
}
else {
    Write-Error "Failed to install service."
}
