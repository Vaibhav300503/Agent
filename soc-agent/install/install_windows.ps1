# Check for Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges!"
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = "$ScriptDir\..\src\service_windows.py"

# 2. Check for Python
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in PATH. Please install Python 3 and try again."
    exit 1
}

# 3. Install required Python dependencies
Write-Host "Installing required Python dependencies from requirements.txt..."
$RequirementsFile = "$ScriptDir\..\requirements.txt"
if (Test-Path $RequirementsFile) {
    python -m pip install --upgrade pip
    python -m pip install -r $RequirementsFile
} else {
    Write-Host "requirements.txt not found, installing core dependencies manually..."
    python -m pip install pywin32 requests PyYAML psutil watchdog
}

if (!$?) {
    Write-Error "Failed to install Python dependencies."
    exit 1
}

# 4. Finalizing Path Setup
Write-Host "Verifying Python path..."
$PythonPath = python -c "import sys; print(sys.executable)"
Write-Host "Using Python: $PythonPath"


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
