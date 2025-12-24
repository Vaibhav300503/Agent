#!/bin/bash

# SOC Agent Smart Installer for Linux

BASE_DIR="/opt/soc-agent"
CONFIG_FILE="$BASE_DIR/config/agent_config.yaml"

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

echo "=================================="
echo "   SOC Agent Linux Installer"
echo "=================================="

# 1. Prompt for Server URL
read -p "Enter SOC Server URL (e.g. http://192.168.1.5:8080/api/v1/logs): " SERVER_URL

if [ -z "$SERVER_URL" ]; then
    echo "Error: URL cannot be empty."
    exit 1
fi

# 2. Check for Python, Pip and Venv
echo "Checking for Python, Pip and Venv..."
if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Installing..."
    apt-get update && apt-get install -y python3 python3-pip python3-venv
elif ! dpkg -l | grep -q python3-venv; then
    echo "Python3-venv not found. Installing..."
    apt-get update && apt-get install -y python3-venv
fi

# 3. Install Files
echo "Installing files to $BASE_DIR..."
mkdir -p "$BASE_DIR"
# Copy from current directory (assumed installer is run from within the unzipped folder)
# We copy src, config, install, tests and requirements.txt
cp -r src config install tests requirements.txt "$BASE_DIR/" 2>/dev/null || cp -r ../src ../config ../install ../tests ../requirements.txt "$BASE_DIR/"

# 4. Setup Virtual Environment
echo "Setting up Virtual Environment..."
python3 -m venv "$BASE_DIR/venv"
source "$BASE_DIR/venv/bin/activate"

# 5. Install Dependencies
echo "Installing Python dependencies in Venv..."
"$BASE_DIR/venv/bin/pip" install --upgrade pip
"$BASE_DIR/venv/bin/pip" install -r "$BASE_DIR/requirements.txt"

# 6. Fix Path Issues
echo "Virtual environment ready at $BASE_DIR/venv"
# PYTHONPATH is less critical when using a venv, but we keep it for local module resolution


# 6. Update Config

echo "Configuring Agent..."
if [ -f "$CONFIG_FILE" ]; then
    # Use different delimiter for sed in case URL has slashes
    sed -i "s|url: .*|url: \"$SERVER_URL\"|" "$CONFIG_FILE"
else
    echo "Warning: Config file not found at $CONFIG_FILE"
fi

# 7. Setup Service

echo "Registering Systemd Service..."
SERVICE_SRC="$BASE_DIR/install/soc-agent.service"
if [ -f "$SERVICE_SRC" ]; then
    cp "$SERVICE_SRC" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable soc-agent
    systemctl restart soc-agent
    echo "Service started."
else
    echo "Error: Service file not found."
    exit 1
fi

echo "=================================="
echo "Installation Complete!"
echo "Agent is sending logs to: $SERVER_URL"
echo "Check status: systemctl status soc-agent"
