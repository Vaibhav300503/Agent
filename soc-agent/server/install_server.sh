#!/bin/bash

# SOC Ingest Server Installer for Ubuntu

INSTALL_DIR="/opt/soc-server"
LOG_DIR="/var/log/soc-ingest"
SERVICE_FILE="/etc/systemd/system/soc-server.service"

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

echo "Installing SOC Ingest Server..."

# 1. Create Directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"

# 2. Copy Server Script
# Assuming files are in current directory
cp ingest_server.py "$INSTALL_DIR/"

# 3. Create Systemd Service
cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=SOC Log Ingest Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/ingest_server.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/soc-ingest/systemd.log
StandardError=append:/var/log/soc-ingest/systemd.log

[Install]
WantedBy=multi-user.target
EOF

# 4. Permissions
chmod 700 "$INSTALL_DIR"
chmod 700 "$LOG_DIR"
# Secure the service file
chmod 644 "$SERVICE_FILE"

# 5. Enable and Start
systemctl daemon-reload
systemctl enable soc-server
systemctl start soc-server

echo "------------------------------------------------"
echo "Installation Complete."
echo "Server is listening on port 8080."
echo "Logs will be stored in $LOG_DIR"
echo "Check status with: systemctl status soc-server"
echo "------------------------------------------------"
