#!/bin/bash
# AUTOMATED DEBUG SCRIPT
# This script will apply the latest fixes and capture the error logs for you.

echo "=========================================="
echo "1. Applying Service Fixes..."
echo "=========================================="
# Ensure we have execution permissions
chmod +x install.sh
# Run the installer to update systemd service
./install.sh

echo ""
echo "=========================================="
echo "2. Waiting for Service Timeout (10s)..."
echo "=========================================="
sleep 10ok

echo ""
echo "=========================================="
echo "3. Capturing Error Logs..."
echo "=========================================="
# Save logs to a file
journalctl -u soc-platform -n 100 --no-pager > error_log.txt

echo "Logs captured to: error_log.txt"
echo "Here are the last 20 lines of the error:"
echo "------------------------------------------"
tail -n 20 error_log.txt
echo "------------------------------------------"
https://2b288541ec06.ngrok-free.app/
pRGMkZexCIzJhXX62bln3lgBhZF+PwH/
