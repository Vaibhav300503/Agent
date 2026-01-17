# Custom SOC Log Agent - Deployment Guide

## Overview
This custom agent collects logs from Windows and Linux and sends them to your central SOC Server.

## 1. Setting up the Server (Receiver)
Before installing agents, ensure your Ubuntu server is ready.
See [Server Manual](server_manual.md) for details.

---

## 2. Building the Windows Installer (For Admins)
To create a distributable `.exe` for your Windows endpoints:
1.  Open PowerShell as Administrator.
2.  Navigate to the project folder:
    ```powershell
    cd "c:\Users\INDIA TECHNOLOGY\Desktop\script\soc-agent"
    ```
3.  Run the builder script:
    ```powershell
    .\build_agent_exe.ps1
    ```
4.  **Result**: You will get a folder named `dist\SocAgent`.
    *   **Zip this folder** and distribute it to your Windows endpoints.

## 3. Installing on Endpoints

### Windows Installation
1.  Unzip the `SocAgent` folder on the target machine (e.g., in `C:\Program Files\`).
2.  Right-click `setup.bat` and **Run as Administrator**.
3.  Enter your SOC Server URL when prompted (e.g., `http://192.168.1.50:8080/api/v1/logs`).
4.  The script will automatically configure the agent and start the service.

### Linux Installation
1.  Copy the entire `soc-agent` folder to the target Linux machine.
2.  Run the easy installer as root:
    ```bash
    cd soc-agent/install
    chmod +x easy_install_linux.sh
    sudo ./easy_install_linux.sh
    ```
3.  Enter your SOC Server URL when prompted.
4.  The service will start automatically.

## Troubleshooting
- **Windows**: If the service fails to start, check `soc_agent.log` inside the installation folder.
- **Linux**: Check `systemctl status soc-agent`.
