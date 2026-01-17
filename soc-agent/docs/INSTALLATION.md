# SOC Platform & Agent Installation Guide

This guide provides step-by-step instructions for deploying the SOC (Security Operations Center) Platform (Server) and the SOC Agents (Windows/Linux).

---

## 🚀 Server Deployment (Ubuntu 20.04+)

The SOC Platform is the central brain that receives, parses, stores, and analyzes logs.

### Prerequisites
- Ubuntu 20.04 LTS or newer
- 4GB RAM, 50GB disk (minimum)
- Root/sudo access
- Public IP or reachable hostname

### Installation Steps
1. **Copy Files**: Transfer the `server/` folder to your Linux server.
   ```bash
   scp -r server/ user@YOUR_SERVER_IP:/tmp/soc-server
   ```
2. **Run Automated Installer**:
   ```bash
   cd /tmp/soc-server
   chmod +x install.sh
   sudo ./install.sh
   ```
3. **Configuration**:
   The installer will prompt you for:
   - Installation directory (default: `/opt/soc-platform`)
   - MongoDB & Redis passwords
   - API Token (used for agent authentication)
   - TheHive URL/API Key (optional)

4. **Verify**:
   ```bash
   sudo systemctl status soc-platform
   curl http://localhost:8080/health
   # Result: {"status":"healthy"}
   ```

---

## 🛠 SOC Agent Deployment

The agent collects logs from endpoints and transmits them to the server.

### 1. Windows Installation
1. **Build Installer** (Optional - if you need a fresh .exe):
   ```powershell
   cd soc-agent
   .\build_agent_exe.ps1
   ```
2. **Install**:
   - Copy the `dist/SocAgent` folder or the `soc-agent` source to the target machine.
   - Run `install/install_windows.ps1` as Administrator.
   - Enter the Server URL (e.g., `http://YOUR_SERVER_IP:8080/api/v1/logs`) when prompted.
3. **Check**:
   - Open `Services.msc` and verify "SocAgent" is running.
   - Logs are located in `soc_agent.log` in the installation folder.

### 2. Linux Installation
1. **Copy Files**: Transfer the `soc-agent` folder to the target Linux machine.
2. **Easy Install**:
   ```bash
   cd soc-agent/install
   chmod +x easy_install_linux.sh
   sudo ./easy_install_linux.sh
   ```
3. **Verify**:
   - `sudo systemctl status soc-agent`
   - `tail -f /var/log/soc-agent.log` (if configured)

---

## ⚙️ Configuration Reference

### `config/agent_config.yaml`
Key settings to adjust:
- `server.url`: Full API endpoint to the server.
- `server.api_token`: Must match the token set during server installation.
- `agent.polling_interval_sec`: How often to pull logs (default: 120s).
- `features`: Toggle FIM, Network Monitoring, etc.

---

## 🐛 Troubleshooting
- **Connection Refused**: Ensure port `8080` is open on the server firewall (`ufw allow 8080/tcp`).
- **Auth Failure**: Verify `api_token` matches in both agent config and server settings.
- **Log Gaps**: Check if the agent service is running and has read permissions for the targeted log files.
