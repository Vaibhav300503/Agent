# SOC Ingest Server - Ubuntu Manual

This guide explains how to set up the central Log Ingest Server on an Ubuntu machine to receive logs from your agents.

## Prerequisites

- **OS**: Ubuntu 20.04 LTS or newer (Debian/RHEL also supported with minor adjustments)
- **Python**: 3.6+ (Pre-installed on most modern Linux distros)
- **Network**: Port `8080` (default) must be open in the firewall.

## Installation

1. **Transfer Files**:
   Copy the `server/` folder from this project to your Ubuntu server (e.g., using `scp`).
   ```bash
   scp -r server/ user@your-ubuntu-server:/home/user/
   ```

2. **Run Installer**:
   SSH into your server and run the installation script as root.
   ```bash
   cd server
   chmod +x install_server.sh
   sudo ./install_server.sh
   ```

## Configuration

The server configuration is currently defined at the top of `/opt/soc-server/ingest_server.py`.

- **Port**: Default `8080`
- **Auth Token**: Default `secret-token`. **IMPORTANT**: Change this token in the script AND in your agents' `agent_config.yaml` to match.
- **Log Directory**: Default `/var/log/soc-ingest`

To change settings:
```bash
sudo nano /opt/soc-server/ingest_server.py
sudo systemctl restart soc-server
```

## Maintenance & Usage

### Checking Server Status
```bash
sudo systemctl status soc-server
```

### Viewing Collected Logs
Logs are organized by Hostname in the log directory.
```bash
cd /var/log/soc-ingest
ls -F
# output: server-01/  workstation-02/

# View live incoming logs
tail -f /var/log/soc-ingest/server-01/*.log
```

## Security Recommendations
1. **Firewall**: Restrict access to port 8080 to known agent IP ranges using `ufw`.
   ```bash
   sudo ufw allow from 192.168.1.0/24 to any port 8080
   ```
2. **TLS/SSL**: This server uses HTTP by default. For production, it is highly recommended to use a reverse proxy like **Nginx** to handle HTTPS termination.

### Nginx Reverse Proxy Example
1. Install Nginx: `sudo apt install nginx`
2. Create config `/etc/nginx/sites-available/soc-server`:
   ```nginx
   server {
       listen 443 ssl;
       server_name soc.yourdomain.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;

       location / {
           proxy_pass http://localhost:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```
3. Update your agents' `agent_config.yaml` to use `https://soc.yourdomain.com`.
