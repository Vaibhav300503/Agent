# SOC Platform & Agent Ecosystem 🛡️

A powerful, lightweight, and secure Security Operations Center (SOC) framework designed for real-time log collection, threat detection, and automated incident response. This project provides a full-stack solution including cross-platform agents and a high-performance backend.

---

## 🚀 Key Features

### 📡 SOC Agent Capabilities
*   **Multi-Platform Collection**: Native support for **Windows Event Logs** (Security, System, Application) and **Linux Syslogs**.
*   **Network Visibility**: Real-time snapshotting of TCP/UDP connections with process attribution (ID the app making the connection).
*   **File Integrity Monitoring (FIM)**: Real-time directory watching with **Canary File** support to detect ransomware activity.
*   **Application-Level Defense**: Specialized parsers for **Nginx, Apache, MySQL, PostgreSQL**, and **BIND DNS**.
*   **Robust Transport**: Local SQLite buffering to prevent data loss during network downtime + Heartbeat status reporting.

### �️ SOC Platform (Server) Capabilities
*   **High-Throughput Ingestion**: Optimized API using **FastAPI** and **Redis** queues for asynchronous processing.
*   **Intelligent Processing**: Parallel workers handle parsing, GeoIP enrichment, and pattern-based threat detection.
*   **Rule Engine**: Pre-seeded with **OWASP Top 10** detection rules for SQLi, XSS, Brute force, and Lateral Movement.
*   **Security Orchestration**: Native integration with **TheHive** for automatic case creation.
*   **Time-Series Storage**: Optimized **MongoDB** schema for efficient long-term log analysis.

---

## 📂 Project Structure

```text
├── config/              # Agent configuration files
├── docs/                # Detailed technical documentation
├── install/             # Windows (PS1) and Linux (SH) service installers
├── server/              # Central SOC Platform (Backend)
│   ├── api/             # REST Ingestion API
│   ├── workers/         # Parser, Enricher, and Detector workers
│   └── install.sh       # Automated Ubuntu installer
├── src/                 # SOC Agent source code (Python)
└── build_agent_exe.ps1  # Windows PyInstaller build script
```

---

## ⚡ Quick Start

### 1. Deploy the Server (Ubuntu 20.04+)
The server is the central brain. Deploy it on a reachable Linux host:

```bash
cd server
chmod +x install.sh
sudo ./install.sh
```
*Follow the interactive prompts to set your **API Token** and DB passwords.*

### 2. Configure the Agent
Update the configuration on your endpoints to point to your server:

**File:** `config/agent_config.yaml`
```yaml
server:
  url: "http://YOUR_SERVER_IP:5000/api/v1/logs"
  api_token: "YOUR_SECRET_TOKEN"
agent:
  polling_interval_sec: 120  # Optimized for performance
```

### 3. Install the Agent
*   **Windows**: Run `install/install_windows.ps1` as Administrator.
*   **Linux**: Run `sudo install/easy_install_linux.sh`.

---

## 🛡️ Security First
This platform is built with a "Security-in-Depth" approach:
*   **Data Sanitization**: All logs are automatically sanitized via a dedicated pipeline to prevent SQL injection and XSS from malicious log entries.
*   **Auth Enforcement**: Secure Bearer Token authentication required for all agent-server communication.
*   **Audit Trail**: Local agent logs (`soc_agent.log`) provide a full audit of sanitization and transmission status.

---

## 📖 Documentation
Detailed guides are available in the `/docs` directory:
*   [**Installation Guide**](docs/INSTALLATION.md) - Advanced setup and troubleshooting.
*   [**Features List**](docs/FEATURES.md) - Complete breakdown of monitoring capabilities.
*   [**Architecture**](docs/WORKING.md) - Deep dive into collectors and data flow.

---

### 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

---
**Disclaimer**: This tool is for security monitoring and defensive purposes. Ensure you have proper authorization before deploying agents on systems you do not own.
