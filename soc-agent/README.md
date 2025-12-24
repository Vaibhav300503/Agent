# Custom SOC Agent & Platform

A lightweight, powerful, and secure Security Operations Center (SOC) ecosystem designed for automated log collection, threat detection, and incident response.

## 📁 Project Structure

- `src/`: Core logic of the SOC Agent (Python).
- `server/`: SOC Platform backend (Flux, MongoDB, Redis).
- `install/`: Installation scripts for Windows and Linux.
- `config/`: Configuration templates.
- `docs/`: Detailed documentation.

## 📖 Documentation

- [**Installation Guide**](docs/INSTALLATION.md): How to set up the server and agents.
- [**Features Overview**](docs/FEATURES.md): What the agent and server can do.
- [**Architecture & Working**](docs/WORKING.md): How the data is collected and processed.
- [**Detection Rules**](SOC_OWASP_Detection_Rules.md): Detailed OWASP-mapped detection logic.

## 🚀 Quick Start (Agent)

1. **Configure**: Update `config/agent_config.yaml` with your server URL and API token.
2. **Install**:
   - **Windows**: Run `install/install_windows.ps1` as Admin.
   - **Linux**: Run `install/easy_install_linux.sh` as Root.
3. **Verify**: Check `soc_agent.log` for successful connection and heartbeats.

## 🛠 Features at a Glance

- **Cross-Platform**: Windows Event Logs & Linux Syslogs.
- **Application Monitoring**: Web servers (Nginx/Apache), Databases (MySQL/PostgreSQL), and DNS.
- **Network Visibility**: Real-time connection tracking and process attribution.
- **File Integrity**: Real-time FIM (File Integrity Monitoring).
- **Threat Detection**: Integrated rule engine with OWASP mapping.
- **Secure**: Automated data sanitization and SQL injection prevention.

---

Built for modern security observability. 🛡️
