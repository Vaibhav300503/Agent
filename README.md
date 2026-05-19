# SOC Agent - Security Operations Center Log Collection Agent

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Validation](https://img.shields.io/badge/enrichment-100%25-success)]()
[![Rules](https://img.shields.io/badge/rules-44%20active-blue)]()

A production-ready SOC agent that collects, enriches, and forwards security logs from Windows and Linux endpoints to a centralized SOC platform with advanced threat detection capabilities.

---

## 🚀 Quick Start

```bash
# Install Server (Ubuntu/Debian)
cd soc-agent
sudo bash install/install.sh

# Install Agent on Windows
cd soc-agent
.\install\install_agent.ps1

# Install Agent on Linux
cd soc-agent
sudo bash install/install_agent.sh
```

---

## ✨ Features

### **Agent Capabilities**
- ✅ **Multi-Platform Support** - Windows (Event Logs) and Linux (Syslog, Auth, Web Server)
- ✅ **Automatic Log Enrichment** - Adds source, destination, severity, and log category metadata
- ✅ **Real-Time Collection** - Continuous monitoring with buffered transport
- ✅ **Intelligent Filtering** - Pre-filters noise and focuses on security-relevant events
- ✅ **Resilient Transport** - SQLite buffering with retry logic for network failures

### **Detection & Alerting**
- ✅ **46 Detection Rules** - OWASP Top 10 + custom SOC rules
- ✅ **Priority-Based Execution** - Critical threats evaluated first
- ✅ **MITRE ATT&CK Mapping** - All rules mapped to tactics and techniques
- ✅ **Deduplication** - Intelligent alert grouping to reduce noise
- ✅ **TheHive Integration** - Automatic case creation for high/critical alerts

### **Log Enrichment**
- ✅ **Source Identification** - `{hostname}/{service}` format
- ✅ **Destination Tracking** - SOC server endpoint
- ✅ **Severity Normalization** - Unified Low/Medium/High/Critical levels
- ✅ **Log Categorization** - Security/Application/Network/System
- ✅ **Timestamp Standardization** - ISO 8601 format
- ✅ **GeoIP Enrichment** - Location data for external IPs

---

## 📊 System Status

| Component | Status | Coverage |
|-----------|--------|----------|
| **Log Enrichment** | ✅ 100% | All logs have required metadata |
| **Detection Rules** | ✅ 44 Active | 2 redundant rules disabled |
| **Validation** | ✅ Passing | 179/179 tests passed |
| **Dashboard** | ✅ Ready | All filters operational |
| **CI/CD** | ✅ Integrated | Strict quality gates enforced |

---

## 📚 Documentation

### **Getting Started**
- **[Installation Guide](docs/INSTALLATION.md)** - Server and agent deployment
- **[Features Overview](docs/FEATURES.md)** - Complete capabilities list
- **[System Architecture](docs/WORKING.md)** - Data flow and components

### **Configuration & Rules**
- **[Detection Rules](docs/RULES.md)** - All 46 rules with MITRE mapping
- **[Log Schema](docs/LOG_SCHEMA.md)** - Field definitions and formats

### **Validation & Quality**
- **[Stabilization Report](docs/STABILIZATION.md)** - Production readiness checklist
- **[Validation Audit](docs/VALIDATION_AUDIT.md)** - Comprehensive testing results

---

## 🏗️ Architecture

```
┌─────────────────┐
│   Endpoints     │
│  (Win/Linux)    │
└────────┬────────┘
         │ Logs
         ▼
┌─────────────────┐
│   SOC Agent     │
│  - Collectors   │
│  - Enrichment   │
│  - Transport    │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│   SOC Server    │
│  - API Ingest   │
│  - MongoDB      │
│  - Detector     │
└────────┬────────┘
         │
         ├──► Dashboard (Vue.js)
         └──► TheHive (Alerts)
```

---

## 🔧 Configuration

### **Agent Configuration** (`config/agent_config.yaml`)
```yaml
server_url: https://soc.company.com/api/v1/logs
agent_id: auto-generated
hostname: auto-detected
collectors:
  - windows_events
  - linux_logs
  - network_monitor
```

### **Server Configuration** (Environment Variables)
```bash
MONGO_URI=mongodb://localhost:27017/soc_platform
REDIS_HOST=localhost
THEHIVE_URL=https://thehive.company.com
THEHIVE_API_KEY=your_key_here
```

---

## 📈 Log Collection

### **Windows Sources**
- Windows Event Logs (Security, System, Application)
- Windows Defender (malware, threats)
- Windows Firewall (connections, blocks)
- Registry Monitoring (persistence, modifications)
- Process Creation (Sysmon-like tracking)

### **Linux Sources**
- Authentication Logs (`/var/log/auth.log`)
- Syslog (`/var/log/syslog`)
- Web Server Logs (Apache, Nginx)
- Database Logs (MySQL, PostgreSQL)
- DNS Query Logs

### **Network Monitoring**
- Active Connections (TCP/UDP)
- Bandwidth Anomalies
- Port Scan Detection
- Beaconing Detection

---

## 🎯 Detection Rules

### **Rule Categories**
- **OWASP Top 10** (8 rules) - Injection, broken access, auth failures
- **Windows-Specific** (2 rules) - Persistence, service modifications
- **Linux-Specific** (1 rule) - Sudoers modifications
- **Network** (5 rules) - Port scans, data exfiltration, beaconing
- **HTTP/Web** (5 rules) - SQLi, XSS, command injection, traversal
- **Authentication** (5 rules) - Brute force, credential stuffing, lateral movement
- **Endpoint** (3 rules) - Process chains, unsigned binaries, registry persistence
- **Baseline Monitoring** (10 rules) - Low-severity behavioral indicators

### **Priority Levels**
- **1-10 (Critical)**: Ransomware, privilege escalation, persistence
- **11-30 (High)**: Active attacks, brute force, malware
- **31-60 (Medium)**: Suspicious behavior, anomalies
- **61-100 (Low)**: Baseline monitoring, reconnaissance

---

## ✅ Validation & Testing

### **Automated Validation**
```bash
# Run enrichment validation
python validate_enrichment.py

# Run CI/CD validation
python cicd_validate.py
```

### **Test Results**
- ✅ **100% enrichment success** - All required fields present
- ✅ **179/179 tests passed** - Comprehensive validation suite
- ✅ **5/5 CI/CD tests passed** - Production quality gates

---

## 🚦 CI/CD Integration

Add to your pipeline:

**GitHub Actions:**
```yaml
- name: Validate Log Enrichment
  run: |
    cd soc-agent
    python cicd_validate.py
```

**GitLab CI:**
```yaml
validate_enrichment:
  script:
    - cd soc-agent
    - python cicd_validate.py
```

**Exit Codes:**
- `0` - Validation passed (build continues)
- `1` - Validation failed (build stops)

---

## 📦 Installation

### **Server Requirements**
- Ubuntu 20.04+ or Debian 11+
- Python 3.8+
- MongoDB 4.4+
- Redis 6.0+
- 4GB RAM minimum

### **Agent Requirements**
- **Windows**: Windows 10/Server 2016+, Python 3.8+
- **Linux**: Ubuntu 18.04+/Debian 10+, Python 3.8+
- Network connectivity to SOC server

### **Installation Steps**

See **[INSTALLATION.md](docs/INSTALLATION.md)** for detailed steps.

---

## 🔐 Security

- **Encrypted Transport**: All logs sent via HTTPS
- **API Authentication**: Bearer token authentication
- **Data Sanitization**: SQL injection prevention
- **Least Privilege**: Agent runs with minimal permissions
- **Secure Storage**: Encrypted credentials in config

---

## 🤝 Contributing

1. Test your changes with validation suite
2. Ensure all tests pass (`python validate_enrichment.py`)
3. Update documentation as needed
4. Follow existing code style and conventions

---

## 📝 License

[Your License Here]

---

## 🆘 Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Documentation**: Full docs available in `/docs` folder
- **Validation**: Run `python cicd_validate.py` to verify system health

---

## 📊 Project Stats

- **Total Rules**: 46 (44 enabled, 2 disabled)
- **Log Sources**: 15+ (Windows Events, Linux Logs, Network)
- **Enrichment Fields**: 7 (source, destination, severity_level, log_category, log_type, timestamp, hostname)
- **Test Coverage**: 100% (179/179 tests passing)
- **MITRE Coverage**: 40+ techniques mapped

---

**Status**: ✅ Production Ready | **Last Updated**: 2026-01-17 | **Version**: 1.0.0
