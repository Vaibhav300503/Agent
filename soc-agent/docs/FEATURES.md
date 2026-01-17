# Features List

The SOC Platform and Agent ecosystem providing comprehensive security monitoring for hybrid environments.

## 🛡 SOC Agent Features

### Multi-Platform Collectors
- **Windows Event Log Collector**:
  - Security, System, and Application logs.
  - Windows Defender alert extraction.
  - PowerShell & Process creation auditing (Event 4688).
  - Firewall block events (Event 5152/5157).
  - **v2.1.0**: Normalized auth fields (`auth_status`, `auth_method`, `login_type`)
- **Linux Log Collector**:
  - `auth.log`, `syslog`, `messages`, `secure`, and `kern.log`.
  - Application logs: Nginx, Apache, MySQL, PostgreSQL, BIND.
  - WAF-style attack detection (SQLi, XSS, Path Traversal) in web logs.
  - Brute force detection on SSH and Database logins.
  - **v2.1.0**: Separate `query_string` parsing, normalized auth fields

### Advanced Monitoring
- **Network Monitoring**:
  - Continuous snapshotting of active TCP/UDP connections.
  - Bandwidth anomaly detection.
  - Process attribution (which process owns which connection).
  - **v2.1.0**: Connection `duration` tracking, flow metrics placeholders
- **File Integrity Monitoring (FIM)**:
  - Real-time monitoring of sensitive directories (e.g., `/etc`, `C:\Windows\System32`).
  - Detection of file creation, modification, and deletion.
  - Canary file support for ransomware detection.

### Robust Transport
- **Local Buffering**: SQLite-based buffer to ensure no data loss during network outages.
- **Data Sanitization**: Automatic normalization of timestamps and prevention of SQL injection payloads in logs.
- **Heartbeat**: Status reporting every **420 seconds** (7 min) including:
  - Agent uptime, event count, last transmission timestamp
  - Buffer size, log gap detection, health status
- **Batch Transmission**: Logs sent every **200 seconds** for consistent delivery

---

## 🖥 SOC Server (Platform) Features

### Scalable Ingestion
- **Flask-based API**: Optimized for high-throughput log ingestion.
- **Redis Queue**: Asynchronous processing pipeline using a worker-driven architecture.
- **MongoDB Storage**: Time-series optimized storage for raw logs, processed events, and alerts.

### Threat Detection & Enrichment
- **Simple Rule Engine**: 
  - Threshold-based alerting (e.g., 5 failures in 1 min).
  - Pattern matching (regex) on log content.
  - Pre-seeded with **46+ detection rules** including:
    - OWASP Top 10 coverage
    - Network flow analysis (beaconing, exfiltration, port scanning)
    - TLS security (deprecated versions, C2 patterns)
    - Authentication anomalies (credential stuffing, lateral movement, impossible travel)
    - Endpoint threats (parent-child chains, unsigned binaries, registry persistence)
- **GeoIP Enrichment**: Automatically identifies the geographical source of external IP addresses.
- **Intel Integration**: Pre-loaded with detection rules for malware persistence, lateral movement, and more.

### Incident Response
- **TheHive Integration**: Automatically creates cases and alerts in TheHive for high-priority detections.
- **Alert Management**: Aggregated alerting to prevent alert fatigue.

### Dashboard & Analytics
- **Health Monitoring**: API endpoint for real-time cluster and agent status.
- **Statistics API**: Aggregated metrics on logs processed, alerts generated, and active agents.

---

## 📚 Documentation

- [Detection Rules](DETECTION_RULES.md) - Full rule reference with MITRE ATT&CK mappings
- [Log Schema](LOG_SCHEMA.md) - Complete field reference for all log sources
- [Internal Architecture](WORKING.md) - Data flow and implementation details
- [Installation Guide](INSTALLATION.md) - Deployment instructions

