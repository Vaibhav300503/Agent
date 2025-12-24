# Features List

The SOC Platform and Agent ecosystem providing comprehensive security monitoring for hybrid environments.

## 🛡 SOC Agent Features

### Multi-Platform Collectors
- **Windows Event Log Collector**:
  - Security, System, and Application logs.
  - Windows Defender alert extraction.
  - PowerShell & Process creation auditing (Event 4688).
  - Firewall block events (Event 5152/5157).
- **Linux Log Collector**:
  - `auth.log`, `syslog`, `messages`, `secure`, and `kern.log`.
  - Application logs: Nginx, Apache, MySQL, PostgreSQL, BIND.
  - WAF-style attack detection (SQLi, XSS, Path Traversal) in web logs.
  - Brute force detection on SSH and Database logins.

### Advanced Monitoring
- **Network Monitoring**:
  - Continuous snapshotting of active TCP/UDP connections.
  - Bandwidth anomaly detection.
  - Process attribution (which process owns which connection).
- **File Integrity Monitoring (FIM)**:
  - Real-time monitoring of sensitive directories (e.g., `/etc`, `C:\Windows\System32`).
  - Detection of file creation, modification, and deletion.
  - Canary file support for ransomware detection.

### Robust Transport
- **Local Buffering**: SQLite-based buffer to ensure no data loss during network outages.
- **Data Sanitization**: Automatic normalization of timestamps and prevention of SQL injection payloads in logs.
- **Heartbeat**: Continuous status reporting including agent version, IP, and OS type.

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
  - Pre-seeded with **OWASP Top 10** detection rules.
- **GeoIP Enrichment**: Automatically identifies the geographical source of external IP addresses.
- **Intel Integration**: Pre-loaded with detection rules for malware persistence, lateral movement, and more.

### Incident Response
- **TheHive Integration**: Automatically creates cases and alerts in TheHive for high-priority detections.
- **Alert Management**: Aggregated alerting to prevent alert fatigue.

### Dashboard & Analytics
- **Health Monitoring**: API endpoint for real-time cluster and agent status.
- **Statistics API**: Aggregated metrics on logs processed, alerts generated, and active agents.
