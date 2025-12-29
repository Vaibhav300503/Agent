# Detection Rules Reference

Complete reference of all detection rules in the SOC Platform, including MITRE ATT&CK mappings.

## Rule Categories

| Category | Count | Coverage |
|----------|-------|----------|
| Access Control (OWASP A01) | 3 | Lateral movement, object access, privilege escalation |
| Injection (OWASP A03) | 2 | SQL injection, command injection |
| Authentication (OWASP A07) | 5 | Brute-force, credential stuffing, impossible travel |
| Integrity (OWASP A08) | 1 | Insecure deserialization |
| Network/Bandwidth | 5 | Port scanning, beaconing, data exfiltration |
| HTTP/Web | 6 | SQLi, XSS, path traversal, command injection |
| TLS/SSL | 2 | Deprecated TLS, suspicious C2 |
| Endpoint/Process | 2 | Parent-child chains, unsigned binaries |
| Registry | 1 | Persistence attempts |
| FIM | 1 | Ransomware canary |
| AV/Malware | 1 | Defender detections |
| Application | 2 | Database brute-force, web DoS |

---

## Rule Severity Levels

| Severity | Action Required | Examples |
|----------|-----------------|----------|
| **critical** | Immediate investigation | SQL injection, registry persistence, ransomware |
| **high** | Investigate within 1 hour | Port scanning, credential stuffing, data exfiltration |
| **medium** | Investigate within 24 hours | Failed logins, deprecated TLS, unsigned binaries |
| **low** | Review periodically | Scripting user-agents, 404 patterns, after-hours login |

---

## Network Rules

### SOC-NET-001: High Bandwidth Anomaly
- **Severity**: high
- **MITRE**: T1048, T1498
- **Description**: Detection of significant spikes in network bandwidth
- **Required Fields**: `log_source`, `direction`, `volume_mb`

### SOC-NET-002: Potential Port Scan Detected
- **Severity**: high  
- **MITRE**: T1595.001
- **Description**: Heuristic detection of multiple unique ports blocked from a single source IP
- **Required Fields**: `event_type`, `source_ip`

### SOC-NET-003: Data Exfiltration - High Bytes Sent
- **Severity**: high
- **MITRE**: T1048
- **Description**: Unusually high bytes_sent from single endpoint
- **Required Fields**: `direction`, `volume_mb`, `hostname`
- **False Positives**: Large file uploads, backups, video conferencing

### SOC-NET-004: Beaconing Detection
- **Severity**: medium
- **MITRE**: T1071, T1573
- **Description**: Periodic C2 beaconing patterns with consistent timing
- **Required Fields**: `status`, `bytes_sent`, `dst_ip`, `hostname`

### SOC-NET-005: Port Scan - High Packet Rate
- **Severity**: high
- **MITRE**: T1595.001
- **Description**: Rapid connection attempts to multiple ports
- **Required Fields**: `packets_sent`, `src_ip`

---

## HTTP/Web Rules

### SOC-HTTP-001: Enhanced SQL Injection Detection
- **Severity**: critical
- **MITRE**: T1190
- **Description**: Advanced SQLi patterns including UNION, boolean, time-based
- **Required Fields**: `query_string`

### SOC-HTTP-002: XSS Attack Pattern Detection
- **Severity**: high
- **MITRE**: T1189
- **Description**: Cross-site scripting attempt detection
- **Required Fields**: `query_string`

### SOC-HTTP-003: Command Injection Attempt
- **Severity**: critical
- **MITRE**: T1059
- **Description**: OS command injection patterns in web requests
- **Required Fields**: `query_string`

### SOC-HTTP-004: Directory Traversal Attack
- **Severity**: high
- **MITRE**: T1083
- **Description**: Path traversal attempts to access files outside webroot
- **Required Fields**: `uri`

### SOC-HTTP-005: Abnormal 5xx Error Rate
- **Severity**: medium
- **MITRE**: T1499
- **Description**: High rate of server errors
- **Required Fields**: `status_code`, `hostname`

---

## TLS/SSL Rules

### SOC-TLS-001: Deprecated TLS Version Usage
- **Severity**: medium
- **MITRE**: T1573.001
- **Description**: Detection of insecure TLS versions (1.0, 1.1, SSLv3)
- **Required Fields**: `tls_version`

### SOC-TLS-002: Suspicious Encrypted C2 Pattern
- **Severity**: high
- **MITRE**: T1071.001, T1573
- **Description**: Low-volume encrypted connections with repeated patterns
- **Required Fields**: `tls_version`, `bytes_sent`, `sni`, `hostname`

---

## Authentication Rules

### SOC-AUTH-003: Enhanced Credential Stuffing Detection
- **Severity**: high
- **MITRE**: T1110.004
- **Description**: Multiple accounts targeted from single IP
- **Required Fields**: `auth_status`, `source_ip`, `username`

### SOC-AUTH-004: Lateral Movement Detection
- **Severity**: high
- **MITRE**: T1550, T1021
- **Description**: Single account authenticating to multiple hosts rapidly
- **Required Fields**: `auth_status`, `login_type`, `username`, `hostname`

### SOC-AUTH-005: Impossible Travel Detection
- **Severity**: high
- **MITRE**: T1078
- **Description**: Same user logging in from geographically distant locations
- **Required Fields**: `auth_status`, `username`, `geoip_country`

---

## Endpoint Rules

### SOC-EP-001: Suspicious Parent-Child Process Chain
- **Severity**: high
- **MITRE**: T1055, T1059
- **Description**: Unusual process spawning patterns (e.g., Office spawning cmd)
- **Required Fields**: `parent_process`, `process_name`

### SOC-EP-002: Unsigned Binary Execution
- **Severity**: medium
- **MITRE**: T1553.002
- **Description**: Execution of unsigned or invalidly signed binaries
- **Required Fields**: `signature_status`

### SOC-REG-001: Registry Persistence Attempt
- **Severity**: critical
- **MITRE**: T1547.001, T1543.003
- **Description**: Modification of registry Run keys or services for persistence
- **Required Fields**: `event_code`, `registry_key`

---

## Adding Custom Rules

To add custom detection rules, insert them into `server/seed_owasp_rules.py`:

```python
{
    "rule_id": "CUSTOM-001",
    "name": "Custom Rule Name",
    "description": "What this rule detects",
    "severity": "high",  # critical, high, medium, low
    "enabled": True,
    "conditions": {
        "filters": [
            {"field": "log_source", "operator": "eq", "value": "web_server"}
        ],
        "threshold": 5,
        "timeframe": "5m",
        "group_by": ["source_ip"]
    },
    "mitre_technique": ["T1190"],
    "false_positive_notes": "Known false positive scenarios"
}
```

Then run: `python seed_owasp_rules.py` to load the rules into MongoDB.
