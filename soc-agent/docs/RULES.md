# SOC Detection Rules Master Reference (v2.1.0)

This document is the definitive technical reference for all **46+ detection rules** implemented in the SOC Platform. It provides a deep dive into the security rationale, exact technical logic, and actionable response guidance for each rule.

---

## 📑 Table of Contents

- [A01: Broken Access Control](#a01-broken-access-control)
- [A03: Injection](#a03-injection)
- [A07: Identification and Authentication Failures](#a07-identification-and-authentication-failures)
- [A08: Software and Data Integrity Failures](#a08-software-and-data-integrity-failures)
- [Persistence & Evasion (Windows)](#persistence--evasion-windows)
- [Linux System Security](#linux-system-security)
- [Network & Bandwidth Anomaly](#network--bandwidth-anomaly)
- [Endpoint Protection (AV/FIM)](#endpoint-protection-avfim)
- [Enterprise Network Flow (v2.1+)](#enterprise-network-flow-v21)
- [HTTP/Web Enhanced (v2.1+)](#httpweb-enhanced-v21)
- [TLS/SSL Security (v2.1+)](#tlsssl-security-v21)
- [Enterprise Authentication (v2.1+)](#enterprise-authentication-v21)
- [Enterprise Endpoint (v2.1+)](#enterprise-endpoint-v21)

---

## 🛡 A01: Broken Access Control

### OWASP-A01-001: Lateral Movement - Explicit Credentials
*   **Security Rationale**: Detects "Pass-the-Hash" or "Pass-the-Ticket" style behavior where an attacker uses legitimate credentials to jump from one compromised host to another.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Windows Security Log
    *   **Event ID**: `4648` (A logon was attempted using explicit credentials)
    *   **Threshold**: 5 events in 60 minutes
    *   **Group By**: `source_host`
*   **MITRE ATT&CK**: [T1550.004](https://attack.mitre.org/techniques/T1550/004/)
*   **False Positive Mitigation**: Legitimate administrative use of `runas` to manage remote servers.
*   **Response**: Identify the source host and the credentials being used. Audit if the user should be logging into the destination servers.

### OWASP-A01-002: Unauthorized Object Access Attempts
*   **Security Rationale**: Identifies mass unauthorized access to files or directories, often a precursor to data exfiltration or ransomware.
*   **Risk Level**: **Medium**
*   **Technical Logic**:
    *   **Data Source**: Windows Security Log
    *   **Event ID**: `4663` (An attempt was made to access an object)
    *   **Filter**: `access_mask` matches `0x2` (Write), `0x10000` (Delete), or `0x10` (Execute).
    *   **Threshold**: 15 events in 5 minutes
    *   **Group By**: `user_name`
*   **MITRE ATT&CK**: [T1005](https://attack.mitre.org/techniques/T1005/)
*   **False Positive Mitigation**: Automated backup software or bulk file renaming/movement by authorized users.
*   **Response**: Review the specific files being accessed and the permissions of the user.

### OWASP-A01-003: Unauthorized Privilege Grant Attempt
*   **Security Rationale**: Immediate alert when a user is granted extreme administrative privileges that could allow system control.
*   **Risk Level**: **Critical**
*   **Technical Logic**:
    *   **Data Source**: Windows Security Log (System/Security)
    *   **Event ID**: `4704` (User right assigned) or `4717` (System security access granted)
    *   **Filter**: `privilege_list` contains `SeDebugPrivilege`, `SeLoadDriverPrivilege`, or `SeTakeOwnershipPrivilege`.
*   **MITRE ATT&CK**: [T1134](https://attack.mitre.org/techniques/T1134/), [T1548](https://attack.mitre.org/techniques/T1548/)
*   **False Positive Mitigation**: Scheduled security configuration updates or software installers.
*   **Response**: Directly contact the admin who granted the privilege. Audit the receiving account immediately.

---

## 💉 A03: Injection

### OWASP-A03-001: SQL Injection Attempt
*   **Security Rationale**: Attacks targeting the database layer to dump user data, bypass logins, or modify records.
*   **Risk Level**: **Critical**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs (Nginx/Apache) / WAF logs
    *   **Rule**: RegEx match in message/payload: `(UNION.*SELECT)|(OR\s+1\s*=\\s*1)|(EXEC\b)|(DROP\b)|('\s*;\\s*--)`
*   **MITRE ATT&CK**: [T1190](https://attack.mitre.org/techniques/T1190/)
*   **False Positive Mitigation**: Legitimate technical blogs or documentation sites where code snippets are shared (rare in production logs).
*   **Response**: Block the source IP at the firewall immediately. Review application logs to see if the injection was successful.

### OWASP-A03-002: OS Command Injection Attempt
*   **Security Rationale**: High-confidence detection of attackers trying to execute shell commands (e.g., `whoami`) on the server.
*   **Risk Level**: **Critical**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs / API logs
    *   **Rule**: RegEx match for metacharacters followed by commands: `[;|\\&\\$\\(\\)]\s*(whoami|id|cat|ls|pwd|ping|net|ipconfig)`
*   **MITRE ATT&CK**: [T1059](https://attack.mitre.org/techniques/T1059/)
*   **False Positive Mitigation**: API endpoints that legitimately accept shell-like parameters (highly dangerous design).
*   **Response**: Isolate the server and check for unauthorized files (web shells).

---

## 🔑 A07: Identification and Authentication Failures

### OWASP-A07-001: Brute-Force Login Attempt
*   **Security Rationale**: Identifies automated attempts to guess passwords for a single account.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Windows Security Log / Linux Auth logs
    *   **Event ID/Type**: `4625` (An account failed to log on)
    *   **Threshold**: 10 failed attempts in 10 minutes
    *   **Group By**: `source_ip`
*   **MITRE ATT&CK**: [T1110](https://attack.mitre.org/techniques/T1110/)
*   **False Positive Mitigation**: Users with old cached credentials on mobile devices or locked workstations.
*   **Response**: Block source IP if external. Check if account lockouts are being triggered.

---

## 🖥 Persistence & Evasion (Windows)

### SOC-WIN-001: Scheduled Task Creation (Persistence)
*   **Security Rationale**: Common persistence mechanism. Attackers create tasks to re-download malware or execute payloads after system reboot.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Windows Security Log
    *   **Event ID**: `4698` (A scheduled task was created)
    *   **Filter**: `user_name` is NOT `SYSTEM`.
*   **MITRE ATT&CK**: [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
*   **False Positive Mitigation**: Legitimate software installations or IT admin maintenance tasks.
*   **Response**: Inspect the task details (command line, schedule). Verify the binary being pointed to.

### SOC-WIN-002: Service Binary Path Modification
*   **Security Rationale**: High-impact evasion technique. Replacing a path for an existing system service with a malicious binary.
*   **Risk Level**: **Critical**
*   **Technical Logic**:
    *   **Data Source**: Windows Registry Audit (Sysmon/Security)
    *   **Event ID**: `4657` (A registry value was modified)
    *   **Details**: Target key contains `Services` and target value is `ImagePath`.
*   **MITRE ATT&CK**: [T1574.011](https://attack.mitre.org/techniques/T1574/011/)
*   **False Positive Mitigation**: Major Windows updates or service pack installations.
*   **Response**: Immediately verify the existing service file. Check for unrecognized binaries in `System32`.

---

## 📡 Network & Bandwidth Anomaly

### SOC-NET-001: High Bandwidth Anomaly
*   **Security Rationale**: Identifies abnormal traffic patterns which could mean data exfiltration (outbound) or DDoS (inbound).
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Agent Bandwidth Monitor (psutil)
    *   **Metric**: Significant spike above moving 24-hour average.
*   **MITRE ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/), [T1498](https://attack.mitre.org/techniques/T1498/)
*   **False Positive Mitigation**: Scheduled database backups or large file transfers.
*   **Response**: Trace the process generating the traffic and the destination IP.

---

## 📈 Enterprise Network Flow (v2.1+)

### SOC-NET-003: Data Exfiltration - High Bytes Sent
*   **Security Rationale**: Specifically monitors for massive outbound data transfers from internal hosts.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Network Bandwidth Collector
    *   **Filter**: `direction` == "outbound" AND `volume_mb` >= 100
    *   **Threshold**: 3 spikes in 1 hour
    *   **Group By**: `hostname`
*   **MITRE ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/)
*   **Response**: Check if the host is a known backup server. Inspect `dst_ip` for geographic anomalies.

### SOC-NET-004: Beaconing Detection
*   **Security Rationale**: Identifies consistent, low-frequency connections typical of malware check-ins.
*   **Risk Level**: **Medium**
*   **Technical Logic**:
    *   **Data Source**: Network Connection Snapshots
    *   **Filter**: `status` == "ESTABLISHED" AND `bytes_sent` < 1000
    *   **Threshold**: 10 consistent connections in 30 minutes
    *   **Group By**: `dst_ip`, `hostname`
*   **MITRE ATT&CK**: [T1071](https://attack.mitre.org/techniques/T1071/)
*   **Response**: Perform a reputation check on the destination IP. Inspect the process creating the connection.

---

## 🌐 HTTP/Web Enhanced (v2.1+)

### SOC-HTTP-002: XSS Attack Pattern Detection
*   **Security Rationale**: Prevents scripts from being injected into user sessions via query parameters.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs
    *   **Filter**: RegEx for `<script>`, `javascript:`, `onerror`, `onload`, `<iframe>`, `svg`.
*   **MITRE ATT&CK**: [T1189](https://attack.mitre.org/techniques/T1189/)
*   **Response**: Sanitize application inputs. Verify if any user data was compromised.

### SOC-HTTP-004: Directory Traversal Attack
*   **Security Rationale**: Attacks attempting to "break out" of the web directory to read sensitive files (e.g., `.env`, `passwd`).
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs (URI parsing)
    *   **Filter**: RegEx for `../`, `..\`, `/etc/passwd`, `c:\\windows`.
*   **MITRE ATT&CK**: [T1083](https://attack.mitre.org/techniques/T1083/)
*   **Response**: Check if the application allows file inclusion. Harden the web server config.

---

## 🔐 TLS/SSL Security (v2.1+)

### SOC-TLS-001: Deprecated TLS Version Usage
*   **Security Rationale**: Identifies traffic that is vulnerable to man-in-the-middle decryption.
*   **Risk Level**: **Medium**
*   **Technical Logic**:
    *   **Data Source**: TLS/SSL Collector
    *   **Filter**: `tls_version` in `[TLSv1.0, TLSv1.1, SSLv3, SSLv2]`.
*   **Response**: Update server configuration to disable legacy protocols.

### SOC-TLS-002: Suspicious Encrypted C2 Pattern
*   **Security Rationale**: Traffic that is encrypted but has beacon-like timing and low data volume.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: TLS Collector + Flow Metrics
    *   **Threshold**: 15 connections in 1 hour
    *   **Group By**: `sni` (Server Name Indication), `hostname`
*   **MITRE ATT&CK**: [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
*   **Response**: Identify if the SNI is a known legitimate service. If unusual, block the domain.

---

## 🏢 Enterprise Authentication (v2.1+)

### SOC-AUTH-004: Lateral Movement Detection
*   **Security Rationale**: High-confidence alert for an account that has already been compromised.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Unified Auth Logs
    *   **Filter**: `auth_status` == "success" AND `login_type` in [Network, RemoteInteractive, ssh]
    *   **Threshold**: 5 unique hostnames in 15 minutes
    *   **Group By**: `username`
*   **MITRE ATT&CK**: [T1550](https://attack.mitre.org/techniques/T1550/)
*   **Response**: Disable the account immediately. Force password reset. Investigate the first source of logon.

### SOC-AUTH-005: Impossible Travel Detection
*   **Security Rationale**: Detects account compromise when a user logs in from two geographically distant locations faster than physical travel allows.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Unified Auth Logs + GeoIP Enrichment
    *   **Threshold**: 2 unique `geoip_country` values in 2 hours
    *   **Group By**: `username`
*   **MITRE ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/)
*   **Response**: Verify if the user is using a VPN. If not, reset session tokens and passwords.

---

## 🧬 Enterprise Endpoint (v2.1+)

### SOC-EP-001: Suspicious Parent-Child Process Chain
*   **Security Rationale**: Identifies fileless malware or macro-based exploitation.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Windows Process Creation (4688) / Linux Audited
    *   **Filter**: Parent is `winword`, `excel`, `chrome`, etc.; Child is `cmd`, `powershell`, `wscript`.
*   **MITRE ATT&CK**: [T1055](https://attack.mitre.org/techniques/T1055/), [T1059](https://attack.mitre.org/techniques/T1059/)
*   **Response**: Kill the suspicious child process. Isolate the endpoint.

### SOC-REG-001: Registry Persistence Attempt
*   **Security Rationale**: Critical monitoring of Windows "Run" keys often abused by malware to gain persistence.
*   **Risk Level**: **Critical**
*   **Technical Logic**:
    *   **Data Source**: Windows Registry Audit (4657)
    *   **Filter**: `registry_key` matches `Run`, `RunOnce`, `Winlogon`, `Shell`.
*   **MITRE ATT&CK**: [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
---

## 📉 Low Severity & Supplemental Rules

### SOC-LOW-001: Unusual 404 Error Count
*   **Security Rationale**: Identifies background noise scanning or targeted directory brute-force attempts.
*   **Risk Level**: **Low**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs
    *   **Condition**: `status_code` == 404
    *   **Threshold**: 50 events in 10 minutes
    *   **Group By**: `source_ip`
*   **MITRE ATT&CK**: [T1595](https://attack.mitre.org/techniques/T1595/)
*   **Response**: Check if the IP is a known search engine crawler. If not, consider blocking if the rate increases.

### SOC-LOW-002: Scripting User-Agent Usage
*   **Security Rationale**: Detects automated tools (curl, wget, python-requests) interacting with the web front-end.
*   **Risk Level**: **Low**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs (User-Agent header)
    *   **Filter**: RegEx match for `curl|wget|python-requests|Go-http-client`.
*   **MITRE ATT&CK**: [T1583](https://attack.mitre.org/techniques/T1583/)

### SOC-LOW-003: Access to Sensitive Web Patterns
*   **Security Rationale**: Detects "door knocking" on critical configuration files that should not be public.
*   **Risk Level**: **Low**
*   **Technical Logic**:
    *   **Data Source**: Web Server Logs (URI)
    *   **Filter**: RegEx match for `.env`, `config.php`, `.git`, `web.config`, `/etc/passwd`.
*   **MITRE ATT&CK**: [T1083](https://attack.mitre.org/techniques/T1083/)

### SOC-LOW-004: Clearing Bash History
*   **Security Rationale**: Detects an attacker trying to hide their tracks after a manual compromise of a Linux shell.
*   **Risk Level**: **Low**
*   **Technical Logic**:
    *   **Data Source**: Linux Syslog / Shell History
    *   **Filter**: RegEx for `history -c` or `unset HISTFILE`.
*   **MITRE ATT&CK**: [T1070.003](https://attack.mitre.org/techniques/T1070/003/)
*   **Response**: Immediately audit the active session and origin of the user.

### SOC-LOW-007: Unusual Remote Login Time
*   **Security Rationale**: Identifies potential account compromise or insider threat activity outside of normal business hours.
*   **Risk Level**: **Low**
*   **Technical Logic**:
    *   **Data Source**: Unified Auth Logs
    *   **Condition**: Successful login AND `is_after_hours` == True.
*   **MITRE ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/)
*   **Response**: Cross-reference with known maintenance windows or authorized overtime.

---

## 🛡 Endpoint Protection (AV/FIM)

### SOC-FIM-001: Ransomware Canary Alert
*   **Security Rationale**: Earliest possible warning of ransomware encryption activity.
*   **Risk Level**: **Critical**
*   **Technical Logic**:
    *   **Data Source**: Agent FIM Collector
    *   **Condition**: `event_type` == "canary_file_alert"
*   **MITRE ATT&CK**: [T1486](https://attack.mitre.org/techniques/T1486/)
*   **Response**: **Isolate the host immediately via the network firewall.** Shut down the machine once volatile memory is captured.

### SOC-AV-001: Malware Detection Alert
*   **Security Rationale**: Legacy AV detected a persistent thread.
*   **Risk Level**: **High**
*   **Technical Logic**:
    *   **Data Source**: Windows Defender logs
    *   **Condition**: `log_source` == "windows_defender"
*   **MITRE ATT&CK**: [T1204.002](https://attack.mitre.org/techniques/T1204/002/)
*   **Response**: Verify if the AV was able to successfully quarantine/remove the file. If not, manual remediation is required.

---

## 🏗 Summary Table of Rules

| ID | Name | Severity | MITRE |
|:---|:---|:---|:---|
| OWASP-A01-003 | Unauthorized Privilege Grant | Critical | T1548 |
| OWASP-A03-001 | SQL Injection Attempt | Critical | T1190 |
| OWASP-A03-002 | OS Command Injection | Critical | T1059 |
| SOC-WIN-002 | Service Path Modification | Critical | T1574.011 |
| SOC-LX-001 | Sudoers Modification | Critical | T1548.003 |
| SOC-FIM-001 | Ransomware Canary Alert | Critical | T1486 |
| SOC-REG-001 | Registry Persistence | Critical | T1547.001 |
| OWASP-A01-001 | Lateral Movement | High | T1550.004 |
| OWASP-A07-001 | Brute-Force Login | High | T1110 |
| SOC-WIN-001 | Scheduled Task Creation | High | T1053.005 |
| SOC-NET-001 | High Bandwidth Anomaly | High | T1048 |
| SOC-AV-001 | Malware Detection Alert | High | T1204.002 |
| SOC-AUTH-005 | Impossible Travel | High | T1078 |
| SOC-EP-001 | Suspicious Parent-Child | High | T1055 |
| SOC-NET-004 | Beaconing Detection | Medium | T1071 |
| SOC-TLS-001 | Deprecated TLS | Medium | T1573.001 |
| SOC-LOW-001 | Unusual 404 Count | Low | T1595 |
