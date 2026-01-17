import os
from pymongo import MongoClient
from datetime import datetime

# Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
DB_NAME = MONGO_URI.split("/")[-1] if "/" in MONGO_URI else "soc_platform"

def seed_rules():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    
    rules = [
        # --- A01: Broken Access Control ---
        {
            "rule_id": "OWASP-A01-001",
            "name": "Lateral Movement - Explicit Credentials",
            "description": "Detection of Event ID 4648 indicating logon using explicit credentials across different servers.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_code": 4648,
                "threshold": 5,
                "timeframe": "60m",
                "group_by": ["source_host"]
            },
            "mitre_technique": ["T1550.004"]
        },
        {
            "rule_id": "OWASP-A01-002",
            "name": "Unauthorized Object Access Attempts",
            "description": "Multiple attempts to access objects with WRITE/DELETE masks (Event ID 4663).",
            "severity": "medium",
            "enabled": True,
            "conditions": {
                "event_code": 4663,
                "filters": [
                    {"field": "access_mask", "operator": "regex", "value": "0x2|0x10000|0x10"}
                ],
                "threshold": 15,
                "timeframe": "5m",
                "group_by": ["user_name"]
            },
            "mitre_technique": ["T1005"]
        },
        {
            "rule_id": "OWASP-A01-003",
            "name": "Unauthorized Privilege Grant Attempt",
            "description": "User right assigned or Access rights granted by non-admin (Event 4704/4717).",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "event_code": [4704, 4717],
                "filters": [
                    {"field": "privilege_list", "operator": "regex", "value": "SeDebugPrivilege|SeLoadDriverPrivilege|SeTakeOwnershipPrivilege"}
                ]
            },
            "mitre_technique": ["T1134", "T1548"]
        },
        
        # --- A03: Injection ---
        {
            "rule_id": "OWASP-A03-001",
            "name": "SQL Injection Attempt",
            "description": "Detection of common SQL injection patterns in HTTP request data.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "message", "operator": "regex", "value": "(UNION.*SELECT)|(OR\\s+1\\s*=\\s*1)|(EXEC\\b)|(DROP\\b)|('\\s*;\\s*--)"}
                ]
            },
            "mitre_technique": ["T1190"]
        },
        {
            "rule_id": "OWASP-A03-002",
            "name": "OS Command Injection Attempt",
            "description": "Detection of shell metacharacters and commands in HTTP parameters.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "message", "operator": "regex", "value": "[;|\\&\\$\\(\\)]\\s*(whoami|id|cat|ls|pwd|ping|net|ipconfig)"}
                ]
            },
            "mitre_technique": ["T1059"]
        },

        # --- A07: Identification and Authentication Failures ---
        {
            "rule_id": "OWASP-A07-001",
            "name": "Brute-Force Login Attempt",
            "description": "High volume of failed login attempts from a single source.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_code": 4625,
                "threshold": 10,
                "timeframe": "10m",
                "group_by": ["source_ip"]
            },
            "mitre_technique": ["T1110"]
        },
        {
            "rule_id": "OWASP-A07-002",
            "name": "Credential Stuffing Signature",
            "description": "Login attempts to many different accounts from a single IP.",
            "severity": "medium",
            "enabled": True,
            "conditions": {
                "event_code": 4625,
                "threshold": 5,
                "timeframe": "5m",
                "group_by": ["source_ip"],
                "group_by_fields": ["user_name"] # Not strictly supported by engine yet, but useful metadata
            },
            "mitre_technique": ["T1110.004"]
        },

        # --- A08: Software and Data Integrity Failures ---
        {
            "rule_id": "OWASP-A08-001",
            "name": "Insecure Deserialization Attempt",
            "description": "Detection of Java/Python serialization markers in HTTP traffic.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "message", "operator": "regex", "value": "rO0AB|0xACED0005|pickle\\.load|BinaryFormatter"}
                ]
            },
            "mitre_technique": ["T1190"]
        },

        # --- Persistence & Evasion (Windows Specific) ---
        {
            "rule_id": "SOC-WIN-001",
            "name": "Scheduled Task Creation (Persistence)",
            "description": "A new scheduled task was created, often used for persistence.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_code": 4698,
                "filters": [
                    {"field": "user_name", "operator": "neq", "value": "SYSTEM"}
                ]
            },
            "mitre_technique": ["T1053.005"]
        },
        {
            "rule_id": "SOC-WIN-002",
            "name": "Service Binary Path Modification",
            "description": "Modification of a service's executable path in the registry.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "event_code": 4657,
                "filters": [
                    {"field": "object_name", "operator": "contains", "value": "Services"},
                    {"field": "object_name", "operator": "contains", "value": "ImagePath"}
                ]
            },
            "mitre_technique": ["T1574.011"]
        },

        # --- Linux Specific ---
        {
            "rule_id": "SOC-LX-001",
            "name": "Unauthorized sudoers Modification",
            "description": "Modification of the /etc/sudoers file by a non-root user.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "log_source", "operator": "contains", "value": "sudoers"},
                    {"field": "event_action", "operator": "eq", "value": "write"}
                ]
            },
            "mitre_technique": ["T1548.003"]
        },

        # --- Low Severity & Supplemental Rules ---
        {
            "rule_id": "SOC-LOW-001",
            "name": "Unusual 404 Error Count",
            "description": "Possible directory brute-force or scanning activity.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [{"field": "status_code", "operator": "eq", "value": 404}],
                "threshold": 50,
                "timeframe": "10m",
                "group_by": ["source_ip"]
            },
            "mitre_technique": ["T1595"]
        },
        {
            "rule_id": "SOC-LOW-002",
            "name": "Scripting User-Agent Usage",
            "description": "Detection of automated scripting tools (curl, wget).",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "user_agent", "operator": "regex", "value": "curl|wget|python-requests|Go-http-client"}
                ]
            },
            "mitre_technique": ["T1583"]
        },
        {
            "rule_id": "SOC-LOW-003",
            "name": "Access to Sensitive Web Patterns",
            "description": "Attempts to access .env, config, or .git directories.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "request_path", "operator": "regex", "value": "\\.env|config\\.php|\\.git|web\\.config|/etc/passwd"}
                ]
            },
            "mitre_technique": ["T1083"]
        },
        {
            "rule_id": "SOC-LOW-004",
            "name": "Clearing Bash History",
            "description": "User attempting to hide traces by clearing bash history.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "message", "operator": "regex", "value": "history -c|unset HISTFILE"}
                ]
            },
            "mitre_technique": ["T1070.003"]
        },
        {
            "rule_id": "SOC-LOW-005",
            "name": "Account Created and Group Added",
            "description": "New account created and immediately added to a group (suspicious behavior).",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "event_code": [4720, 4728],
                "threshold": 2,
                "timeframe": "5m",
                "group_by": ["subject_user"]
            },
            "mitre_technique": ["T1136"]
        },
        {
            "rule_id": "SOC-LOW-006",
            "name": "Password Policy Change",
            "description": "Modification of domain or local password policy.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "event_code": 4739
            },
            "mitre_technique": ["T1484"]
        },
        {
            "rule_id": "SOC-LOW-007",
            "name": "Unusual Remote Login Time",
            "description": "Login activity outside of normal business hours (8 AM - 6 PM).",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "event_code": [4624, "ssh_successful_login"],
                "filters": [
                    # This rule might need engine support for time-of-day, 
                    # for now we'll label it but it might fire more than intended without hour filtering
                    {"field": "is_after_hours", "operator": "eq", "value": True} 
                ]
            },
            "mitre_technique": ["T1078"]
        },
        {
            "rule_id": "SOC-LOW-008",
            "name": "High DNS Query Volume",
            "description": "Large number of DNS queries from a single source, potential tunneling.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [{"field": "protocol", "operator": "eq", "value": "DNS"}],
                "threshold": 500,
                "timeframe": "5m",
                "group_by": ["source_ip"]
            },
            "mitre_technique": ["T1071.004"]
        },
        {
            "rule_id": "SOC-LOW-009",
            "name": "PING Command on Sensitive Systems",
            "description": "Use of ping for internal reconnaissance from a web server.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "process_name", "operator": "contains", "value": "ping"},
                    {"field": "parent_process", "operator": "regex", "value": "w3wp|apache|nginx"}
                ]
            },
            "mitre_technique": ["T1018"]
        },
        {
            "rule_id": "SOC-LOW-010",
            "name": "Base64 in Command Line",
            "description": "Detection of base64 strings in process command lines, common for obfuscation.",
            "severity": "low",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "command_line", "operator": "regex", "value": "\\s+-e[nc]*\\s+[A-Za-z0-9+/=]{20,}"}
                ]
            },
            "mitre_technique": ["T1027"]
        },
        # --- Network & Bandwidth ---
        {
            "rule_id": "SOC-NET-001",
            "name": "High Bandwidth Anomaly",
            "description": "Detection of significant spikes in network bandwidth, potentially indicating data exfiltration or DDoS.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_type": "traffic_anomaly",
                "filters": [
                    {"field": "log_source", "operator": "eq", "value": "network_bandwidth"}
                ]
            },
            "mitre_technique": ["T1048", "T1498"]
        },
        {
            "rule_id": "SOC-NET-002",
            "name": "Potential Port Scan Detected",
            "description": "Heuristic detection of multiple unique ports blocked from a single source IP.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_type": "port_scan_detected",
                "group_by": ["source_ip"]
            },
            "mitre_technique": ["T1595.001"]
        },
        # --- Endpoint Protection & FIM ---
        {
            "rule_id": "SOC-FIM-001",
            "name": "Ransomware Canary Alert",
            "description": "Modification or deletion of a FIM Canary file, strongly indicating ransomware activity.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "event_type": "canary_file_alert"
            },
            "mitre_technique": ["T1486"]
        },
        {
            "rule_id": "SOC-AV-001",
            "name": "Malware Detection Alert",
            "description": "Threat identified by endpoint antivirus (Windows Defender).",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_type": "malware_detection",
                "log_source": "windows_defender"
            },
            "mitre_technique": ["T1204.002"]
        },
        # --- Application Security ---
        {
            "rule_id": "SOC-APP-001",
            "name": "Database Authentication Brute Force",
            "description": "Multiple failed database login attempts from a single source.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_type": "authentication_failure",
                "log_source": "database",
                "threshold": 5,
                "timeframe": "10m",
                "group_by": ["source_ip"]
            },
            "mitre_technique": ["T1110"]
        },
        {
            "rule_id": "SOC-APP-002",
            "name": "Web Infrastructure DoS Attempt",
            "description": "High frequency of web requests from a single client indicating potential DoS.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_type": "high_request_frequency",
                "threshold": 2, # Already pre-aggregated by agent to some extent
                "timeframe": "5m",
                "group_by": ["client_ip"]
            },
            "mitre_technique": ["T1498"]
        },
        
        # === NEW ENTERPRISE-GRADE DETECTION RULES ===
        
        # --- Network Flow Metrics Rules ---
        {
            "rule_id": "SOC-NET-003",
            "name": "Data Exfiltration - High Bytes Sent",
            "description": "Unusually high bytes_sent from single endpoint indicating potential data exfiltration.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "log_source": "network_bandwidth",
                "filters": [
                    {"field": "direction", "operator": "eq", "value": "outbound"},
                    {"field": "volume_mb", "operator": "gte", "value": 100}
                ],
                "threshold": 3,
                "timeframe": "1h",
                "group_by": ["hostname"]
            },
            "mitre_technique": ["T1048"],
            "false_positive_notes": "Legitimate large file uploads, backups, video conferencing"
        },
        {
            "rule_id": "SOC-NET-004",
            "name": "Beaconing Detection - Periodic Low Volume Traffic",
            "description": "Detection of periodic C2 beaconing patterns with consistent timing intervals.",
            "severity": "medium",
            "enabled": True,
            "conditions": {
                "log_source": "network_snapshot",
                "filters": [
                    {"field": "status", "operator": "eq", "value": "ESTABLISHED"},
                    {"field": "bytes_sent", "operator": "lt", "value": 1000}
                ],
                "threshold": 10,
                "timeframe": "30m",
                "group_by": ["dst_ip", "hostname"]
            },
            "mitre_technique": ["T1071", "T1573"],
            "false_positive_notes": "Heartbeat services, monitoring agents, NTP"
        },
        {
            "rule_id": "SOC-NET-005",
            "name": "Port Scan - High Packet Rate",
            "description": "Rapid connection attempts to multiple ports indicating reconnaissance.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "packets_sent", "operator": "gte", "value": 100}
                ],
                "threshold": 20,
                "timeframe": "5m",
                "group_by": ["src_ip"]
            },
            "mitre_technique": ["T1595.001"],
            "false_positive_notes": "Vulnerability scanners, network monitoring tools"
        },
        
        # --- HTTP/Web Enhanced Rules ---
        {
            "rule_id": "SOC-HTTP-001",
            "name": "Enhanced SQL Injection Detection",
            "description": "Advanced SQLi patterns including UNION-based, boolean-based, and time-based injection.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "log_source": "web_server",
                "filters": [
                    {"field": "query_string", "operator": "regex", "value": "(UNION.*SELECT|OR\\s+1\\s*=\\s*1|AND\\s+1\\s*=\\s*1|SLEEP\\s*\\(|BENCHMARK\\s*\\(|WAITFOR\\s+DELAY)"}
                ]
            },
            "mitre_technique": ["T1190"],
            "false_positive_notes": "Developer testing, security scanners"
        },
        {
            "rule_id": "SOC-HTTP-002",
            "name": "XSS Attack Pattern Detection",
            "description": "Cross-site scripting attempt detection in URI and query parameters.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "log_source": "web_server",
                "filters": [
                    {"field": "query_string", "operator": "regex", "value": "(<script|javascript:|onerror\\s*=|onload\\s*=|<iframe|<svg.*onload)"}
                ]
            },
            "mitre_technique": ["T1189"],
            "false_positive_notes": "Web development, CMS editors with HTML content"
        },
        {
            "rule_id": "SOC-HTTP-003",
            "name": "Command Injection Attempt",
            "description": "Detection of OS command injection patterns in web requests.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "log_source": "web_server",
                "filters": [
                    {"field": "query_string", "operator": "regex", "value": "([;|&]\\s*(cat|ls|id|whoami|wget|curl|nc|netcat|bash|sh|cmd|powershell))"}
                ]
            },
            "mitre_technique": ["T1059"],
            "false_positive_notes": "API testing, legitimate shell command parameters"
        },
        {
            "rule_id": "SOC-HTTP-004",
            "name": "Directory Traversal Attack",
            "description": "Path traversal attempts to access files outside webroot.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "log_source": "web_server",
                "filters": [
                    {"field": "uri", "operator": "regex", "value": "(\\.\\./|\\.\\.\\\\/etc/passwd|c:\\\\windows)"}
                ]
            },
            "mitre_technique": ["T1083"],
            "false_positive_notes": "Rare false positives, typically malicious"
        },
        {
            "rule_id": "SOC-HTTP-005",
            "name": "Abnormal 5xx Error Rate",
            "description": "High rate of server errors indicating potential attack or system instability.",
            "severity": "medium",
            "enabled": True,
            "conditions": {
                "log_source": "web_server",
                "filters": [
                    {"field": "status_code", "operator": "gte", "value": 500}
                ],
                "threshold": 50,
                "timeframe": "10m",
                "group_by": ["hostname"]
            },
            "mitre_technique": ["T1499"],
            "false_positive_notes": "Application bugs, deployment issues"
        },
        
        # --- TLS/SSL Rules ---
        {
            "rule_id": "SOC-TLS-001",
            "name": "Deprecated TLS Version Usage",
            "description": "Detection of insecure TLS versions (TLS 1.0, 1.1, SSLv3).",
            "severity": "medium",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "tls_version", "operator": "regex", "value": "(TLSv1\\.0|TLSv1\\.1|SSLv3|SSLv2)"}
                ]
            },
            "mitre_technique": ["T1573.001"],
            "false_positive_notes": "Legacy systems, IoT devices"
        },
        {
            "rule_id": "SOC-TLS-002",
            "name": "Suspicious Encrypted C2 Pattern",
            "description": "Low-volume encrypted connections to unusual SNI with repeated patterns.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "tls_version", "operator": "exists", "value": True},
                    {"field": "bytes_sent", "operator": "lt", "value": 5000}
                ],
                "threshold": 15,
                "timeframe": "1h",
                "group_by": ["sni", "hostname"]
            },
            "mitre_technique": ["T1071.001", "T1573"],
            "false_positive_notes": "Keep-alive connections, CDN health checks"
        },
        
        # --- Authentication Enhanced Rules ---
        {
            "rule_id": "SOC-AUTH-003",
            "name": "Enhanced Credential Stuffing Detection",
            "description": "Multiple accounts targeted from single IP with alternating success/failure.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "auth_status", "operator": "eq", "value": "failure"}
                ],
                "threshold": 10,
                "timeframe": "10m",
                "group_by": ["source_ip"],
                "group_by_unique": ["username"]
            },
            "mitre_technique": ["T1110.004"],
            "false_positive_notes": "Shared workstations, NAT environments"
        },
        {
            "rule_id": "SOC-AUTH-004",
            "name": "Lateral Movement Detection",
            "description": "Single account authenticating to multiple hosts rapidly.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "auth_status", "operator": "eq", "value": "success"},
                    {"field": "login_type", "operator": "in", "value": ["Network", "RemoteInteractive", "ssh"]}
                ],
                "threshold": 5,
                "timeframe": "15m",
                "group_by": ["username"],
                "group_by_unique": ["hostname"]
            },
            "mitre_technique": ["T1550", "T1021"],
            "false_positive_notes": "IT administrators, deployment scripts"
        },
        {
            "rule_id": "SOC-AUTH-005",
            "name": "Impossible Travel Detection",
            "description": "Same user logging in from geographically distant locations.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "filters": [
                    {"field": "auth_status", "operator": "eq", "value": "success"}
                ],
                "threshold": 2,
                "timeframe": "2h",
                "group_by": ["username"],
                "group_by_unique": ["geoip_country"]
            },
            "mitre_technique": ["T1078"],
            "false_positive_notes": "VPN users, corporate proxies"
        },
        
        # --- Endpoint Enhanced Rules ---
        {
            "rule_id": "SOC-EP-001",
            "name": "Suspicious Parent-Child Process Chain",
            "description": "Detection of unusual process spawning patterns indicative of exploitation.",
            "severity": "high",
            "enabled": True,
            "conditions": {
                "event_type": "process_creation",
                "filters": [
                    {"field": "parent_process", "operator": "regex", "value": "(winword|excel|powerpnt|outlook|iexplore|chrome|firefox)"},
                    {"field": "process_name", "operator": "regex", "value": "(cmd|powershell|wscript|cscript|mshta|regsvr32)"}
                ]
            },
            "mitre_technique": ["T1055", "T1059"],
            "false_positive_notes": "Legitimate macros, browser plugins"
        },
        {
            "rule_id": "SOC-EP-002",
            "name": "Unsigned Binary Execution",
            "description": "Execution of unsigned or invalidly signed binaries.",
            "severity": "medium",
            "enabled": True,
            "conditions": {
                "event_type": "process_creation",
                "filters": [
                    {"field": "signature_status", "operator": "neq", "value": "valid"}
                ]
            },
            "mitre_technique": ["T1553.002"],
            "false_positive_notes": "Development tools, open-source software"
        },
        {
            "rule_id": "SOC-REG-001",
            "name": "Registry Persistence Attempt",
            "description": "Modification of registry Run keys or services for persistence.",
            "severity": "critical",
            "enabled": True,
            "conditions": {
                "event_code": 4657,
                "filters": [
                    {"field": "registry_key", "operator": "regex", "value": "(Run|RunOnce|Services|Winlogon|Shell)"}
                ]
            },
            "mitre_technique": ["T1547.001", "T1543.003"],
            "false_positive_notes": "Software installers, system updates"
        }
    ]
    
    print(f"Seeding {len(rules)} detection rules into {DB_NAME}...")
    
    for rule in rules:
        rule["created_at"] = datetime.utcnow()
        rule["updated_at"] = datetime.utcnow()
        db.rules.update_one({"rule_id": rule["rule_id"]}, {"$set": rule}, upsert=True)
    
    print("✓ Detection rules successfully seeded.")

if __name__ == "__main__":
    seed_rules()
