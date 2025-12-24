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
