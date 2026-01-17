#!/usr/bin/env python3
"""
Test script to demonstrate log enrichment functionality

This script shows before/after examples of log enrichment,
demonstrating how raw logs are transformed with:
- source field (endpoint/service identification)
- destination field (SOC server)
- severity_level (standardized: Low, Medium, High, Critical)
- log_category (Security, Application, Network, System)
"""

import sys
import os
import json
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sanitizer import enrich_log


class MockConfig:
    """Mock config object for testing"""
    def __init__(self):
        self.server_url = "https://soc.company.com/api/v1/logs"


def print_comparison(title: str, before: Dict[str, Any], after: Dict[str, Any]):
    """Print before/after comparison"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")
    
    print("\n📥 BEFORE (Raw Log):")
    print(json.dumps(before, indent=2, default=str))
    
    print("\n✨ AFTER (Enriched):")
    # Highlight new fields
    new_fields = {
        'source': after.get('source'),
        'destination': after.get('destination'),
        'severity_level': after.get('severity_level'),
        'log_category': after.get('log_category'),
        'log_type': after.get('log_type')
    }
    print("\n  🎯 New Metadata Fields:")
    print(json.dumps(new_fields, indent=4))
    
    print("\n  📋 Complete Enriched Log:")
    print(json.dumps(after, indent=2, default=str))


def test_windows_auth_failure():
    """Test Windows authentication failure log"""
    raw_log = {
        "timestamp": "2026-01-17T05:15:32.123456",
        "hostname": "WIN-SERVER-01",
        "ip_address": "10.0.1.100",
        "os_type": "Windows",
        "log_source": "windows_authentication",
        "event_type": "authentication",
        "event_id": 4625,
        "severity": 2,  # Windows EventType: Warning
        "source_ip": "203.0.113.89",
        "account_name": "admin",
        "auth_status": "failure",
        "message": "An account failed to log on"
    }
    
    config = MockConfig()
    enriched_log = enrich_log(raw_log.copy(), config)
    
    print_comparison(
        "Windows Authentication Failure (Event ID 4625)",
        raw_log,
        enriched_log
    )


def test_linux_web_attack():
    """Test Linux web server SQL injection attempt"""
    raw_log = {
        "timestamp": "2026-01-17T10:22:15",
        "hostname": "web-server-01",
        "ip_address": "10.0.1.50",
        "os_type": "Linux",
        "log_source": "web_server",
        "event_type": "http_request",
        "client_ip": "45.33.32.156",
        "http_method": "GET",
        "uri": "/admin.php?id=1' OR '1'='1",
        "status_code": 403,
        "attack_type": "sql_injection",
        "alert_severity": "high",
        "message": "Blocked SQL injection attempt"
    }
    
    config = MockConfig()
    enriched_log = enrich_log(raw_log.copy(), config)
    
    print_comparison(
        "Linux Web Server - SQL Injection Attack",
        raw_log,
        enriched_log
    )


def test_firewall_block():
    """Test Windows firewall blocking event"""
    raw_log = {
        "timestamp": "2026-01-17T08:45:12",
        "hostname": "FW-SERVER-01",
        "ip_address": "10.0.1.1",
        "os_type": "Windows",
        "log_source": "windows_firewall",
        "event_type": "firewall_block",
        "event_id": 5152,
        "severity": 4,  # Information
        "source_ip": "192.168.100.45",
        "destination_ip": "10.0.1.100",
        "destination_port": 3389,
        "protocol": "TCP",
        "message": "The Windows Filtering Platform has blocked a connection"
    }
    
    config = MockConfig()
    enriched_log = enrich_log(raw_log.copy(), config)
    
    print_comparison(
        "Windows Firewall - Connection Blocked",
        raw_log,
        enriched_log
    )


def test_ssh_login_success():
    """Test SSH successful login"""
    raw_log = {
        "timestamp": "2026-01-17T09:30:22",
        "hostname": "ubuntu-web-01",
        "ip_address": "10.0.2.50",
        "os_type": "Linux",
        "log_source": "authentication",
        "event_type": "ssh_login_success",
        "username": "devops",
        "source_ip": "192.168.1.100",
        "auth_method": "publickey",
        "auth_status": "success",
        "message": "Accepted publickey for devops from 192.168.1.100 port 52341 ssh2"
    }
    
    config = MockConfig()
    enriched_log = enrich_log(raw_log.copy(), config)
    
    print_comparison(
        "Linux SSH - Successful Login",
        raw_log,
        enriched_log
    )


def test_malware_detection():
    """Test Windows Defender malware detection"""
    raw_log = {
        "timestamp": "2026-01-17T11:15:45",
        "hostname": "WORKSTATION-05",
        "ip_address": "10.0.3.120",
        "os_type": "Windows",
        "log_source": "windows_defender",
        "event_type": "malware_detection",
        "event_id": 1116,
        "severity": 1,  # Error
        "threat_name": "Trojan:Win32/Wacatac.B!ml",
        "threat_severity": "Severe",
        "detection_path": "C:\\Users\\Public\\malware.exe",
        "message": "Windows Defender detected malware"
    }
    
    config = MockConfig()
    enriched_log = enrich_log(raw_log.copy(), config)
    
    print_comparison(
        "Windows Defender - Malware Detection",
        raw_log,
        enriched_log
    )


def test_database_auth_failure():
    """Test database authentication failure"""
    raw_log = {
        "timestamp": "2026-01-17T07:20:10",
        "hostname": "db-server-01",
        "ip_address": "10.0.4.10",
        "os_type": "Linux",
        "log_source": "database",
        "event_type": "authentication_failure",
        "database_type": "mysql",
        "username": "app_user",
        "alert_severity": "medium",
        "message": "Access denied for user 'app_user'@'10.0.1.50'"
    }
    
    config = MockConfig()
    enriched_log = enrich_log(raw_log.copy(), config)
    
    print_comparison(
        "Database - Authentication Failure",
        raw_log,
        enriched_log
    )


def main():
    """Run all test cases"""
    print("\n" + "="*80)
    print("  LOG ENRICHMENT TEST SUITE")
    print("  Demonstrating Before/After Log Transformation")
    print("="*80)
    
    test_cases = [
        ("Windows Authentication", test_windows_auth_failure),
        ("Web Application Attack", test_linux_web_attack),
        ("Firewall Blocking", test_firewall_block),
        ("SSH Login", test_ssh_login_success),
        ("Malware Detection", test_malware_detection),
        ("Database Authentication", test_database_auth_failure)
    ]
    
    for name, test_func in test_cases:
        try:
            test_func()
        except Exception as e:
            print(f"\n❌ Error testing {name}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*80)
    print("  SUMMARY: Dashboard-Ready Fields")
    print("="*80)
    print("""
All logs now include:
  
  ✅ source           - Identifies originating endpoint/service
  ✅ destination      - Identifies SOC server receiving logs  
  ✅ severity_level   - Standardized: Low, Medium, High, Critical
  ✅ log_category     - High-level: Security, Application, Network, System
  ✅ log_type         - Detailed log source (e.g., "windows_firewall")

Dashboard Compatibility:
  - Severity Distribution Widget → Use 'severity_level' field
  - Log Type Filter → Use 'log_category' for broad, 'log_type' for detailed
  - Source Filter → Use 'source' field  
  - Destination Filter → Use 'destination' field
""")


if __name__ == "__main__":
    main()
