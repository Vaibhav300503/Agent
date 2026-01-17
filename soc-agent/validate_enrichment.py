#!/usr/bin/env python3
"""
Automated validation script for log enrichment and rule effectiveness

This script validates:
1. All logs have required metadata fields (source, destination, severity_level, log_category)
2. Field values are correctly populated and standardized
3. Enrichment logic works across different log types
4. Dashboard compatibility (field names, formats)

Usage:
    python validate_enrichment.py
"""

import sys
import os
from typing import Dict, Any, List
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sanitizer import enrich_log


class MockConfig:
    """Mock config for testing"""
    def __init__(self):
        self.server_url = "https://soc.company.com/api/v1/logs"


class ValidationSuite:
    """Comprehensive validation test suite"""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.errors = []
        
    def assert_field_exists(self, log: Dict, field: str, test_name: str) -> bool:
        """Assert field exists in log"""
        if field not in log:
            self.errors.append(f"{test_name}: Missing field '{field}'")
            self.tests_failed += 1
            return False
        self.tests_passed += 1
        return True
    
    def assert_field_value(self, log: Dict, field: str, valid_values: List, test_name: str) -> bool:
        """Assert field value is in valid set"""
        value = log.get(field)
        if value not in valid_values:
            self.errors.append(f"{test_name}: Invalid {field}='{value}' (expected one of {valid_values})")
            self.tests_failed += 1
            return False
        self.tests_passed += 1
        return True
    
    def assert_not_empty(self, log: Dict, field: str, test_name: str) -> bool:
        """Assert field is not empty"""
        value = log.get(field)
        if not value or value == "unknown":
            self.errors.append(f"{test_name}: Field '{field}' is empty or default")
            self.tests_failed += 1
            return False
        self.tests_passed += 1
        return True
    
    def test_required_fields_present(self, log: Dict, test_name: str) -> bool:
        """Test 1: All required fields are present"""
        required_fields = ['source', 'destination', 'severity_level', 'log_category', 'log_type']
        all_present = True
        
        for field in required_fields:
            if not self.assert_field_exists(log, field, test_name):
                all_present = False
        
        return all_present
    
    def test_severity_standardized(self, log: Dict, test_name: str) -> bool:
        """Test 2: Severity is standardized"""
        valid_severities = ['Low', 'Medium', 'High', 'Critical']
        return self.assert_field_value(log, 'severity_level', valid_severities, test_name)
    
    def test_category_valid(self, log: Dict, test_name: str) -> bool:
        """Test 3: Category is valid"""
        valid_categories = ['Security', 'Application', 'Network', 'System']
        return self.assert_field_value(log, 'log_category', valid_categories, test_name)
    
    def test_source_format(self, log: Dict, test_name: str) -> bool:
        """Test 4: Source field is properly formatted"""
        if not self.assert_not_empty(log, 'source', test_name):
            return False
        
        source = log.get('source')
        # Should be in format "hostname" or "hostname/Service"
        if '/' in source:
            parts = source.split('/')
            if len(parts) != 2 or not parts[0] or not parts[1]:
                self.errors.append(f"{test_name}: Invalid source format '{source}' (expected 'hostname/Service')")
                self.tests_failed += 1
                return False
        
        self.tests_passed += 1
        return True
    
    def test_backward_compatibility(self, original: Dict, enriched: Dict, test_name: str) -> bool:
        """Test 5: Original fields are preserved"""
        preserved_fields = ['hostname', 'ip_address', 'log_source', 'os_type']
        all_preserved = True
        
        for field in preserved_fields:
            if field in original:
                if field not in enriched or enriched[field] != original[field]:
                    self.errors.append(f"{test_name}: Original field '{field}' not preserved")
                    self.tests_failed += 1
                    all_preserved = False
                else:
                    self.tests_passed += 1
        
        return all_preserved
    
    def test_dashboard_compatibility(self, log: Dict, test_name: str) -> bool:
        """Test 6: Fields are dashboard-compatible"""
        # Check field names match expected dashboard schema
        dashboard_fields = {
            'source': str,
            'destination': str,
            'severity_level': str,
            'log_category': str,
            'log_type': str
        }
        
        compatible = True
        for field, expected_type in dashboard_fields.items():
            if field not in log:
                continue
            
            if not isinstance(log[field], expected_type):
                self.errors.append(f"{test_name}: Field '{field}' wrong type (expected {expected_type.__name__})")
                self.tests_failed += 1
                compatible = False
            else:
                self.tests_passed += 1
        
        return compatible
    
    def run_test_case(self, test_log: Dict, test_name: str) -> bool:
        """Run all tests on a single log entry"""
        print(f"\n🧪 {test_name}")
        print(f"   Input: {test_log.get('log_source', 'unknown')} | {test_log.get('event_type', 'N/A')}")
        
        config = MockConfig()
        enriched_log = enrich_log(test_log.copy(), config)
        
        # Run all validation tests
        results = [
            self.test_required_fields_present(enriched_log, test_name),
            self.test_severity_standardized(enriched_log, test_name),
            self.test_category_valid(enriched_log, test_name),
            self.test_source_format(enriched_log, test_name),
            self.test_backward_compatibility(test_log, enriched_log, test_name),
            self.test_dashboard_compatibility(enriched_log, test_name)
        ]
        
        # Print enriched fields
        print(f"   Output:")
        print(f"     source: {enriched_log.get('source')}")
        print(f"     destination: {enriched_log.get('destination')}")
        print(f"     severity_level: {enriched_log.get('severity_level')}")
        print(f"     log_category: {enriched_log.get('log_category')}")
        
        if all(results):
            print(f"   ✅ PASS")
            return True
        else:
            print(f"   ❌ FAIL ({sum(1 for r in results if not r)} test(s) failed)")
            return False
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*70)
        print("VALIDATION SUMMARY")
        print("="*70)
        print(f"✅ Tests Passed: {self.tests_passed}")
        print(f"❌ Tests Failed: {self.tests_failed}")
        print(f"📊 Success Rate: {(self.tests_passed/(self.tests_passed+self.tests_failed)*100):.1f}%")
        
        if self.errors:
            print(f"\n⚠️  ERRORS ({len(self.errors)}):")
            for error in self.errors[:10]:  # Show first 10
                print(f"   - {error}")
            if len(self.errors) > 10:
                print(f"   ... and {len(self.errors) - 10} more")
        
        print("="*70)


def create_test_logs() -> List[Dict]:
    """Create comprehensive test log set"""
    return [
        # Test 1: Windows Authentication
        {
            "timestamp": "2026-01-17T10:00:00",
            "hostname": "WIN-SERVER-01",
            "ip_address": "10.0.1.100",
            "os_type": "Windows",
            "log_source": "windows_authentication",
            "event_id": 4625,
            "severity": 2,
            "source_ip": "192.168.1.50",
            "account_name": "admin",
            "message": "Failed login"
        },
        
        # Test 2: Linux Web Server
        {
            "timestamp": "2026-01-17T10:05:00",
            "hostname": "web-server-01",
            "ip_address": "10.0.2.50",
            "os_type": "Linux",
            "log_source": "web_server",
            "event_type": "http_request",
            "status_code": 500,
            "client_ip": "203.0.113.45",
            "message": "Internal server error"
        },
        
        # Test 3: Windows Defender
        {
            "timestamp": "2026-01-17T10:10:00",
            "hostname": "WORKSTATION-05",
            "ip_address": "10.0.3.120",
            "os_type": "Windows",
            "log_source": "windows_defender",
            "event_type": "malware_detection",
            "event_id": 1116,
            "severity": 1,
            "threat_name": "Trojan:Win32/Wacatac",
            "message": "Malware detected"
        },
        
        # Test 4: Network Connection
        {
            "timestamp": "2026-01-17T10:15:00",
            "hostname": "router-01",
            "ip_address": "10.0.4.1",
            "os_type": "Linux",
            "log_source": "network_snapshot",
            "src_ip": "10.0.1.50",
            "dst_ip": "203.0.113.89",
            "protocol": "TCP",
            "status": "ESTABLISHED",
            "message": "Active connection"
        },
        
        # Test 5: Windows Firewall
        {
            "timestamp": "2026-01-17T10:20:00",
            "hostname": "FW-SERVER-01",
            "ip_address": "10.0.5.1",
            "os_type": "Windows",
            "log_source": "windows_firewall",
            "event_type": "firewall_block",
            "event_id": 5152,
            "severity": 4,
            "source_ip": "192.168.100.45",
            "destination_port": 3389,
            "message": "Connection blocked"
        },
        
        # Test 6: Linux SSH Authentication
        {
            "timestamp": "2026-01-17T10:25:00",
            "hostname": "ubuntu-web-01",
            "ip_address": "10.0.6.50",
            "os_type": "Linux",
            "log_source": "authentication",
            "event_type": "ssh_login_success",
            "auth_status": "success",
            "username": "devops",
            "source_ip": "192.168.1.100",
            "message": "SSH login successful"
        },
        
        # Test 7: Database Authentication Failure
        {
            "timestamp": "2026-01-17T10:30:00",
            "hostname": "db-server-01",
            "ip_address": "10.0.7.10",
            "os_type": "Linux",
            "log_source": "database",
            "event_type": "authentication_failure",
            "alert_severity": "medium",
            "username": "app_user",
            "message": "Database auth failed"
        },
        
        # Test 8: Log with minimal fields (edge case)
        {
            "timestamp": "2026-01-17T10:35:00",
            "hostname": "minimal-host",
            "ip_address": "10.0.8.1",
            "os_type": "Linux",
            "message": "Minimal log entry"
        },
        
        # Test 9: High severity event (should be Critical)
        {
            "timestamp": "2026-01-17T10:40:00",
            "hostname": "critical-host",
            "ip_address": "10.0.9.1",
            "os_type": "Windows",
            "log_source": "windows_defender",
            "event_type": "ransomware_detected",
            "message": "Ransomware activity"
        },
        
        # Test 10: HTTP high severity
        {
            "timestamp": "2026-01-17T10:45:00",
            "hostname": "web-02",
            "ip_address": "10.0.10.1",
            "os_type": "Linux",
            "log_source": "web_server",
            "event_type": "sql_injection",
            "alert_severity": "high",
            "status_code": 403,
            "message": "SQL injection blocked"
        }
    ]


def main():
    """Main validation function"""
    print("="*70)
    print("LOG ENRICHMENT VALIDATION SUITE")
    print("="*70)
    print(f"Testing enrichment logic with {10} sample logs across different types\n")
    
    suite = ValidationSuite()
    test_logs = create_test_logs()
    
    passed = 0
    failed = 0
    
    for i, test_log in enumerate(test_logs, 1):
        test_name = f"Test {i}/{len(test_logs)}: {test_log.get('log_source', 'unknown')}"
        if suite.run_test_case(test_log, test_name):
            passed += 1
        else:
            failed += 1
    
    # Print detailed summary
    suite.print_summary()
    
    # Final verdict
    print(f"\n{'='*70}")
    if failed == 0:
        print("🎉 ALL TESTS PASSED - Enrichment is working correctly!")
        print("✅ Dashboard-ready metadata is present in all logs")
        print("="*70)
        return 0
    else:
        print(f"⚠️  {failed}/{len(test_logs)} TEST CASES FAILED")
        print("❌ Fix enrichment logic before deploying")
        print("="*70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
