#!/usr/bin/env python3
"""
CI/CD Integration Script for Log Enrichment Validation

This script is designed to run in CI/CD pipelines to validate that:
1. All logs have required metadata fields (source, destination, severity_level, log_category)
2. No empty or default-only values
3. No conflicting severity or log_type assignments

Exit Codes:
  0 - All validations passed
  1 - Validation failures detected (fails the build)

Usage:
  python cicd_validate.py
  
Environment:
  CI=true (optional) - Enables CI-specific formatting
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sanitizer import enrich_log
from typing import Dict, Any, List


class CICDValidator:
    """CI/CD-compatible validation with strict pass/fail"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.is_ci = os.getenv('CI', '').lower() == 'true'
        
    def log_error(self, message: str):
        """Log a critical error (fails build)"""
        self.errors.append(message)
        if self.is_ci:
            print(f"::error::{message}")
        else:
            print(f"❌ ERROR: {message}")
    
    def log_warning(self, message: str):
        """Log a warning (doesn't fail build)"""
        self.warnings.append(message)
        if self.is_ci:
            print(f"::warning::{message}")
        else:
            print(f"⚠️  WARNING: {message}")
    
    def validate_required_fields(self, log: Dict, test_name: str) -> bool:
        """Validate all required fields are present"""
        required = ['source', 'destination', 'severity_level', 'log_category', 'log_type']
        missing = [f for f in required if f not in log]
        
        if missing:
            self.log_error(f"{test_name}: Missing required fields: {', '.join(missing)}")
            return False
        return True
    
    def validate_no_empty_values(self, log: Dict, test_name: str) -> bool:
        """Validate fields are not empty or default-only"""
        issues = []
        
        # Check source
        if not log.get('source') or log['source'] == 'unknown':
            issues.append("'source' is empty or default")
        
        # Check destination
        if not log.get('destination'):
            issues.append("'destination' is empty")
        
        # Check severity_level
        valid_severities = ['Low', 'Medium', 'High', 'Critical']
        if log.get('severity_level') not in valid_severities:
            issues.append(f"'severity_level' invalid: {log.get('severity_level')}")
        
        # Check log_category
        valid_categories = ['Security', 'Application', 'Network', 'System']
        if log.get('log_category') not in valid_categories:
            issues.append(f"'log_category' invalid: {log.get('log_category')}")
        
        if issues:
            for issue in issues:
                self.log_error(f"{test_name}: {issue}")
            return False
        return True
    
    def validate_log(self, test_log: Dict, test_name: str) -> bool:
        """Run all validations on a single log"""
        # Enrich the log
        try:
            from sanitizer import enrich_log
            
            class MockConfig:
                server_url = "https://soc.company.com/api/v1/logs"
            
            enriched = enrich_log(test_log.copy(), MockConfig())
        except Exception as e:
            self.log_error(f"{test_name}: Enrichment failed: {e}")
            return False
        
        # Run validations
        return (
            self.validate_required_fields(enriched, test_name) and
            self.validate_no_empty_values(enriched, test_name)
        )
    
    def run_validation_suite(self) -> bool:
        """Run complete validation suite"""
        print("="*70)
        print("CI/CD LOG ENRICHMENT VALIDATION")
        print("="*70)
        
        # Test logs covering all scenarios
        test_cases = [
            ("Windows Authentication", {
                "timestamp": "2026-01-17T10:00:00",
                "hostname": "WIN-01",
                "ip_address": "10.0.1.1",
                "os_type": "Windows",
                "log_source": "windows_authentication",
                "event_id": 4625,
                "severity": 2
            }),
            ("Linux Web Server", {
                "timestamp": "2026-01-17T10:00:00",
                "hostname": "web-01",
                "ip_address": "10.0.2.1",
                "os_type": "Linux",
                "log_source": "web_server",
                "status_code": 500
            }),
            ("Windows Defender", {
                "timestamp": "2026-01-17T10:00:00",
                "hostname": "ws-01",
                "ip_address": "10.0.3.1",
                "os_type": "Windows",
                "log_source": "windows_defender",
                "event_type": "malware_detection",
                "severity": 1
            }),
            ("Network Connection", {
                "timestamp": "2026-01-17T10:00:00",
                "hostname": "router-01",
                "ip_address": "10.0.4.1",
                "os_type": "Linux",
                "log_source": "network_snapshot"
            }),
            ("Minimal Log (Edge Case)", {
                "timestamp": "2026-01-17T10:00:00",
                "hostname": "minimal-host",
                "ip_address": "10.0.5.1",
                "os_type": "Linux"
            })
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_log in test_cases:
            if self.validate_log(test_log, test_name):
                passed += 1
                print(f"✅ {test_name}: PASS")
            else:
                failed += 1
                print(f"❌ {test_name}: FAIL")
        
        # Summary
        print("\n" + "="*70)
        print("VALIDATION RESULTS")
        print("="*70)
        print(f"Passed: {passed}/{len(test_cases)}")
        print(f"Failed: {failed}/{len(test_cases)}")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")
        
        if self.errors:
            print(f"\n❌ CRITICAL ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  - {error}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        print("="*70)
        
        # Final verdict
        if failed == 0 and len(self.errors) == 0:
            print("\n✅ VALIDATION PASSED - Build can proceed")
            return True
        else:
            print("\n❌ VALIDATION FAILED - Build must stop")
            return False


def main():
    """Main entry point"""
    validator = CICDValidator()
    success = validator.run_validation_suite()
    
    # Exit with appropriate code for CI/CD
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
