#!/usr/bin/env python3
"""
Script to add priority fields to existing detection rules

This script:
1. Connects to MongoDB
2. Loads all existing rules
3. Assigns priority based on severity and rule type
4. Updates rules with priority field

Priority Levels:
  1-10:   Critical severity - Immediate threats (ransomware, privilege escalation)
  11-30:  High severity - Active attacks (SQLi, brute force, port scans)
  31-60:  Medium severity - Suspicious behavior (failed auth, anomalies)
  61-100: Low severity - Baseline monitoring (scripting tools, 404s)

Usage:
    python add_rule_priorities.py [--dry-run]
"""

import os
import sys
from pymongo import MongoClient
from datetime import datetime
import argparse

# Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
DB_NAME = MONGO_URI.split("/")[-1] if "/" in MONGO_URI else "soc_platform"


# Priority mapping based on severity and rule characteristics
PRIORITY_MAP = {
    # Critical (1-10)
    "SOC-FIM-001": 1,  # Ransomware canary
    "OWASP-A01-003": 2,  # Unauthorized privilege grant
    "SOC-WIN-002": 3,  # Service binary path modification
    "SOC-LX-001": 4,  # Unauthorized sudoers modification
    "OWASP-A08-001": 5,  # Insecure deserialization
    "SOC-REG-001": 6,  # Registry persistence
    "SOC-HTTP-003": 7,  # Command injection
    "SOC-HTTP-001": 8,  # Enhanced SQL injection
    "OWASP-A03-001": 9,  # SQL injection (redundant, lower priority)
    "OWASP-A03-002": 10,  # OS command injection
    
    # High (11-30)
    "SOC-AV-001": 11,  # Malware detection
    "OWASP-A07-001": 12,  # Brute-force login
    "SOC-AUTH-003": 13,  # Enhanced credential stuffing
    "SOC-AUTH-004": 14,  # Lateral movement
    "SOC-AUTH-005": 15,  # Impossible travel
    "SOC-NET-002": 16,  # Port scan detected
    "SOC-NET-003": 17,  # Data exfiltration
    "SOC-NET-005": 18,  # Port scan - high packet rate
    "SOC-HTTP-002": 19,  # XSS attack
    "SOC-HTTP-004": 20,  # Directory traversal
    "SOC-WIN-001": 21,  # Scheduled task creation
    "SOC-APP-001": 22,  # Database auth brute force
    "SOC-APP-002": 23,  # Web DoS attempt
    "SOC-EP-001": 24,  # Suspicious process chain
    "SOC-TLS-002": 25,  # Suspicious encrypted C2
    "SOC-NET-001": 26,  # High bandwidth anomaly
    "OWASP-A01-001": 27,  # Lateral movement
    
    # Medium (31-60)
    "OWASP-A01-002": 31,  # Unauthorized object access
    "OWASP-A07-002": 32,  # Credential stuffing signature
    "SOC-HTTP-005": 33,  # Abnormal 5xx error rate
    "SOC-TLS-001": 34,  # Deprecated TLS version
    "SOC-NET-004": 35,  # Beaconing detection
    "SOC-EP-002": 36,  # Unsigned binary execution
    
    # Low (61-100)
    "SOC-LOW-001": 61,  # Unusual 404 count
    "SOC-LOW-002": 62,  # Scripting user-agent
    "SOC-LOW-003": 63,  # Access to sensitive web patterns
    "SOC-LOW-004": 64,  # Clearing bash history
    "SOC-LOW-005": 65,  # Account created and group added
    "SOC-LOW-006": 66,  # Password policy change
    "SOC-LOW-007": 67,  # Unusual remote login time
    "SOC-LOW-008": 68,  # High DNS query volume
    "SOC-LOW-009": 69,  # PING command on sensitive systems
    "SOC-LOW-010": 70,  # Base64 in command line
}


def calculate_priority(rule):
    """
    Calculate priority for a rule based on severity and type
    
    Returns: Priority number (1-100)
    """
    rule_id = rule.get("rule_id")
    
    # Use explicit mapping if available
    if rule_id in PRIORITY_MAP:
        return PRIORITY_MAP[rule_id]
    
    # Fallback: Calculate based on severity
    severity = rule.get("severity", "low").lower()
    
    if "critical" in severity:
        return 10  # End of critical range
    elif "high" in severity:
        return 30  # End of high range
    elif "medium" in severity:
        return 60  # End of medium range
    else:
        return 100  # End of low range


def add_priorities(dry_run=False):
    """
    Add priority fields to all rules in MongoDB
    """
    print(f"Connecting to MongoDB: {DB_NAME}")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    
    # Get all rules
    rules = list(db.rules.find({}))
    print(f"Found {len(rules)} rules in database\n")
    
    # Statistics
    updated = 0
    skipped = 0
    errors = []
    
    # Process each rule
    for rule in rules:
        rule_id = rule.get("rule_id", "unknown")
        current_priority = rule.get("priority")
        
        # Calculate priority
        new_priority = calculate_priority(rule)
        
        # Prepare update data
        update_data = {
            "priority": new_priority,
            "category": "detection",  # Add category field as well
            "updated_at": datetime.utcnow()
        }
        
        if current_priority == new_priority:
            print(f"✓ {rule_id}: Priority already set to {new_priority} (skipped)")
            skipped += 1
            continue
        
        if dry_run:
            print(f"[DRY-RUN] Would update {rule_id}: priority {current_priority} → {new_priority}")
            updated += 1
        else:
            try:
                result = db.rules.update_one(
                    {"rule_id": rule_id},
                    {"$set": update_data}
                )
                
                if result.modified_count > 0:
                    print(f"✓ Updated {rule_id}: priority {current_priority} → {new_priority} | severity: {rule.get('severity')}")
                    updated += 1
                else:
                    print(f"  {rule_id}: No changes made")
                    skipped += 1
            except Exception as e:
                error_msg = f"Failed to update {rule_id}: {e}"
                print(f"✗ {error_msg}")
                errors.append(error_msg)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total rules:     {len(rules)}")
    print(f"Updated:         {updated}")
    print(f"Skipped:         {skipped}")
    print(f"Errors:          {len(errors)}")
    
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  - {error}")
    
    if dry_run:
        print("\n⚠️  DRY-RUN MODE - No changes were made to the database")
    else:
        print("\n✓ Successfully updated rule priorities")
    
    print("="*70)
    
    client.close()
    return len(errors) == 0


def verify_priorities():
    """
    Verify priority assignments by showing distribution
    """
    print(f"Connecting to MongoDB: {DB_NAME}")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    
    # Get rules with priorities
    rules = list(db.rules.find({}, {"rule_id": 1, "name": 1, "severity": 1, "priority": 1}).sort("priority", 1))
    
    print(f"\n{'='*70}")
    print("PRIORITY DISTRIBUTION")
    print(f"{'='*70}\n")
    
    print(f"{'Priority':<12} {'Severity':<12} {'Rule ID':<20} {'Name':<30}")
    print("-"*70)
    
    for rule in rules:
        priority = rule.get("priority", "N/A")
        severity = rule.get("severity", "unknown")
        rule_id = rule.get("rule_id", "unknown")
        name = rule.get("name", "")[:30]
        
        print(f"{priority:<12} {severity:<12} {rule_id:<20} {name}")
    
    # Show counts by severity
    print(f"\n{'='*70}")
    print("RULES BY SEVERITY")
    print(f"{'='*70}\n")
    
    severity_counts = {}
    for rule in rules:
        sev = rule.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    for sev, count in sorted(severity_counts.items()):
        print(f"{sev.capitalize():<15} {count} rules")
    
    client.close()


def main():
    parser = argparse.ArgumentParser(description="Add priority fields to detection rules")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying them")
    parser.add_argument("--verify", action="store_true", help="Show current priority distribution")
    
    args = parser.parse_args()
    
    if args.verify:
        verify_priorities()
    else:
        success = add_priorities(dry_run=args.dry_run)
        
        if success and not args.dry_run:
            print("\n✅ You can now verify priorities with: python add_rule_priorities.py --verify")
        
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
