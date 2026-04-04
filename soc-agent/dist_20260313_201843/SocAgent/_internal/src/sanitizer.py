"""
Data Sanitization and Validation Utilities for SOC Agent

Provides SQL injection prevention and data sanitization for logs
before sending to backend server.
"""

import re
import html
from datetime import datetime
from typing import Any, Dict

class DataSanitizer:
    """
    Sanitizes log data before sending to server to prevent SQL injection
    and other injection attacks in the backend.
    """
    
    # SQL injection patterns to detect/sanitize
    SQL_INJECTION_PATTERNS = [
        r'(\bUNION\b.*\bSELECT\b)',
        r'(\bOR\b\s+\d+\s*=\s*\d+)',
        r'(\bAND\b\s+\d+\s*=\s*\d+)',
        r'(;\s*DROP\s+TABLE)',
        r'(;\s*DELETE\s+FROM)',
        r'(;\s*UPDATE\s+)',
        r'(;\s*INSERT\s+INTO)',
        r"('\s+OR\s+'[^']*'\s*=\s*')",
        r'(--\s*$)',
        r'(/\*.*\*/)',
        r'(\bEXEC\b\s*\()',
        r'(\bEXECUTE\b\s*\()',
        r'(xp_cmdshell)',
    ]
    
    # Compile patterns for performance
    SQL_PATTERNS_COMPILED = [re.compile(pattern, re.IGNORECASE) for pattern in SQL_INJECTION_PATTERNS]
    
    # Maximum field lengths to prevent DoS
    MAX_FIELD_LENGTHS = {
        'message': 10000,
        'raw_log': 10000,
        'uri': 2000,
        'user_agent': 500,
        'username': 100,
        'hostname': 255,
        'ip_address': 45,  # IPv6 max length
        'process_path': 500,
        'file_path': 500,
    }
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = None) -> str:
        """
        Sanitize a string value to prevent injection attacks
        
        Args:
            value: The string to sanitize
            max_length: Maximum allowed length (truncates if exceeded)
        
        Returns:
            Sanitized string safe for backend storage
        """
        if not isinstance(value, str):
            value = str(value)
        
        # Remove null bytes (can cause issues in some databases)
        value = value.replace('\x00', '')
        
        # HTML escape to prevent XSS in web interfaces
        value = html.escape(value)
        
        # Truncate if needed
        if max_length and len(value) > max_length:
            value = value[:max_length] + '...[truncated]'
        
        return value
    
    @staticmethod
    def detect_sql_injection(value: str) -> bool:
        """
        Detect if a string contains SQL injection patterns
        
        Args:
            value: String to check
        
        Returns:
            True if SQL injection detected, False otherwise
        """
        if not isinstance(value, str):
            return False
        
        for pattern in DataSanitizer.SQL_PATTERNS_COMPILED:
            if pattern.search(value):
                return True
        
        return False
    
    @staticmethod
    def sanitize_log_entry(log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize an entire log entry before sending to backend
        
        Args:
            log_entry: Dictionary containing log data
        
        Returns:
            Sanitized log entry safe for backend storage
        """
        sanitized = {}
        
        for key, value in log_entry.items():
            if value is None:
                sanitized[key] = None
                continue
            
            # Handle strings
            if isinstance(value, str):
                # Get max length for this field if defined
                max_length = DataSanitizer.MAX_FIELD_LENGTHS.get(key)
                
                # Sanitize the value
                sanitized_value = DataSanitizer.sanitize_string(value, max_length)
                
                # Flag if SQL injection detected (don't block, but tag it)
                if DataSanitizer.detect_sql_injection(value):
                    sanitized['_sql_injection_detected'] = True
                    sanitized['_original_field'] = key
                
                sanitized[key] = sanitized_value
            
            # Handle nested dictionaries (rare, but possible)
            elif isinstance(value, dict):
                sanitized[key] = DataSanitizer.sanitize_log_entry(value)
            
            # Handle lists
            elif isinstance(value, list):
                sanitized[key] = [
                    DataSanitizer.sanitize_string(item) if isinstance(item, str) else item
                    for item in value
                ]
            
            # Pass through other types (int, float, bool)
            else:
                sanitized[key] = value
        
        return sanitized


class TimestampParser:
    """
    Parses and normalizes timestamps from various log formats
    to ISO 8601 format for consistent backend storage.
    """
    
    # Common timestamp formats in logs
    TIMESTAMP_FORMATS = [
        # ISO 8601
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        
        # Apache/Nginx logs
        '%d/%b/%Y:%H:%M:%S %z',
        
        # Syslog
        '%b %d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        
        # Windows Event Log
        '%m/%d/%Y %I:%M:%S %p',
        '%Y-%m-%d %H:%M:%S.%f',
        
        # Common formats
        '%Y-%m-%d %H:%M:%S,%f',
        '%d-%b-%Y %H:%M:%S',
    ]
    
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> str:
        """
        Parse a timestamp string and convert to ISO 8601 format
        
        Args:
            timestamp_str: Timestamp string in various formats
        
        Returns:
            ISO 8601 formatted timestamp string
        """
        if not timestamp_str:
            return datetime.now().isoformat()
        
        # If already ISO format, return as-is
        if 'T' in timestamp_str and ('+' in timestamp_str or 'Z' in timestamp_str or timestamp_str.count(':') >= 2):
            try:
                # Validate it's actually parseable
                datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return timestamp_str
            except:
                pass
        
        # Try each format
        for fmt in TimestampParser.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                
                # If no timezone and it's syslog format (no year), add current year
                if '%Y' not in fmt:
                    current_year = datetime.now().year
                    dt = dt.replace(year=current_year)
                
                return dt.isoformat()
            except ValueError:
                continue
        
        # If all parsing fails, use current time and log warning
        import logging
        logging.warning(f"Could not parse timestamp: {timestamp_str}, using current time")
        return datetime.now().isoformat()
    
    @staticmethod
    def normalize_log_timestamps(log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize all timestamp fields in a log entry to ISO 8601
        
        Args:
            log_entry: Dictionary containing log data
        
        Returns:
            Log entry with normalized timestamps
        """
        # Common timestamp field names
        timestamp_fields = ['timestamp', 'event_time', 'time', 'datetime', 'created_at']
        
        for field in timestamp_fields:
            if field in log_entry and isinstance(log_entry[field], str):
                log_entry[field] = TimestampParser.parse_timestamp(log_entry[field])
        
        # Ensure there's always a timestamp field
        if 'timestamp' not in log_entry:
            log_entry['timestamp'] = datetime.now().isoformat()
        
        return log_entry


def sanitize_and_normalize(log_entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to both sanitize and normalize a log entry
    
    Args:
        log_entry: Raw log entry dictionary
    
    Returns:
        Sanitized and normalized log entry ready for backend
    """
    # First normalize timestamps
    log_entry = TimestampParser.normalize_log_timestamps(log_entry)
    
    # Then sanitize all fields
    log_entry = DataSanitizer.sanitize_log_entry(log_entry)
    
    return log_entry


class LogEnricher:
    """
    Enriches log entries with standardized metadata fields for dashboard compatibility
    """
    
    @staticmethod
    def normalize_severity(log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize severity to standard levels: Low, Medium, High, Critical
        
        Handles:
        - Windows Event Log severity (integer EventType codes)
        - Linux alert_severity (string values)
        - HTTP status codes
        - Event type inference
        
        Args:
            log_entry: Log entry dictionary
        
        Returns:
            Log entry with added 'severity_level' field
        """
        # Windows Event Log severity (EventType)
        if 'severity' in log_entry and isinstance(log_entry['severity'], int):
            win_severity_map = {
                1: "Medium",    # Error
                2: "Low",       # Warning
                3: "Low",       # Information
                4: "Low",       # Information Success
                5: "Low"        # Information Failure
            }
            log_entry['severity_level'] = win_severity_map.get(log_entry['severity'], "Low")
            log_entry['severity_original'] = log_entry['severity']  # Keep original
        
        # Linux alert_severity (string)
        elif 'alert_severity' in log_entry:
            alert_map = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "info": "Low"
            }
            severity_str = str(log_entry['alert_severity']).lower()
            log_entry['severity_level'] = alert_map.get(severity_str, "Low")
        
        # HTTP status codes
        elif 'status_code' in log_entry:
            status = log_entry['status_code']
            if status >= 500:
                log_entry['severity_level'] = "High"
            elif status in [401, 403, 404]:
                log_entry['severity_level'] = "Medium"
            elif status >= 400:
                log_entry['severity_level'] = "Medium"
            else:
                log_entry['severity_level'] = "Low"
        
        # Infer from event_type
        elif 'event_type' in log_entry:
            event_type = str(log_entry['event_type']).lower()
            
            # Critical events
            if any(keyword in event_type for keyword in ['malware', 'ransomware', 'breach', 'exploit']):
                log_entry['severity_level'] = "Critical"
            
            # High severity events
            elif any(keyword in event_type for keyword in ['port_scan', 'sql_injection', 'xss', 
                                                           'path_traversal', 'zone_transfer', 
                                                           'bruteforce', 'dos', 'unauthorized_access']):
                log_entry['severity_level'] = "High"
            
            # Medium severity events
            elif any(keyword in event_type for keyword in ['failure', 'invalid', 'denied', 'blocked', 
                                                           'error', 'abnormal', 'suspicious']):
                log_entry['severity_level'] = "Medium"
            
            # Low severity (informational)
            else:
                log_entry['severity_level'] = "Low"
        
        # Default
        else:
            log_entry['severity_level'] = "Low"
        
        return log_entry
    
    @staticmethod
    def categorize_log(log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add high-level log_category field based on log_source
        
        Categories: Security, Application, Network, System
        
        Args:
            log_entry: Log entry dictionary
        
        Returns:
            Log entry with added 'log_category' and 'log_type' fields
        """
        log_source = str(log_entry.get('log_source', '')).lower()
        event_type = str(log_entry.get('event_type', '')).lower()
        
        # Security category
        if any(keyword in log_source for keyword in ['auth', 'firewall', 'defender', 'malware', 
                                                      'security', 'fim', 'antivirus', 'intrusion',
                                                      'access_control', 'encryption']):
            log_entry['log_category'] = "Security"
        
        # Application category
        elif any(keyword in log_source for keyword in ['web', 'database', 'dns', 'application', 
                                                        'http', 'api', 'service']):
            log_entry['log_category'] = "Application"
        
        # Network category
        elif any(keyword in log_source for keyword in ['network', 'tailscale', 'connection', 
                                                        'vpn', 'router', 'switch', 'firewall']):
            log_entry['log_category'] = "Network"
        
        # System category
        elif any(keyword in log_source for keyword in ['kernel', 'syslog', 'system', 'boot', 
                                                        'hardware', 'driver', 'os']):
            log_entry['log_category'] = "System"
        
        # Fallback: Categorize based on event_type
        elif event_type:
            if any(keyword in event_type for keyword in ['login', 'auth', 'sudo', 'firewall', 
                                                          'malware', 'attack', 'intrusion', 'breach']):
                log_entry['log_category'] = "Security"
            elif any(keyword in event_type for keyword in ['http', 'request', 'query', 'response']):
                log_entry['log_category'] = "Application"
            elif any(keyword in event_type for keyword in ['connection', 'network', 'packet']):
                log_entry['log_category'] = "Network"
            else:
                log_entry['log_category'] = "System"
        
        # Default
        else:
            log_entry['log_category'] = "System"
        
        # Add detailed log_type (alias for log_source for backward compatibility)
        log_entry['log_type'] = log_entry.get('log_source', 'unknown')
        
        return log_entry
    
    @staticmethod
    def enrich_metadata(log_entry: Dict[str, Any], config=None) -> Dict[str, Any]:
        """
        Enrich log entry with source and destination metadata
        
        Args:
            log_entry: Log entry dictionary
            config: Optional config object with server_url
        
        Returns:
            Log entry with added 'source' and 'destination' fields
        """
        # Add source field (endpoint/service that generated the log)
        if 'source' not in log_entry:
            hostname = log_entry.get('hostname', 'unknown')
            log_source = log_entry.get('log_source', '')
            
            # Create hierarchical source identifier
            if log_source:
                # Capitalize log_source for readability
                source_name = log_source.replace('_', ' ').title().replace(' ', '')
                log_entry['source'] = f"{hostname}/{source_name}"
            else:
                log_entry['source'] = hostname
        
        # Add destination field (SOC server receiving the logs)
        if 'destination' not in log_entry and config:
            from urllib.parse import urlparse
            try:
                server_url = getattr(config, 'server_url', None)
                if server_url:
                    parsed_url = urlparse(server_url)
                    log_entry['destination'] = parsed_url.hostname or "soc-server"
                    log_entry['destination_endpoint'] = server_url
                else:
                    log_entry['destination'] = "soc-server"
            except Exception:
                log_entry['destination'] = "soc-server"
        elif 'destination' not in log_entry:
            log_entry['destination'] = "soc-server"
        
        return log_entry


def enrich_log(log_entry: Dict[str, Any], config=None) -> Dict[str, Any]:
    """
    Complete log enrichment pipeline: sanitize, normalize, and enrich
    
    This function applies all transformations needed to make logs dashboard-ready:
    1. Timestamp normalization
    2. Data sanitization
    3. Severity standardization
    4. Log categorization
    5. Metadata enrichment (source/destination)
    6. IP resolution and GeoIP enrichment
    7. Risk scoring (SOAR eligibility)
    
    Args:
        log_entry: Raw log entry dictionary
        config: Optional config object with server_url
    
    Returns:
        Fully enriched log entry ready for ingestion
    """
    # Sanitize and normalize (existing function)
    log_entry = sanitize_and_normalize(log_entry)
    
    # Enrich with standardized fields
    log_entry = LogEnricher.normalize_severity(log_entry)
    log_entry = LogEnricher.categorize_log(log_entry)
    log_entry = LogEnricher.enrich_metadata(log_entry, config)
    
    # IP Resolution and GeoIP Enrichment (Step 6)
    try:
        from geo_enricher import enrich_log_ips, GeoEnricher
        from utils import get_ip_address

        # Reuse a module-level enricher singleton for cache efficiency
        if not hasattr(enrich_log, '_geo_enricher'):
            enrich_log._geo_enricher = GeoEnricher(config) if config else GeoEnricher()

        agent_ip = get_ip_address()
        log_entry = enrich_log_ips(
            log_entry,
            agent_ip=agent_ip,
            config=config,
            enricher=enrich_log._geo_enricher
        )
    except ImportError:
        # geo_enricher or geoip2 not available — skip silently
        pass
    except Exception as e:
        import logging as _logging
        _logging.getLogger(__name__).debug(f"IP/Geo enrichment skipped: {e}")
    
    # Risk Scoring (Step 7 — SOAR eligibility)
    try:
        from soar_engine import enrich_log_risk
        log_entry = enrich_log_risk(log_entry)
    except ImportError:
        pass
    except Exception as e:
        import logging as _logging
        _logging.getLogger(__name__).debug(f"Risk scoring skipped: {e}")
    
    return log_entry

