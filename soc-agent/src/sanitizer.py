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
