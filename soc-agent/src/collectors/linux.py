import os
import time
import threading
import logging
import re
from datetime import datetime
from collections import defaultdict
from collectors.base import BaseCollector
from utils import get_hostname, get_ip_address, get_os_type

class LinuxCollector(BaseCollector):
    def __init__(self, config, transport):
        super().__init__(config, transport)
        self.files = config.get_linux_files()
        self.web_logs = config.get_web_server_logs() if config.enable_linux_application_logs else []
        self.db_logs = config.get_database_logs() if config.enable_linux_application_logs else []
        self.dns_logs = config.get_dns_logs() if config.enable_linux_application_logs else []
        
        # Combine all monitored files
        self.all_files = self.files + self.web_logs + self.db_logs + self.dns_logs
        
        self.hostname = get_hostname()
        self.ip_address = get_ip_address()
        self.os_type = get_os_type()
        self.file_pointers = {} # filepath -> offset
        self.file_mtimes = {} # filepath -> last modification time
        
        # Request frequency tracking for DDoS/brute force detection
        self.request_tracker = defaultdict(lambda: {'count': 0, 'first_seen': time.time()})

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)

    def _poll_loop(self):
        # Initial seek to end
        for f in self.all_files:
            if os.path.exists(f):
                try:
                    self.file_pointers[f] = os.path.getsize(f)
                except OSError:
                    self.file_pointers[f] = 0

        while self.running:
            for filepath in self.all_files:
                self._read_file(filepath)
            
            time.sleep(self.config.polling_interval)

    def _read_file(self, filepath):
        if not os.path.exists(filepath):
            return

        # OPTIMIZATION: Check modification time before reading
        try:
            current_mtime = os.path.getmtime(filepath)
            last_mtime = self.file_mtimes.get(filepath, 0)
            
            if current_mtime == last_mtime:
                self.logger.debug(f"No changes in {filepath} (mtime: {current_mtime})")
                return
            
            self.file_mtimes[filepath] = current_mtime
        except OSError as e:
            self.logger.warning(f"Could not stat {filepath}: {e}")

        last_pos = self.file_pointers.get(filepath, 0)
        current_size = os.path.getsize(filepath)

        if current_size < last_pos:
            # File truncated or rotated
            last_pos = 0

        if current_size == last_pos:
            return # No new data

        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(last_pos)
                lines = f.readlines()
                self.file_pointers[filepath] = f.tell()

                for line in lines:
                    if line.strip():
                        self._process_line(filepath, line.strip())
        except Exception as e:
            self.logger.error(f"Error reading {filepath}: {e}")

    def _process_line(self, filepath, line):
        """Route line to appropriate parser based on log source"""
        
        # Determine log type and route to specialized parser
        if filepath in self.web_logs:
            self._parse_web_log(filepath, line)
        elif filepath in self.db_logs:
            self._parse_database_log(filepath, line)
        elif filepath in self.dns_logs:
            self._parse_dns_log(filepath, line)
        elif 'auth' in filepath or 'secure' in filepath:
            self._parse_auth_log(filepath, line)
        else:
            # Generic syslog processing
            self._parse_generic_syslog(filepath, line)
    
    def _parse_web_log(self, filepath, line):
        """Parse nginx/apache access logs with WAF-style attack detection"""
        # Apache Combined Log Format regex
        # IP - - [timestamp] "METHOD URI PROTOCOL" STATUS SIZE "REFERER" "USER-AGENT"
        pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\S+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        
        if not match:
            # Try simpler common log format
            pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\S+)'
            match = re.match(pattern, line)
        
        if match:
            groups = match.groups()
            client_ip = groups[0]
            timestamp_str = groups[1]
            method = groups[2]
            full_uri = groups[3]
            protocol = groups[4]
            status = int(groups[5])
            size = groups[6]
            referer = groups[7] if len(groups) > 7 else "-"
            user_agent = groups[8] if len(groups) > 8 else "-"
            
            # Parse query string from URI (enterprise telemetry)
            if '?' in full_uri:
                uri_path, query_string = full_uri.split('?', 1)
            else:
                uri_path = full_uri
                query_string = None
            
            log_entry = {
                "timestamp": timestamp_str,  # Will be normalized by sanitizer
                "log_timestamp_original": timestamp_str,  # Keep original for debugging
                "hostname": self.hostname,
                "ip_address": self.ip_address,
                "os_type": self.os_type,
                "log_source": "web_server",
                "event_type": "http_request",
                "client_ip": client_ip,
                "http_method": method,
                "uri": uri_path,
                "query_string": query_string,  # Separated from URI
                "http_protocol": protocol,
                "status_code": status,
                "response_size": size,
                "referer": referer,
                "user_agent": user_agent,
                "message": line
            }
            
            # Detect attacks using full_uri for pattern matching
            attack_detected = self._detect_web_attack_patterns(log_entry, method, full_uri, user_agent, status)
            
            # Track request frequency for DDoS detection
            self._track_request_frequency(client_ip, log_entry)
            
            # Only send if attack detected or abnormal status
            if attack_detected or status >= 400:
                self.send_log(line, log_entry)
        else:
            # Could not parse, send as generic
            self._parse_generic_syslog(filepath, line)
    
    def _detect_web_attack_patterns(self, log_entry, method, uri, user_agent, status):
        """Detect common web attacks (SQL injection, XSS, path traversal)"""
        attack_detected = False
        
        # Suspicious HTTP methods
        if method in ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']:
            log_entry["attack_type"] = "suspicious_http_method"
            log_entry["alert_severity"] = "medium"
            attack_detected = True
        
        # SQL Injection patterns
        sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"'\s+or\s+'", 
            r";\s*drop\s+table", r"exec\s*\(", r"xp_cmdshell"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                log_entry["attack_type"] = "sql_injection"
                log_entry["alert_severity"] = "high"
                attack_detected = True
                break
        
        # XSS patterns
        xss_patterns = [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=", r"<iframe"]
        for pattern in xss_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                log_entry["attack_type"] = "xss_attempt"
                log_entry["alert_severity"] = "high"
                attack_detected = True
                break
        
        # Path traversal
        if "../" in uri or "..\\" in uri or "/etc/passwd" in uri or "c:\\" in uri.lower():
            log_entry["attack_type"] = "path_traversal"
            log_entry["alert_severity"] = "high"
            attack_detected = True
        
        # Abnormal status codes
        if status in [400, 401, 403, 500, 502, 503]:
            log_entry["anomaly"] = "abnormal_status_code"
            if status == 500:
                log_entry["alert_severity"] = "medium"
                attack_detected = True
        
        return attack_detected
    
    def _track_request_frequency(self, client_ip, log_entry):
        """Track request frequency to detect high-volume attacks"""
        current_time = time.time()
        tracker = self.request_tracker[client_ip]
        
        # Reset if more than 60 seconds have passed
        if current_time - tracker['first_seen'] > 60:
            tracker['count'] = 0
            tracker['first_seen'] = current_time
        
        tracker['count'] += 1
        
        # Alert if more than 100 requests per minute
        if tracker['count'] > 100:
            alert_entry = log_entry.copy()
            alert_entry["event_type"] = "high_request_frequency"
            alert_entry["attack_type"] = "potential_dos"
            alert_entry["alert_severity"] = "high"
            alert_entry["requests_per_minute"] = tracker['count']
            alert_entry["message"] = f"High request frequency from {client_ip}: {tracker['count']} requests in 60 seconds"
            self.send_log(alert_entry["message"], alert_entry)
            
            # Reset to avoid spam
            tracker['count'] = 0
            tracker['first_seen'] = current_time
    
    def _parse_database_log(self, filepath, line):
        """Parse MySQL/PostgreSQL error logs for security events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": "database",
            "event_type": "database_event",
            "message": line
        }
        
        # MySQL patterns
        if "mysql" in filepath.lower():
            log_entry["database_type"] = "mysql"
            
            if "Access denied for user" in line:
                log_entry["event_type"] = "authentication_failure"
                log_entry["alert_severity"] = "medium"
                # Extract username
                user_match = re.search(r"Access denied for user '(.*?)'", line)
                if user_match:
                    log_entry["username"] = user_match.group(1)
                self.send_log(line, log_entry)
            
            elif "Aborted connection" in line:
                log_entry["event_type"] = "connection_aborted"
                log_entry["alert_severity"] = "low"
                self.send_log(line, log_entry)
        
        # PostgreSQL patterns
        elif "postgresql" in filepath.lower():
            log_entry["database_type"] = "postgresql"
            
            if "FATAL" in line and "password authentication failed" in line:
                log_entry["event_type"] = "authentication_failure"
                log_entry["alert_severity"] = "medium"
                # Extract username
                user_match = re.search(r'for user "(.*?)"', line)
                if user_match:
                    log_entry["username"] = user_match.group(1)
                self.send_log(line, log_entry)
            
            elif "too many connections" in line:
                log_entry["event_type"] = "connection_exhaustion"
                log_entry["alert_severity"] = "high"
                self.send_log(line, log_entry)
    
    def _parse_dns_log(self, filepath, line):
        """Parse BIND DNS logs for security events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": "dns_server",
            "event_type": "dns_event",
            "message": line
        }
        
        # Zone transfer attempts
        if "transfer of" in line.lower() or "notify from" in line.lower():
            log_entry["event_type"] = "zone_transfer_attempt"
            log_entry["alert_severity"] = "high"
            self.send_log(line, log_entry)
        
        # Query floods (NXDOMAIN responses can indicate DNS amplification)
        elif "NXDOMAIN" in line:
            log_entry["event_type"] = "nxdomain_response"
            # Could add frequency tracking here similar to web requests
            self.send_log(line, log_entry)
    
    def _parse_auth_log(self, filepath, line):
        """Parse auth.log or secure for SSH and authentication events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": "authentication",
            "message": line
        }
        
        # SSH successful login
        if "Accepted" in line and ("publickey" in line or "password" in line):
            log_entry["event_type"] = "ssh_login_success"
            log_entry["alert_severity"] = "info"
            log_entry["auth_status"] = "success"  # Normalized field
            log_entry["login_type"] = "ssh"  # Normalized field
            
            # Extract username and IP
            user_match = re.search(r"Accepted \w+ for (\S+) from (\S+)", line)
            if user_match:
                log_entry["username"] = user_match.group(1)
                log_entry["source_ip"] = user_match.group(2)
            
            # Extract auth method
            if "publickey" in line:
                log_entry["auth_method"] = "publickey"
            elif "password" in line:
                log_entry["auth_method"] = "password"
            
            self.send_log(line, log_entry)
        
        # SSH failed login
        elif "Failed password" in line:
            log_entry["event_type"] = "ssh_login_failure"
            log_entry["alert_severity"] = "medium"
            log_entry["auth_status"] = "failure"  # Normalized field
            log_entry["login_type"] = "ssh"  # Normalized field
            log_entry["auth_method"] = "password"
            log_entry["failure_reason"] = "invalid_password"
            
            # Extract username and IP
            user_match = re.search(r"Failed password for (\S+) from (\S+)", line)
            if user_match:
                log_entry["username"] = user_match.group(1)
                log_entry["source_ip"] = user_match.group(2)
            
            self.send_log(line, log_entry)
        
        # Invalid user (brute force indicator)
        elif "Invalid user" in line:
            log_entry["event_type"] = "ssh_invalid_user"
            log_entry["alert_severity"] = "medium"
            
            # Extract username and IP
            user_match = re.search(r"Invalid user (\S+) from (\S+)", line)
            if user_match:
                log_entry["username"] = user_match.group(1)
                log_entry["source_ip"] = user_match.group(2)
            
            self.send_log(line, log_entry)
        
        # Sudo usage
        elif "sudo:" in line:
            log_entry["event_type"] = "sudo_usage"
            log_entry["alert_severity"] = "info"
            
            # Extract user and command
            sudo_match = re.search(r"(\S+) :.*COMMAND=(.*)", line)
            if sudo_match:
                log_entry["username"] = sudo_match.group(1)
                log_entry["command"] = sudo_match.group(2)
            
            self.send_log(line, log_entry)
    
    def _parse_generic_syslog(self, filepath, line):
        """Generic syslog parsing for unrecognized formats"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": filepath,
            "message": line,
            "raw_log": line
        }
        
        if "tailscaled" in filepath or "tailscaled" in line:
            data["log_source"] = "tailscale"
        elif "kern" in filepath:
            data["log_source"] = "kernel"
        elif "auth" in filepath:
            data["log_source"] = "auth"
        
        self.send_log(line, data)


