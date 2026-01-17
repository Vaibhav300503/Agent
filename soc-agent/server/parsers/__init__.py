"""
Windows Event Log Parser
Parses Windows Event Logs into structured format
"""
import re
import logging
from datetime import datetime

class WindowsEventParser:
    """Parse Windows Event Logs to structured format"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, raw_data):
        """Main parsing method"""
        try:
            event_id = raw_data.get("event_id")
            
            # Route to specific parser based on event_id
            if event_id == 4624:
                return self._parse_logon_success(raw_data)
            elif event_id == 4625:
                return self._parse_logon_failure(raw_data)
            elif event_id == 4688:
                return self._parse_process_creation(raw_data)
            elif event_id == 4672:
                return self._parse_special_privileges(raw_data)
            else:
                return self._parse_generic(raw_data)
        
        except Exception as e:
            self.logger.error(f"Parse error for event {raw_data.get('event_id')}: {e}")
            return self._parse_generic(raw_data)
    
    def _parse_logon_success(self, raw_data):
        """Parse Event ID 4624: Successful Logon"""
        message = raw_data.get("message", "")
        
        try:
            # Extract fields using regex
            user_match = re.search(r"Account Name:\s+(\S+)", message)
            domain_match = re.search(r"Account Domain:\s+(\S+)", message)
            source_ip_match = re.search(r"Source Network Address:\s+(\S+)", message)
            logon_type_match = re.search(r"Logon Type:\s+(\d+)", message)
            
            return {
                "event_code": 4624,
                "event_action": "logon",
                "event_outcome": "success",
                "user_name": user_match.group(1) if user_match else None,
                "user_domain": domain_match.group(1) if domain_match else None,
                "source_ip": source_ip_match.group(1) if source_ip_match else None,
                "logon_type": int(logon_type_match.group(1)) if logon_type_match else None,
                "message": message,
                "parsed_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            self.logger.warning(f"Failed to parse 4624 event: {e}")
            return self._parse_generic(raw_data)
    
    def _parse_logon_failure(self, raw_data):
        """Parse Event ID 4625: Failed Logon"""
        message = raw_data.get("message", "")
        
        user_match = re.search(r"Account Name:\s+(\S+)", message)
        domain_match = re.search(r"Account Domain:\s+(\S+)", message)
        source_ip_match = re.search(r"Source Network Address:\s+(\S+)", message)
        failure_reason_match = re.search(r"Failure Reason:\s+(.+)", message)
        status_match = re.search(r"Status:\s+(0x[0-9A-F]+)", message)
        
        return {
            "event_code": 4625,
            "event_action": "logon",
            "event_outcome": "failure",
            "user_name": user_match.group(1) if user_match else None,
            "user_domain": domain_match.group(1) if domain_match else None,
            "source_ip": source_ip_match.group(1) if source_ip_match else None,
            "failure_reason": failure_reason_match.group(1).strip() if failure_reason_match else None,
            "failure_status": status_match.group(1) if status_match else None,
            "message": message,
            "parsed_at": datetime.utcnow().isoformat()
        }
    
    def _parse_process_creation(self, raw_data):
        """Parse Event ID 4688: Process Creation"""
        message = raw_data.get("message", "")
        
        proc_match = re.search(r"New Process Name:\s+(.+)", message)
        parent_match = re.search(r"Creator Process Name:\s+(.+)", message)
        cmdline_match = re.search(r"Process Command Line:\s+(.+)", message)
        
        return {
            "event_code": 4688,
            "event_action": "process_creation",
            "event_outcome": "success",
            "process_name": proc_match.group(1).strip() if proc_match else None,
            "parent_process": parent_match.group(1).strip() if parent_match else None,
            "command_line": cmdline_match.group(1).strip() if cmdline_match else None,
            "message": message,
            "parsed_at": datetime.utcnow().isoformat()
        }
    
    def _parse_special_privileges(self, raw_data):
        """Parse Event ID 4672: Special Privileges Assigned"""
        message = raw_data.get("message", "")
        
        user_match = re.search(r"Account Name:\s+(\S+)", message)
        
        return {
            "event_code": 4672,
            "event_action": "privilege_assignment",
            "event_outcome": "success",
            "user_name": user_match.group(1) if user_match else None,
            "message": message,
            "parsed_at": datetime.utcnow().isoformat()
        }
    
    def _parse_generic(self, raw_data):
        """Generic parser for unknown event IDs"""
        return {
            "event_code": raw_data.get("event_id"),
            "event_action": "unknown",
            "message": raw_data.get("message", ""),
            "raw_data": raw_data,
            "parsed_at": datetime.utcnow().isoformat()
        }


class LinuxSyslogParser:
    """Parse Linux syslog messages"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, raw_data):
        """Parse syslog message"""
        message = raw_data.get("message", "")
        
        # Try to extract timestamp, hostname, process from syslog format
        # Example: Dec 18 10:00:00 hostname sshd[1234]: Failed password for user from 192.168.1.1
        
        syslog_pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)"
        match = re.search(syslog_pattern, message)
        
        if match:
            timestamp_str, hostname, process, pid, log_message = match.groups()
            
            # Check for SSH failed login
            if "Failed password" in log_message:
                ip_match = re.search(r"from (\S+)", log_message)
                user_match = re.search(r"for (\S+)", log_message)
                
                return {
                    "event_action": "ssh_failed_login",
                    "event_outcome": "failure",
                    "source_ip": ip_match.group(1) if ip_match else None,
                    "user_name": user_match.group(1) if user_match else None,
                    "process": process,
                    "pid": int(pid) if pid else None,
                    "message": log_message,
                    "parsed_at": datetime.utcnow().isoformat()
                }
            
            # Check for successful SSH login
            elif "Accepted password" in log_message or "Accepted publickey" in log_message:
                ip_match = re.search(r"from (\S+)", log_message)
                user_match = re.search(r"for (\S+)", log_message)
                
                return {
                    "event_action": "ssh_successful_login",
                    "event_outcome": "success",
                    "source_ip": ip_match.group(1) if ip_match else None,
                    "user_name": user_match.group(1) if user_match else None,
                    "process": process,
                    "pid": int(pid) if pid else None,
                    "message": log_message,
                    "parsed_at": datetime.utcnow().isoformat()
                }
            
            # Generic syslog
            return {
                "event_action": "syslog",
                "process": process,
                "pid": int(pid) if pid else None,
                "message": log_message,
                "parsed_at": datetime.utcnow().isoformat()
            }
        
        # Fallback: return raw message
        return {
            "event_action": "syslog",
            "message": message,
            "parsed_at": datetime.utcnow().isoformat()
        }
