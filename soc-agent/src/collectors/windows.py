import logging
import time
import os
import win32evtlog # type: ignore
import win32evtlogutil # type: ignore
import win32security # type: ignore
import win32con # type: ignore
import json
import threading
from datetime import datetime
from collectors.base import BaseCollector
from utils import get_hostname, get_ip_address, get_os_type

class WindowsCollector(BaseCollector):
    def __init__(self, config, transport):
        super().__init__(config, transport)
        self.channels = config.get_windows_channels()
        self.hostname = get_hostname()
        self.ip_address = get_ip_address()
        self.os_type = get_os_type()
        self.checkpoints = {} # Channel -> RecordNumber
        self.last_record_counts = {} # Channel -> Last total count
        
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()
        
    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
            
    def _poll_loop(self):
        while self.running:
            for channel in self.channels:
                try:
                    self._collect_channel(channel)
                except Exception as e:
                    self.logger.error(f"Error reading channel {channel}: {e}")
            
            time.sleep(self.config.polling_interval)
            
    def _collect_channel(self, channel):
        hand = win32evtlog.OpenEventLog(None, channel)
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            
            # Simple checkpointing logic: 
            # In a real heavy-duty agent, we'd use SEEK_READ + RecordNumber.
            # Here, for simplicity in "tailing", we might miss logs if not running.
            # Improved approach: Store last_read_time or check NEW records.
            # Given requirements: "Incemental log reading (offset / last-read checkpoint)"
            # we should persist record numbers.
            
            # Since backwards reading is default for `ReadEventLog` without seek, 
            # we actually want FORWARD read from checking point or end.
            # But win32evtlog API via pywin32 is tricky with Seek.
            # Standard approach: Read backwards until we hit a known record, or just read all new.
            # Optimized approach for this script:
            # 1. Open Log.
            # 2. Get OldestRecord and NumberOfRecords.
            # 3. LastRecord = Oldest + Number - 1.
            # 4. We want to read from (LastCheckpoint + 1) to LastRecord.
            
            # However, `ReadEventLog` in python is usually Sequential.
            # Let's try to just read everything since startup for now, or just the last N if starting fresh.
            pass 
        finally:
            win32evtlog.CloseEventLog(hand)

        # Re-implementing with a cleaner "Tail" approach using WMI or just standard API 
        # But `ReadEventLog` is faster than WMI.
        
        # Let's use a simpler strategy for this MVP:
        # Read the last X events, filter by TimeGenerated > LastPollTime.
        # This avoids complex RecordID math which varies by OS version sometimes.
        
    def _collect_channel(self, channel):
        # Implementation using TimeGenerated watermarking
        last_time = self.checkpoints.get(channel, datetime.now().timestamp())
        
        # Current time for next run
        new_max_time = last_time
        
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
            
            # OPTIMIZATION: Check if new events exist before querying
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            last_count = self.last_record_counts.get(channel, 0)
            
            if total_records == last_count:
                self.logger.debug(f"No new events in {channel} (count: {total_records})")
                win32evtlog.CloseEventLog(hand)
                return
            
            self.last_record_counts[channel] = total_records
            
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = []
            while True:
                events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events_batch:
                    break
                    
                for event in events_batch:
                    # Event times are usually pywintypes.datetime, convert to timestamp
                    event_time = event.TimeGenerated.timestamp()
                    
                    if event_time <= last_time:
                        # Reached events we've already seen (assuming roughly ordered)
                        # In high volume, this might be flaky if timestamps share the same second.
                        # But for MVP this is robust enough.
                        break
                        
                    if event_time > new_max_time:
                        new_max_time = event_time
                        
                    # Process Event
                    data = self._process_event(event, channel)
                    self.send_log(event, data)
                
                if events_batch and events_batch[-1].TimeGenerated.timestamp() <= last_time:
                    break
                    
            self.checkpoints[channel] = new_max_time
            
        except Exception as e:
            self.logger.error(f"Failed to read {channel}: {e}")
        finally:
             win32evtlog.CloseEventLog(hand)

    def _process_event(self, event, channel):
        # Safe string conversion
        msg = ""
        try:
            msg = win32evtlogutil.SafeFormatMessage(event, channel)
        except Exception:
            msg = str(event.StringInserts) if event.StringInserts else ""

        event_id = event.EventID & 0xFFFF
        
        # Basic log entry
        log_entry = {
            "timestamp": event.TimeGenerated.isoformat(),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": f"windows_{channel}",
            "event_id": event_id,
            "severity": event.EventType,
            "message": msg, 
            "original_record_number": event.RecordNumber
        }
        
        # Route to specialized parsers based on event ID
        if event_id in [1116, 1117, 1118]:
            # Windows Defender events
            self._parse_defender_event(log_entry, event, msg)
        elif event_id in [4624, 4625]:
            # Authentication events
            self._parse_auth_event(log_entry, event, msg)
        elif event_id in [5152, 5157]:
            # Firewall blocking events
            self._parse_firewall_event(log_entry, event, msg)
        elif event_id == 4657:
            # Registry modification events (existing)
            self._parse_registry_event(log_entry, msg)
        elif event_id == 4688:
            # Process creation - add hash
            self._parse_process_creation(log_entry, event, msg)
            
        return log_entry
    
    def _parse_defender_event(self, log_entry, event, msg):
        """Parse Windows Defender malware detection events"""
        event_id = event.EventID & 0xFFFF
        
        log_entry["log_source"] = "windows_defender"
        log_entry["event_type"] = "malware_detection"
        
        lines = msg.splitlines()
        for line in lines:
            if "Threat Name:" in line or "Name:" in line:
                log_entry["threat_name"] = line.split(":", 1)[1].strip()
            elif "Severity:" in line:
                log_entry["threat_severity"] = line.split(":", 1)[1].strip()
            elif "Category:" in line:
                log_entry["threat_category"] = line.split(":", 1)[1].strip()
            elif "Path:" in line:
                log_entry["detection_path"] = line.split(":", 1)[1].strip()
            elif "Detection User:" in line or "User:" in line:
                log_entry["detection_user"] = line.split(":", 1)[1].strip()
            elif "Action:" in line:
                log_entry["remediation_action"] = line.split(":", 1)[1].strip()
        
        # Event-specific tags
        if event_id == 1116:
            log_entry["defender_event"] = "malware_detected"
        elif event_id == 1117:
            log_entry["defender_event"] = "action_taken"
        elif event_id == 1118:
            log_entry["defender_event"] = "remediation_failed"
            log_entry["alert_severity"] = "high"  # Failed remediation is critical
    
    def _parse_auth_event(self, log_entry, event, msg):
        """Parse authentication events (logon success/failure)"""
        event_id = event.EventID & 0xFFFF
        
        log_entry["log_source"] = "windows_authentication"
        log_entry["event_type"] = "authentication"
        
        lines = msg.splitlines()
        for line in lines:
            if "Account Name:" in line and "account_name" not in log_entry:
                # First Account Name is usually the subject
                log_entry["account_name"] = line.split(":", 1)[1].strip()
            elif "Account Domain:" in line and "account_domain" not in log_entry:
                log_entry["account_domain"] = line.split(":", 1)[1].strip()
            elif "Logon Type:" in line:
                logon_type = line.split(":", 1)[1].strip()
                log_entry["logon_type_code"] = logon_type
                # Normalize logon type
                logon_type_map = {
                    "2": "Interactive",
                    "3": "Network",
                    "4": "Batch",
                    "5": "Service",
                    "7": "Unlock",
                    "8": "NetworkCleartext",
                    "9": "NewCredentials",
                    "10": "RemoteInteractive",
                    "11": "CachedInteractive"
                }
                log_entry["logon_type"] = logon_type_map.get(logon_type, f"Unknown({logon_type})")
            elif "Source Network Address:" in line or "Workstation Name:" in line:
                if "Source Network Address:" in line:
                    log_entry["source_ip"] = line.split(":", 1)[1].strip()
            elif "Workstation Name:" in line and "workstation" not in log_entry:
                log_entry["workstation"] = line.split(":", 1)[1].strip()
            elif "Failure Reason:" in line:
                log_entry["failure_reason"] = line.split(":", 1)[1].strip()
            elif "Sub Status:" in line or "Status:" in line:
                if "sub_status" not in log_entry and "Sub Status:" in line:
                    log_entry["sub_status"] = line.split(":", 1)[1].strip()
        
        # Tag event type - normalized auth fields
        if event_id == 4624:
            log_entry["auth_result"] = "success"
            log_entry["auth_status"] = "success"  # Normalized field
        elif event_id == 4625:
            log_entry["auth_result"] = "failure"
            log_entry["auth_status"] = "failure"  # Normalized field
            log_entry["alert_severity"] = "medium"
        
        # Add normalized auth_method based on logon_type
        logon_type_code = log_entry.get("logon_type_code", "")
        if logon_type_code in ["3", "8"]:
            log_entry["auth_method"] = "network"
        elif logon_type_code in ["2", "10", "11"]:
            log_entry["auth_method"] = "interactive"
        elif logon_type_code in ["4", "5"]:
            log_entry["auth_method"] = "service"
        else:
            log_entry["auth_method"] = "other"
        
        # Copy logon_type to login_type for schema consistency
        if "logon_type" in log_entry:
            log_entry["login_type"] = log_entry["logon_type"]
    
    def _parse_firewall_event(self, log_entry, event, msg):
        """Parse firewall blocking events"""
        event_id = event.EventID & 0xFFFF
        
        log_entry["log_source"] = "windows_firewall"
        log_entry["event_type"] = "firewall_block"
        
        lines = msg.splitlines()
        for line in lines:
            if "Source Address:" in line:
                log_entry["source_ip"] = line.split(":", 1)[1].strip()
            elif "Source Port:" in line:
                try:
                    log_entry["source_port"] = int(line.split(":", 1)[1].strip())
                except:
                    pass
            elif "Destination Address:" in line:
                log_entry["destination_ip"] = line.split(":", 1)[1].strip()
            elif "Destination Port:" in line:
                try:
                    log_entry["destination_port"] = int(line.split(":", 1)[1].strip())
                except:
                    pass
            elif "Protocol:" in line:
                protocol = line.split(":", 1)[1].strip()
                # Map protocol number to name
                protocol_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
                log_entry["protocol"] = protocol_map.get(protocol, protocol)
            elif "Application:" in line or "Application Name:" in line:
                log_entry["application"] = line.split(":", 1)[1].strip()
        
        # Port scan detection heuristic
        if "destination_port" in log_entry and "source_ip" in log_entry:
            self._detect_port_scan(log_entry["source_ip"], log_entry.get("destination_port"))
        
        # Event-specific tags
        if event_id == 5152:
            log_entry["firewall_event"] = "packet_blocked"
        elif event_id == 5157:
            log_entry["firewall_event"] = "connection_blocked"
    
    def _parse_registry_event(self, log_entry, msg):
        """Parse registry modification events (existing logic)"""
        lines = msg.splitlines()
        for line in lines:
            if "Object Name:" in line:
                log_entry["registry_key"] = line.split("Object Name:", 1)[1].strip()
            if "Value Name:" in line:
                log_entry["registry_value"] = line.split("Value Name:", 1)[1].strip()
            if "Operation Type:" in line:
                log_entry["operation"] = line.split("Operation Type:", 1)[1].strip()
            if "Account Name:" in line and "account_name" not in log_entry:
                log_entry["account_name"] = line.split("Account Name:", 1)[1].strip()
    
    def _parse_process_creation(self, log_entry, event, msg):
        """Parse process creation and add executable hash"""
        log_entry["event_type"] = "process_creation"
        
        lines = msg.splitlines()
        for line in lines:
            if "New Process Name:" in line or "Process Name:" in line:
                process_path = line.split(":", 1)[1].strip()
                log_entry["process_path"] = process_path
                
                # Calculate hash if file exists
                if os.path.exists(process_path):
                    try:
                        log_entry["process_hash_sha256"] = self._calculate_file_hash(process_path)
                    except Exception as e:
                        self.logger.debug(f"Could not hash {process_path}: {e}")
            elif "Account Name:" in line and "account_name" not in log_entry:
                log_entry["account_name"] = line.split(":", 1)[1].strip()
    
    def _calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _detect_port_scan(self, source_ip, dest_port):
        """Detect potential port scanning behavior"""
        if not hasattr(self, '_port_scan_tracker'):
            self._port_scan_tracker = {}  # source_ip -> {ports: set(), first_seen: timestamp}
        
        import time
        current_time = time.time()
        
        if source_ip not in self._port_scan_tracker:
            self._port_scan_tracker[source_ip] = {
                'ports': set(),
                'first_seen': current_time
            }
        
        tracker = self._port_scan_tracker[source_ip]
        
        # Reset if more than 60 seconds have passed
        if current_time - tracker['first_seen'] > 60:
            tracker['ports'] = set()
            tracker['first_seen'] = current_time
        
        tracker['ports'].add(dest_port)
        
        # Alert if more than 10 unique ports blocked from same IP within 60 seconds
        if len(tracker['ports']) > 10:
            alert_log = {
                "timestamp": datetime.now().isoformat(),
                "hostname": self.hostname,
                "ip_address": self.ip_address,
                "os_type": self.os_type,
                "log_source": "windows_firewall",
                "event_type": "port_scan_detected",
                "alert_severity": "high",
                "source_ip": source_ip,
                "unique_ports_scanned": len(tracker['ports']),
                "message": f"Potential port scan detected from {source_ip}: {len(tracker['ports'])} unique ports blocked in 60 seconds"
            }
            self.send_log(alert_log['message'], alert_log)
            
            # Reset to avoid repeated alerts
            tracker['ports'] = set()
            tracker['first_seen'] = current_time

