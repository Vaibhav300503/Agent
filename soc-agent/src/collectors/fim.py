import os
import glob
import uuid
import time
import hashlib
import logging
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collectors.base import BaseCollector
from utils import get_hostname, get_ip_address, get_os_type

class FIMCollector(BaseCollector):
    """
    File Integrity Monitoring Collector
    
    Creates canary files in sensitive directories and monitors them for modifications.
    Any change to canary files indicates potential ransomware activity.
    Also provides process hashing capabilities for malware detection.
    """
    
    def __init__(self, config, transport):
        super().__init__(config, transport)
        self.config_obj = config
        self.hostname = get_hostname()
        self.ip_address = get_ip_address()
        self.os_type = get_os_type()
        
        self.canary_filename = config.get_canary_filename()
        self.monitor_directories = self._expand_directories(config.get_fim_directories())
        self.canary_files = []
        self.observer = None
        
    def _expand_directories(self, directory_patterns):
        """Expand directory patterns with wildcards (e.g., C:\\Users\\*\\Documents)"""
        expanded = []
        for pattern in directory_patterns:
            if '*' in pattern:
                # Use glob to expand wildcards
                matches = glob.glob(pattern)
                expanded.extend(matches)
            else:
                if os.path.exists(pattern):
                    expanded.append(pattern)
        
        return expanded
    
    def start(self):
        """Start FIM monitoring"""
        self.running = True
        
        # Create canary files
        self._create_canary_files()
        
        # Set up watchdog observer
        self._setup_watchdog()
        
        self.logger.info(f"FIM Collector started monitoring {len(self.canary_files)} canary files")
    
    def stop(self):
        """Stop FIM monitoring"""
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            
        self.logger.info("FIM Collector stopped")
    
    def _create_canary_files(self):
        """Create canary files in monitored directories"""
        for directory in self.monitor_directories:
            if not os.path.exists(directory):
                self.logger.warning(f"Directory does not exist: {directory}")
                continue
            
            canary_path = os.path.join(directory, self.canary_filename)
            
            try:
                # Check if canary already exists
                if os.path.exists(canary_path):
                    self.logger.info(f"Canary file already exists: {canary_path}")
                    self.canary_files.append(canary_path)
                    continue
                
                # Create canary file with unique content
                canary_content = f"SOC Canary File - Do Not Modify\nCreated: {datetime.now().isoformat()}\nUUID: {uuid.uuid4()}\n"
                
                with open(canary_path, 'w') as f:
                    f.write(canary_content)
                
                # Hide file on Windows
                if os.name == 'nt':
                    try:
                        import ctypes
                        FILE_ATTRIBUTE_HIDDEN = 0x02
                        ctypes.windll.kernel32.SetFileAttributesW(canary_path, FILE_ATTRIBUTE_HIDDEN)
                    except Exception as e:
                        self.logger.debug(f"Could not hide canary file: {e}")
                
                self.canary_files.append(canary_path)
                self.logger.info(f"Created canary file: {canary_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to create canary in {directory}: {e}")
    
    def _setup_watchdog(self):
        """Set up watchdog file system observer"""
        if not self.canary_files:
            self.logger.warning("No canary files to monitor, skipping watchdog setup")
            return
        
        try:
            self.observer = Observer()
            event_handler = CanaryEventHandler(self)
            
            # Watch each directory containing canary files
            watched_dirs = set()
            for canary in self.canary_files:
                directory = os.path.dirname(canary)
                if directory not in watched_dirs:
                    try:
                        self.observer.schedule(event_handler, directory, recursive=False)
                        watched_dirs.add(directory)
                        self.logger.debug(f"Watching directory: {directory}")
                    except Exception as e:
                        self.logger.error(f"Failed to watch directory {directory}: {e}")
            
            if watched_dirs:
                self.observer.start()
                self.logger.info(f"Watchdog observer started for {len(watched_dirs)} directories")
            else:
                self.logger.warning("No directories could be watched")
        except Exception as e:
            self.logger.error(f"Failed to setup watchdog observer: {e}")
            self.logger.warning("FIM will run without real-time monitoring")
    
    def handle_canary_event(self, event_type, canary_path):
        """Handle canary file modification or deletion"""
        alert_log = {
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": "file_integrity_monitor",
            "event_type": "canary_file_alert",
            "alert_severity": "critical",
            "attack_type": "potential_ransomware",
            "file_path": canary_path,
            "event": event_type,
            "message": f"CRITICAL: Canary file {event_type}: {canary_path} - Possible ransomware activity detected!"
        }
        
        self.send_log(alert_log['message'], alert_log)
        self.logger.critical(f"Canary file {event_type}: {canary_path}")
    
    @staticmethod
    def calculate_file_hash(filepath):
        """
        Calculate SHA256 hash of a file
        Can be used for process executable hashing
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Failed to hash {filepath}: {e}")
            return None


class CanaryEventHandler(FileSystemEventHandler):
    """Event handler for watchdog to monitor canary file changes"""
    
    def __init__(self, fim_collector):
        super().__init__()
        self.fim_collector = fim_collector
    
    def on_modified(self, event):
        """Called when a file is modified"""
        if not event.is_directory and event.src_path in self.fim_collector.canary_files:
            self.fim_collector.handle_canary_event("modified", event.src_path)
    
    def on_deleted(self, event):
        """Called when a file is deleted"""
        if not event.is_directory and event.src_path in self.fim_collector.canary_files:
            self.fim_collector.handle_canary_event("deleted", event.src_path)
    
    def on_moved(self, event):
        """Called when a file is moved/renamed"""
        if not event.is_directory and event.src_path in self.fim_collector.canary_files:
            self.fim_collector.handle_canary_event("moved", event.src_path)
