import os
import time
import threading
import logging
from .base import BaseCollector
from ..utils import get_hostname, get_ip_address, get_os_type

class LinuxCollector(BaseCollector):
    def __init__(self, config, transport):
        super().__init__(config, transport)
        self.files = config.get_linux_files()
        self.hostname = get_hostname()
        self.ip_address = get_ip_address()
        self.os_type = get_os_type()
        self.file_pointers = {} # filepath -> offset
        self.file_mtimes = {} # filepath -> last modification time

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
        for f in self.files:
            if os.path.exists(f):
                try:
                    self.file_pointers[f] = os.path.getsize(f)
                except OSError:
                    self.file_pointers[f] = 0

        while self.running:
            for filepath in self.files:
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
        # Basic Syslog normalization
        # In a real scenario, we'd use regex to parse RFC3164/5424 timestamps
        # For now, we wrap the raw line
        
        data = {
            "timestamp": time.time(), # Capture time if we can't parse log time
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "log_source": filepath,
            "message": line,
            "raw_log": line
        }
        
        self.send_log(line, data)
