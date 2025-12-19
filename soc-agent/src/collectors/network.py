import platform
import subprocess
import logging
import threading
import time
import os
import re
from collectors.base import BaseCollector
from utils import get_hostname, get_ip_address
from datetime import datetime

class NetworkCollector(BaseCollector):
    def __init__(self, config, transport):
        super().__init__(config, transport)
        self.hostname = get_hostname()
        self.ip_address = get_ip_address()
        self.interval = config.config.get('network', {}).get('interval_sec', 60)
        self.os_type = platform.system()

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
            try:
                if self.os_type == 'Linux':
                    self._collect_linux()
                elif self.os_type == 'Windows':
                    self._collect_windows()
            except Exception as e:
                self.logger.error(f"Error collecting network logs: {e}")
            
            time.sleep(self.interval)

    def _collect_linux(self):
        # Read /proc/net/tcp and /proc/net/udp
        # This avoids external dependencies like netstat or ss
        for protocol in ['tcp', 'udp']:
            path = f"/proc/net/{protocol}"
            if not os.path.exists(path):
                continue
                
            try:
                with open(path, 'r') as f:
                    lines = f.readlines()[1:] # Skip header
                    
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) < 4: continue
                    
                    # Format: sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
                    local_ip, local_port = self._parse_proc_addr(parts[1])
                    remote_ip, remote_port = self._parse_proc_addr(parts[2])
                    state = parts[3]
                    uid = parts[7]
                    
                    # 01 = ESTABLISHED, 0A = LISTEN
                    if state == '0A':
                        status = "LISTEN"
                    elif state == '01':
                        status = "ESTABLISHED"
                    else:
                        continue # Skip time_wait, close_wait for noise reduction
                        
                    log = {
                        "timestamp": datetime.fromtimestamp(time.time()).isoformat(),
                        "hostname": self.hostname,
                        "os_type": "Linux",
                        "log_source": "network_snapshot",
                        "protocol": protocol,
                        "src_ip": local_ip,
                        "src_port": local_port,
                        "dst_ip": remote_ip,
                        "dst_port": remote_port,
                        "status": status,
                        "message": f"Network Connection: {protocol.upper()} {local_ip}:{local_port} -> {remote_ip}:{remote_port} [{status}]"
                    }
                    self.send_log(log['message'], log)
            except Exception as e:
                self.logger.error(f"Failed to read /proc/net/{protocol}: {e}")

    def _parse_proc_addr(self, hex_addr):
        # addr is like 0100007F:0050 (127.0.0.1:80)
        try:
            ip_hex, port_hex = hex_addr.split(':')
            port = int(port_hex, 16)
            # IP is in little-endian hex
            ip_octets = [str(int(ip_hex[i:i+2], 16)) for i in range(6, -2, -2)]
            ip = ".".join(ip_octets)
            return ip, port
        except:
            return "0.0.0.0", 0

    def _collect_windows(self):
        # Use netstat via subprocess
        try:
            # -n: numerical addresses, -a: all connections, -o: owner PID, -p: protocol
            output = subprocess.check_output("netstat -ano -p tcp", shell=True).decode('utf-8', errors='ignore')
            
            for line in output.splitlines():
                line = line.strip()
                if not line.startswith("TCP"): continue
                
                parts = line.split()
                # Format: TCP  LocalAddr  RemoteAddr  State  PID
                if len(parts) < 5: continue
                
                state = parts[3]
                if state not in ["ESTABLISHED", "LISTENING"]:
                    continue
                    
                local_addr = parts[1]
                remote_addr = parts[2]
                
                # Parse IP/Port (handle [::] IPv6 if needed, but keeping simple for now)
                l_ip, l_port = self._parse_netstat_addr(local_addr)
                r_ip, r_port = self._parse_netstat_addr(remote_addr)
                
                log = {
                    "timestamp": datetime.fromtimestamp(time.time()).isoformat(),
                    "hostname": self.hostname,
                    "os_type": "Windows",
                    "log_source": "network_snapshot",
                    "protocol": "TCP",
                    "src_ip": l_ip,
                    "src_port": l_port,
                    "dst_ip": r_ip,
                    "dst_port": r_port,
                    "status": state,
                    "message": f"Network Connection: TCP {l_ip}:{l_port} -> {r_ip}:{r_port} [{state}]"
                }
                self.send_log(log['message'], log)
                
        except Exception as e:
            self.logger.error(f"Netstat failed: {e}")

    def _parse_netstat_addr(self, addr):
        if ":" not in addr: return addr, 0
        # Handle IPv6 [..]:port vs IPv4 ip:port
        try:
            if "]" in addr:
                ip = addr.split("]:")[0] + "]"
                port = int(addr.split("]:")[1])
            else:
                ip = addr.rsplit(":", 1)[0]
                port = int(addr.rsplit(":", 1)[1])
            return ip, port
        except:
            return addr, 0
