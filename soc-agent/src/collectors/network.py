import platform
import subprocess
import logging
import threading
import time
import os
import re
import psutil
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
        
        # Bandwidth monitoring
        self.bandwidth_threshold_mb = config.get_network_bandwidth_threshold()
        self.enable_process_attribution = config.get_enable_process_attribution()
        self._previous_net_io = None  # For tracking bandwidth deltas
        
        # Flow metrics tracking (enterprise telemetry)
        self._connection_start_times = {}  # (local_ip, local_port, remote_ip, remote_port) -> start_time
        self._last_io_counters = None  # For calculating delta packets/bytes

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
                # Track bandwidth anomalies
                self._track_bandwidth_anomalies()
                
                # Collect connection data
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
                        "timestamp": datetime.now().isoformat(),
                        "hostname": self.hostname,
                        "ip_address": self.ip_address,
                        "os_type": "Linux",
                        "log_source": "network_snapshot",
                        "protocol": protocol.upper(),
                        "src_ip": local_ip,
                        "src_port": local_port,
                        "dst_ip": remote_ip,
                        "dst_port": remote_port,
                        "status": status,
                        # Network flow metrics (enterprise telemetry)
                        "duration": self._get_connection_duration(local_ip, local_port, remote_ip, remote_port),
                        "bytes_sent": None,  # Per-connection bytes not available from /proc/net
                        "bytes_received": None,
                        "packets_sent": None,
                        "packets_received": None,
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
    
    def _get_connection_duration(self, local_ip, local_port, remote_ip, remote_port):
        """Track connection duration for flow metrics"""
        conn_key = (local_ip, local_port, remote_ip, remote_port)
        current_time = time.time()
        
        if conn_key not in self._connection_start_times:
            # New connection, start tracking
            self._connection_start_times[conn_key] = current_time
            return 0.0
        else:
            # Return duration since first seen
            return round(current_time - self._connection_start_times[conn_key], 2)

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
                    "timestamp": datetime.now().isoformat(),
                    "hostname": self.hostname,
                    "ip_address": self.ip_address,
                    "os_type": "Windows",
                    "log_source": "network_snapshot",
                    "protocol": "TCP",
                    "src_ip": l_ip,
                    "src_port": l_port,
                    "dst_ip": r_ip,
                    "dst_port": r_port,
                    "status": state,
                    # Network flow metrics (enterprise telemetry)
                    "duration": self._get_connection_duration(l_ip, l_port, r_ip, r_port),
                    "bytes_sent": None,
                    "bytes_received": None,
                    "packets_sent": None,
                    "packets_received": None,
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
    
    def _track_bandwidth_anomalies(self):
        """Monitor bandwidth usage and detect anomalies (DDoS, data exfiltration)"""
        try:
            current_io = psutil.net_io_counters()
            
            if self._previous_net_io is not None:
                # Calculate deltas in MB
                bytes_sent_delta = (current_io.bytes_sent - self._previous_net_io.bytes_sent) / 1024 / 1024
                bytes_recv_delta = (current_io.bytes_recv - self._previous_net_io.bytes_recv) / 1024 / 1024
                
                # Check if either direction exceeds threshold
                if bytes_sent_delta > self.bandwidth_threshold_mb:
                    alert_log = {
                        "timestamp": datetime.now().isoformat(),
                        "hostname": self.hostname,
                        "ip_address": self.ip_address,
                        "os_type": self.os_type,
                        "log_source": "network_bandwidth",
                        "event_type": "traffic_anomaly",
                        "alert_severity": "high",
                        "direction": "outbound",
                        "volume_mb": round(bytes_sent_delta, 2),
                        "time_window_sec": self.interval,
                        "message": f"High outbound bandwidth detected: {round(bytes_sent_delta, 2)} MB in {self.interval} seconds"
                    }
                    self.send_log(alert_log['message'], alert_log)
                
                if bytes_recv_delta > self.bandwidth_threshold_mb:
                    alert_log = {
                        "timestamp": datetime.now().isoformat(),
                        "hostname": self.hostname,
                        "ip_address": self.ip_address,
                        "os_type": self.os_type,
                        "log_source": "network_bandwidth",
                        "event_type": "traffic_anomaly",
                        "alert_severity": "high",
                        "direction": "inbound",
                        "volume_mb": round(bytes_recv_delta, 2),
                        "time_window_sec": self.interval,
                        "message": f"High inbound bandwidth detected: {round(bytes_recv_delta, 2)} MB in {self.interval} seconds"
                    }
                    self.send_log(alert_log['message'], alert_log)
            
            self._previous_net_io = current_io
            
        except Exception as e:
            self.logger.error(f"Bandwidth tracking error: {e}")
    
    def _get_process_info(self, pid):
        """Get process name and executable path for a given PID"""
        try:
            process = psutil.Process(pid)
            return {
                "process_name": process.name(),
                "process_exe": process.exe(),
                "process_pid": pid
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {
                "process_name": "unknown",
                "process_exe": "unknown",
                "process_pid": pid
            }
    
    def _collect_connections_with_processes(self):
        """Collect network connections with process attribution (cross-platform)"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Only track ESTABLISHED connections for data leak monitoring
                if conn.status == 'ESTABLISHED' and conn.pid:
                    # Get process info
                    process_info = self._get_process_info(conn.pid) if self.enable_process_attribution else {}
                    
                    log = {
                        "timestamp": datetime.now().isoformat(),
                        "hostname": self.hostname,
                        "ip_address": self.ip_address,
                        "os_type": self.os_type,
                        "log_source": "network_connection",
                        "event_type": "established_connection",
                        "protocol": "TCP" if conn.type == 1 else "UDP",
                        "local_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip if conn.raddr else "0.0.0.0",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "status": conn.status,
                        "message": f"Connection: {conn.laddr.ip if conn.laddr else '?'}:{conn.laddr.port if conn.laddr else '?'} -> {conn.raddr.ip if conn.raddr else '?'}:{conn.raddr.port if conn.raddr else '?'}"
                    }
                    
                    # Add process info if available
                    if process_info:
                        log.update(process_info)
                    
                    self.send_log(log['message'], log)
                    
        except Exception as e:
            self.logger.error(f"Connection collection with processes failed: {e}")

