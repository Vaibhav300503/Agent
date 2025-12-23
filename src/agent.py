import time
import logging
import sys
import os

# Add the directory containing agent.py to sys.path to resolve imports correctly
# when running as a script (especially on Linux)
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.append(script_dir)

from config import Config
from transport import Transport
# from collectors.windows import WindowsCollector (Imported conditionally)
from collectors.linux import LinuxCollector
from collectors.network import NetworkCollector
from utils import get_hostname, get_ip_address, get_os_type, get_agent_id
import threading
import json

def setup_logging(level):
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("soc_agent.log"),
            logging.StreamHandler()
        ]
    )

def main():
    # Load Config
    config = Config()
    setup_logging(config.config.get('agent', {}).get('log_level', 'INFO'))
    
    logging.info("Starting SOC Agent...")
    
    # Init Transport
    transport = Transport(config)
    transport.start()
    
    collectors = []
    
    # Detect OS and Init Collectors
    if os.name == 'nt':
        logging.info("Detected Windows Environment")
        from collectors.windows import WindowsCollector
        w = WindowsCollector(config, transport)
        w.start()
        collectors.append(w)
    else:
        linux = LinuxCollector(config, transport)
        linux.start()
        collectors.append(linux)

    # Start Network Collector (Cross-platform)
    if config.config.get('network', {}).get('enabled', False):
        logging.info("Starting Network Collector")
        nc = NetworkCollector(config, transport)
        nc.start()
        collectors.append(nc)
        
    # Start Heartbeat Thread
    logging.info("Starting Heartbeat Thread")
    def heartbeat_loop():
        agent_id = get_agent_id()
        while transport.running:
            try:
                # Calculate buffer size (rough estimate)
                buffer_size = 0
                if os.path.exists(config.buffer_path):
                    buffer_size = os.path.getsize(config.buffer_path)
                
                heartbeat_data = {
                    "agent_id": agent_id,
                    "hostname": get_hostname(),
                    "endpoint_name": get_hostname(), # Map hostname to endpoint_name as requested
                    "ip_address": get_ip_address(),
                    "os_type": get_os_type(),
                    "agent_version": "2.0.0",
                    "buffer_size_bytes": buffer_size,
                    "timestamp": datetime.now().isoformat()
                }
                transport.send_heartbeat(heartbeat_data)
            except Exception as e:
                logging.error(f"Heartbeat loop error: {e}")
            
            # Wait 60 seconds (or until agent stops)
            for _ in range(60):
                if not transport.running: break
                time.sleep(1)

    from datetime import datetime
    hb_thread = threading.Thread(target=heartbeat_loop, daemon=True, name="Heartbeat")
    hb_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping Agent...")
        for c in collectors:
            c.stop()
        transport.stop()
        logging.info("Agent Stopped.")

if __name__ == "__main__":
    main()
