import time
import logging
import sys
import os

# Setup paths for local module imports
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)

if script_dir not in sys.path:
    sys.path.insert(0, script_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Add the directory containing agent.py to sys.path to resolve imports correctly
# when running as a script (especially on Linux)
# (Consolidated logic above)



from config import Config
from transport import Transport
# from collectors.windows import WindowsCollector (Imported conditionally)
from collectors.linux import LinuxCollector
from collectors.network import NetworkCollector
from utils import get_hostname, get_ip_address, get_os_type, get_agent_id
import threading
import json
from datetime import datetime

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
        try:
            from collectors.windows import WindowsCollector
            w = WindowsCollector(config, transport)
            w.start()
            collectors.append(w)
            logging.info("Windows collector started successfully")
        except Exception as e:
            logging.error(f"Failed to start Windows collector: {e}")
    else:
        try:
            linux = LinuxCollector(config, transport)
            linux.start()
            collectors.append(linux)
            logging.info("Linux collector started successfully")
        except Exception as e:
            logging.error(f"Failed to start Linux collector: {e}")

    # Start Network Collector (Cross-platform)
    if config.config.get('network', {}).get('enabled', False):
        logging.info("Starting Network Collector")
        try:
            nc = NetworkCollector(config, transport)
            nc.start()
            collectors.append(nc)
            logging.info("Network collector started successfully")
        except Exception as e:
            logging.error(f"Failed to start Network collector: {e}")
    
    # Start FIM Collector (File Integrity Monitoring)
    if config.enable_fim:
        logging.info("Starting FIM Collector")
        try:
            from collectors.fim import FIMCollector
            fim = FIMCollector(config, transport)
            fim.start()
            collectors.append(fim)
            logging.info("FIM collector started successfully")
        except Exception as e:
            logging.error(f"Failed to start FIM collector: {e}")
            logging.warning("Continuing without FIM - check if watchdog is installed")
        
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
