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
from collectors.windows import WindowsCollector
from collectors.linux import LinuxCollector
from collectors.network import NetworkCollector

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
