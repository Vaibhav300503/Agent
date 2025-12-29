"""
Log Parser Worker
Processes raw logs and extracts structured fields
"""
from pymongo import MongoClient
import time
import logging
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers import WindowsEventParser, LinuxSyslogParser

class ParserWorker:
    """Worker that parses raw logs"""
    
    def __init__(self, mongo_uri):
        self.client = MongoClient(mongo_uri, maxPoolSize=20)
        self.db = self.client.get_database()
        
        # Initialize parsers
        self.windows_parser = WindowsEventParser()
        self.linux_parser = LinuxSyslogParser()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Parser Worker initialized")
    
    def run(self):
        """Main worker loop"""
        self.logger.info("Parser Worker started")
        
        while True:
            try:
                # Get unprocessed logs
                raw_logs = list(self.db.raw_logs.find(
                    {"processed": False}
                ).limit(50))
                
                if not raw_logs:
                    time.sleep(1)
                    continue
                
                self.logger.debug(f"Processing {len(raw_logs)} logs")
                
                for raw_log in raw_logs:
                    try:
                        self._process_log(raw_log)
                    except Exception as e:
                        self.logger.error(f"Error processing log {raw_log['_id']}: {e}", exc_info=True)
                        # Mark as processed with error
                        self.db.raw_logs.update_many(
                            {"_id": raw_log["_id"]},
                            {"$set": {"processed": True, "parse_error": str(e)}}
                        )
            
            except Exception as e:
                self.logger.error(f"Worker loop error: {e}", exc_info=True)
                time.sleep(5)
    
    def _process_log(self, raw_log):
        """Process a single log"""
        log_source = raw_log.get("raw_data", {}).get("log_source", "")
        
        # Select parser based on log source
        if log_source.startswith("windows_"):
            parsed = self.windows_parser.parse(raw_log["raw_data"])
        elif "/var/log/" in log_source:
            parsed = self.linux_parser.parse(raw_log["raw_data"])
        else:
            # Generic fallback
            parsed = {
                "message": str(raw_log.get("raw_data", {})),
                "event_action": "unknown"
            }
        
        # Store parsed data inline in raw_log document
        self.db.raw_logs.update_many(
            {"_id": raw_log["_id"]},
            {"$set": {
                "parsed_data": parsed,
                "processed": True
            }}
        )
        
        self.logger.debug(f"Parsed log {raw_log['_id']}")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
    
    worker = ParserWorker(MONGO_URI)
    worker.run()
