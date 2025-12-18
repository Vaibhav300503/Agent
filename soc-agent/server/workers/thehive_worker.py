"""
TheHive Integration Worker
Creates cases in TheHive from high/critical alerts
"""
import requests
import logging
import os
import time
import uuid
from pymongo import MongoClient
from datetime import datetime

class TheHiveClient:
    """Client for TheHive API"""
    
    def __init__(self, url, api_key):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.logger = logging.getLogger(__name__)
    
    def create_case(self, alert):
        """Create a case from an alert"""
        severity_map = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        
        case_data = {
            "title": f"{alert['rule_name']} - {alert.get('agent_hostname', 'Unknown')}",
            "description": alert.get("description", f"Alert ID: {alert['alert_id']}"),
            "severity": severity_map.get(alert["severity"], 2),
            "tlp": 2,  # Amber
            "pap": 2,  # Amber
            "tags": [alert["rule_id"], alert["severity"], "automated"]
        }
        
        try:
            response = requests.post(
                f"{self.url}/api/case",
                json=case_data,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            
            case = response.json()
            self.logger.info(f"✓ Created TheHive case #{case.get('caseId')} for alert {alert['alert_id']}")
            
            # Add observables
            if alert.get("parsed_data", {}).get("source_ip"):
                self.add_observable(case["_id"], "ip", alert["parsed_data"]["source_ip"], ["attacker"])
            
            if alert.get("parsed_data", {}).get("user_name"):
                self.add_observable(case["_id"], "other", alert["parsed_data"]["user_name"], ["target_user"])
            
            return case
        
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create TheHive case: {e}")
            if hasattr(e.response, 'text'):
                self.logger.error(f"Response: {e.response.text}")
            raise
    
    def add_observable(self, case_id, data_type, value, tags=None):
        """Add observable to case"""
        obs_data = {
            "dataType": data_type,
            "data": value,
            "ioc": True,
            "tlp": 2,
            "tags": tags or []
        }
        
        try:
            response = requests.post(
                f"{self.url}/api/case/{case_id}/artifact",
                json=obs_data,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            self.logger.debug(f"Added observable {value} to case {case_id}")
        except Exception as e:
            self.logger.error(f"Failed to add observable: {e}")


class TheHiveWorker:
    """Worker that creates TheHive cases for high/critical alerts"""
    
    def __init__(self, mongo_uri, thehive_url, thehive_api_key):
        self.client = MongoClient(mongo_uri, maxPoolSize=10)
        self.db = self.client.get_database()
        self.thehive = TheHiveClient(thehive_url, thehive_api_key)
        self.logger = logging.getLogger(__name__)
        self.logger.info("TheHive Worker initialized")
    
    def run(self):
        """Main worker loop"""
        self.logger.info("TheHive Worker started")
        
        while True:
            try:
                # Find high/critical alerts without TheHive case
                alerts = list(self.db.alerts.find({
                    "severity": {"$in": ["high", "critical"]},
                    "thehive_case_id": None
                }).limit(5))
                
                for alert in alerts:
                    try:
                        # Create TheHive case
                        case = self.thehive.create_case(alert)
                        
                        # Update alert
                        self.db.alerts.update_one(
                            {"_id": alert["_id"]},
                            {"$set": {
                                "thehive_case_id": case.get("caseId"),
                                "thehive_case_number": case.get("number"),
                                "updated_at": datetime.utcnow()
                            }}
                        )
                        
                        # Store case record
                        self.db.cases.insert_one({
                            "case_id": str(uuid.uuid4()),
                            "thehive_case_id": case.get("caseId"),
                            "alert_ids": [alert["alert_id"]],
                            "title": case.get("title"),
                            "severity": alert["severity"],
                            "status": "Open",
                            "created_at": datetime.utcnow(),
                            "updated_at": datetime.utcnow()
                        })
                        
                    except Exception as e:
                        self.logger.error(f"Failed to create case for alert {alert['alert_id']}: {e}")
                
                time.sleep(10)  # Check for new alerts every 10 seconds
            
            except Exception as e:
                self.logger.error(f"TheHive worker error: {e}", exc_info=True)
                time.sleep(30)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
    THEHIVE_URL = os.getenv("THEHIVE_URL")
    THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
    
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        logging.error("TheHive URL and API key must be configured")
        exit(1)
    
    worker = TheHiveWorker(MONGO_URI, THEHIVE_URL, THEHIVE_API_KEY)
    worker.run()
