"""
Detection Worker
Applies detection rules to enriched logs and generates alerts
"""
from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import json
import uuid
import logging
import os
import redis
import time

import re

class SimpleRuleEngine:
    """Simple threshold-based rule engine"""
    
    def __init__(self, db, redis_client=None):
        self.db = db
        self.redis = redis_client
        self.rules = []
        self.logger = logging.getLogger(__name__)
        self.load_rules()
    
    def load_rules(self):
        """Load enabled rules from MongoDB"""
        self.rules = list(self.db.rules.find({"enabled": True}))
        self.logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def check_log(self, raw_log):
        """Check if log matches any rule"""
        parsed = raw_log.get("parsed_data", {})
        
        for rule in self.rules:
            if self._match_rule(rule, parsed, raw_log):
                return self._create_alert(rule, raw_log, parsed)
        
        return None
    
    def _match_rule(self, rule, parsed, raw_log):
        """Check if a log matches a rule"""
        conditions = rule.get("conditions", {})
        
        # Match event code (single or list)
        if "event_code" in conditions:
            ec = conditions["event_code"]
            log_ec = parsed.get("event_code")
            if isinstance(ec, list):
                if log_ec not in ec: return False
            elif log_ec != ec:
                return False
        
        # Match outcome
        if "outcome" in conditions:
            if parsed.get("event_outcome") != conditions["outcome"]:
                return False
        
        # Complex Filters
        filters = conditions.get("filters", [])
        for f in filters:
            field = f.get("field")
            operator = f.get("operator", "eq")
            value = f.get("value")
            log_val = parsed.get(field)
            
            if operator == "eq":
                if log_val != value: return False
            elif operator == "neq":
                if log_val == value: return False
            elif operator == "regex":
                if not log_val or not re.search(value, str(log_val), re.I):
                    return False
            elif operator == "contains":
                if not log_val or value not in str(log_val):
                    return False
            elif operator == "in":
                if log_val not in value:
                    return False
        
        # Threshold detection
        if "threshold" in conditions:
            return self._check_threshold(rule, parsed, raw_log)
        
        return True
    
    def _check_threshold(self, rule, parsed, current_log):
        """Check if threshold is exceeded within timeframe"""
        conditions = rule["conditions"]
        timeframe_str = conditions.get("timeframe", "5m")
        threshold = conditions.get("threshold", 5)
        group_by = conditions.get("group_by", ["source_ip", "user_name"])
        
        # Parse timeframe (e.g., "5m" -> 5 minutes)
        if timeframe_str.endswith('m'):
            minutes = int(timeframe_str.rstrip('m'))
        elif timeframe_str.endswith('h'):
            minutes = int(timeframe_str.rstrip('h')) * 60
        else:
            minutes = 5
            
        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        # Build query
        query = {
            "timestamp": {"$gte": start_time},
            "processed": True
        }
        
        # Match event code(s)
        ec = conditions.get("event_code")
        if ec:
            if isinstance(ec, list):
                query["parsed_data.event_code"] = {"$in": ec}
            else:
                query["parsed_data.event_code"] = ec
        
        # Add values for grouping
        for field in group_by:
            val = parsed.get(field)
            if val:
                query[f"parsed_data.{field}"] = val
        
        # Add additional filters to query if possible
        filters = conditions.get("filters", [])
        for f in filters:
            if f.get("operator") == "eq":
                query[f"parsed_data.{f['field']}"] = f["value"]
        
        # Count matching events
        count = self.db.raw_logs.count_documents(query)
        
        return count >= threshold
    
    def _create_alert(self, rule, raw_log, parsed):
        """Create alert with inline data"""
        alert_id = str(uuid.uuid4())
        
        # Dedupe hash
        dedupe_key = {
            "rule_id": rule["rule_id"],
            "source_ip": parsed.get("source_ip"),
            "user_name": parsed.get("user_name"),
            "hour": datetime.utcnow().replace(minute=0, second=0, microsecond=0).isoformat()
        }
        dedupe_hash = hashlib.sha256(json.dumps(dedupe_key, sort_keys=True).encode()).hexdigest()
        
        # Check for existing alert (deduplication)
        existing = self.db.alerts.find_one({"dedupe_hash": dedupe_hash})
        if existing:
            # Increment dedupe count
            self.db.alerts.update_one(
                {"_id": existing["_id"]},
                {
                    "$inc": {"dedupe_count": 1},
                    "$push": {"raw_log_ids": raw_log["_id"]},
                    "$set": {"updated_at": datetime.utcnow()}
                }
            )
            self.logger.info(f"Deduplicated alert {existing['alert_id']}")
            return None  # Don't create duplicate
        
        # Create new alert
        alert = {
            "alert_id": alert_id,
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "description": rule.get("description", ""),
            "timestamp": datetime.utcnow(),
            "parsed_data": parsed,  # Inline parsed fields
            "enrichments": parsed.get("geo", {}),  # Inline enrichments
            "raw_log_ids": [raw_log["_id"]],
            "agent_hostname": raw_log.get("metadata", {}).get("hostname"),
            "endpoint_name": raw_log.get("metadata", {}).get("endpoint_name") or raw_log.get("metadata", {}).get("hostname"),
            "agent_ip": raw_log.get("ip_address"),
            "status": "new",
            "thehive_case_id": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "dedupe_hash": dedupe_hash,
            "dedupe_count": 1
        }
        
        self.db.alerts.insert_one(alert)
        
        # Mark raw_log to prevent deletion
        self.db.raw_logs.update_one(
            {"_id": raw_log["_id"]},
            {"$set": {"has_alert": True}}
        )
        
        self.logger.info(f"✓ Created {rule['severity']} alert: {alert_id} - {rule['name']}")
        
        # Push high/critical alerts to Redis for real-time dashboard
        if self.redis and alert["severity"] in ["high", "critical"]:
            try:
                self.redis.publish("soc:alerts:realtime", json.dumps({
                    "alert_id": alert["alert_id"],
                    "rule_name": alert["rule_name"],
                    "severity": alert["severity"],
                    "timestamp": alert["timestamp"].isoformat(),
                    "source_ip": parsed.get("source_ip"),
                    "user_name": parsed.get("user_name"),
                    "agent": alert.get("agent_hostname")
                }))
                self.logger.info(f"→ Pushed {alert['severity']} alert to Redis")
            except Exception as e:
                self.logger.error(f"Redis publish error: {e}")
        
        return alert


class DetectorWorker:
    """Worker that detects threats using rules"""
    
    def __init__(self, mongo_uri, redis_host="localhost", redis_password=None):
        self.client = MongoClient(mongo_uri, maxPoolSize=20)
        self.db = self.client.get_database()
        
        # Initialize Redis (optional)
        try:
            self.redis = redis.Redis(
                host=redis_host,
                password=redis_password,
                decode_responses=True,
                socket_connect_timeout=2
            )
            self.redis.ping()
            logging.info("✓ Redis connected for real-time alerts")
        except Exception as e:
            logging.warning(f"Redis not available: {e}. Real-time alerts disabled.")
            self.redis = None
        
        self.engine = SimpleRuleEngine(self.db, self.redis)
        self.logger = logging.getLogger(__name__)
        self.logger.info("Detector Worker initialized")
    
    def run(self):
        """Main detection loop"""
        self.logger.info("Detector Worker started")
        
        while True:
            try:
                # Get enriched logs that haven't been checked
                logs = list(self.db.raw_logs.find({
                    "processed": True,
                    "enriched": True,
                    "rule_checked": {"$ne": True}
                }).limit(100))
                
                if not logs:
                    time.sleep(2)
                    continue
                
                for log in logs:
                    try:
                        self._check_log(log)
                    except Exception as e:
                        self.logger.error(f"Error checking log {log['_id']}: {e}")
                        # Mark as checked anyway
                        self.db.raw_logs.update_many(
                            {"_id": log["_id"]},
                            {"$set": {"rule_checked": True}}
                        )
            
            except Exception as e:
                self.logger.error(f"Detector worker error: {e}", exc_info=True)
                time.sleep(5)
    
    def _check_log(self, log):
        """Check log against all rules"""
        alert = self.engine.check_log(log)
        
        # Mark as checked
        self.db.raw_logs.update_many(
            {"_id": log["_id"]},
            {"$set": {"rule_checked": True}}
        )

if __name__ == "__main__":
    import time
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
    
    worker = DetectorWorker(MONGO_URI, REDIS_HOST, REDIS_PASSWORD if REDIS_PASSWORD else None)
    worker.run()
