#!/usr/bin/env python3
"""
Migration Script: Convert raw_logs from Time-Series to Standard Collection
This is required because the SOC Platform workers need to update documents (processed, enriched, rule_checked),
which is not supported on Time-Series collections in MongoDB.
"""
from pymongo import MongoClient
import os
import sys

def migrate_database():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
    
    print(f"Connecting to MongoDB: {mongo_uri}")
    client = MongoClient(mongo_uri)
    db = client.get_database()
    
    coll_name = "raw_logs"
    
    # 1. Check if collection is Time-Series
    coll_info = db.command("listCollections", filter={"name": coll_name})
    if not coll_info.get("cursor", {}).get("firstBatch"):
        print(f"Collection '{coll_name}' does not exist. No action needed.")
        return

    is_timeseries = "type" in coll_info["cursor"]["firstBatch"][0] and \
                    coll_info["cursor"]["firstBatch"][0]["type"] == "timeseries"
    
    if not is_timeseries:
        print(f"✓ Collection '{coll_name}' is already a standard collection. Migration already done.")
        return

    print(f"! Detected '{coll_name}' is a Time-Series collection. Starting migration...")

    # 2. Backup existing logs
    temp_coll_name = "raw_logs_temp_backup"
    print(f"Backing up logs to '{temp_coll_name}'...")
    if temp_coll_name in db.list_collection_names():
        db.drop_collection(temp_coll_name)
    
    # Use aggregation to copy data
    db.command("aggregate", coll_name, pipeline=[{"$out": temp_coll_name}], cursor={})
    
    # 3. Drop Time-Series collection
    print(f"Dropping Time-Series collection '{coll_name}'...")
    db.drop_collection(coll_name)
    
    # 4. Recreate as Standard Collection
    print(f"Recreating '{coll_name}' as a standard collection...")
    db.create_collection(coll_name)
    
    # 5. Restore data
    print("Restoring data...")
    db.command("aggregate", temp_coll_name, pipeline=[{"$out": coll_name}], cursor={})
    
    # 6. Re-apply indexes (crucial for performance)
    print("Re-applying indexes...")
    db[coll_name].create_index("timestamp")
    db[coll_name].create_index("timestamp", expireAfterSeconds=2592000) # 30-day TTL
    db[coll_name].create_index([("metadata.hostname", 1), ("timestamp", -1)])
    db[coll_name].create_index([("metadata.agent_id", 1)])
    db[coll_name].create_index([("processed", 1)])
    db[coll_name].create_index([("enriched", 1)])
    db[coll_name].create_index([("rule_checked", 1)])
    db[coll_name].create_index([("has_alert", 1)])
    
    # 7. Clean up
    # print("Cleaning up backup...")
    # db.drop_collection(temp_coll_name)
    
    print("\n" + "="*40)
    print("✓ MIGRATION SUCCESSFUL")
    print("="*40)
    print(f"Collection '{coll_name}' is now a standard collection.")
    print("Existing logs have been preserved.")
    print("Please restart your soc-platform service now.")

if __name__ == "__main__":
    migrate_database()
