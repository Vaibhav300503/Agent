from fastapi import FastAPI, HTTPException, Depends, Header, Request
from pydantic import BaseModel, Field
from typing import List, Optional
from pymongo import MongoClient
from datetime import datetime
import logging
import os

# Configuration from environment
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/soc_platform")
AUTH_TOKEN = os.getenv("API_TOKEN", "Server@123")

# Initialize MongoDB with connection pooling
mongo_client = MongoClient(
    MONGO_URI,
    maxPoolSize=50,  # Maximum 50 connections
    minPoolSize=10,  # Keep 10 connections warm
    serverSelectionTimeoutMS=5000
)
db = mongo_client.get_database()

# Create FastAPI app
app = FastAPI(
    title="SOC Ingest API",
    description="Log ingestion endpoint for SOC agents",
    version="2.0.0"
)

# Rate limiting setup
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address, default_limits=["2000/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Request models
class LogEntry(BaseModel):
    timestamp: str
    hostname: str
    ip_address: str
    os_type: str
    log_source: str
    endpoint_name: Optional[str] = None
    event_id: Optional[int] = None
    severity: Optional[int] = None
    message: str
    raw_log: Optional[str] = None
    original_record_number: Optional[int] = None

    # Network fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    status: Optional[str] = None

    # Registry/Audit fields
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None
    operation: Optional[str] = None
    account_name: Optional[str] = None

class HeartbeatEntry(BaseModel):
    agent_id: str
    hostname: str
    ip_address: str
    os_type: str
    endpoint_name: Optional[str] = None
    agent_version: str
    buffer_size_bytes: int
    timestamp: str

# Authentication dependency
def verify_token(authorization: str = Header(None)):
    """Verify bearer token"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    
    token = authorization.split("Bearer ")[1]
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return token

# Endpoints
@app.post("/api/v1/logs")
@limiter.limit("1000/minute")  # Max 1000 logs per minute per IP
async def ingest_logs(request: Request, logs: List[LogEntry], token: str = Depends(verify_token)):
    """
    Ingest log batch from agents
    
    Stores logs in MongoDB with smart retention:
    - Logs without alerts are auto-deleted after 30 days
    - Logs with alerts are kept permanently
    """
    try:
        if not logs:
            raise HTTPException(status_code=400, detail="Empty log batch")
        
        # Prepare documents
        docs = []
        for log in logs:
            doc = {
                "timestamp": datetime.fromisoformat(log.timestamp.replace('Z', '+00:00')),
                "metadata": {
                    "agent_id": log.hostname,
                    "hostname": log.hostname,
                    "os_type": log.os_type,
                    "log_source": log.log_source,
                    "endpoint_name": log.endpoint_name or log.hostname
                },
                "ip_address": log.ip_address,
                "raw_data": log.dict(),
                "processed": False,
                "has_alert": False,
                "created_at": datetime.utcnow()
            }
            docs.append(doc)
        
        # Insert to MongoDB
        result = db.raw_logs.insert_many(docs)
        
        logging.info(f"Ingested {len(docs)} logs from {logs[0].hostname}")
        
        return {
            "status": "ok",
            "ingested": len(docs),
            "message": f"Successfully ingested {len(docs)} logs"
        }
    
    except Exception as e:
        logging.error(f"Ingest error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/api/v1/heartbeat")
async def receive_heartbeat(heartbeat: HeartbeatEntry, token: str = Depends(verify_token)):
    """
    Receive agent heartbeat and update agent status
    
    Updates agent record in MongoDB with latest status
    """
    try:
        # Update or create agent record
        db.agents.update_one(
            {"agent_id": heartbeat.agent_id},
            {
                "$set": {
                    "hostname": heartbeat.hostname,
                    "ip_address": heartbeat.ip_address,
                    "os_type": heartbeat.os_type,
                    "endpoint_name": heartbeat.endpoint_name or heartbeat.hostname,
                    "agent_version": heartbeat.agent_version,
                    "status": "active",
                    "last_seen": datetime.utcnow(),
                    "stats": {
                        "buffer_size_bytes": heartbeat.buffer_size_bytes
                    }
                },
                "$setOnInsert": {
                    "first_registered": datetime.utcnow(),
                    "labels": []
                }
            },
            upsert=True
        )
        
        return {"status": "ok", "message": "Heartbeat received"}
    
    except Exception as e:
        logging.error(f"Heartbeat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check MongoDB connection
        db.command('ping')
        
        return {
            "status": "healthy",
            "service": "soc-ingest-api",
            "mongodb": "connected"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "service": "soc-ingest-api",
            "error": str(e)
        }

@app.get("/stats")
async def get_stats():
    """Get platform statistics (no auth required for monitoring)"""
    try:
        stats = {
            "agents": {
                "total": db.agents.count_documents({}),
                "active": db.agents.count_documents({"status": "active"})
            },
            "logs": {
                "total": db.raw_logs.count_documents({}),
                "processed": db.raw_logs.count_documents({"processed": True}),
                "pending": db.raw_logs.count_documents({"processed": False})
            },
            "alerts": {
                "total": db.alerts.count_documents({}),
                "new": db.alerts.count_documents({"status": "new"}),
                "high": db.alerts.count_documents({"severity": "high"}),
                "critical": db.alerts.count_documents({"severity": "critical"})
            }
        }
        return stats
    except Exception as e:
        logging.error(f"Stats error: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
