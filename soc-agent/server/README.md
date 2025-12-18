# SOC Platform Server - README

## Overview

Complete SOC (Security Operations Center) platform that replaces Wazuh Agent + Manager with custom components integrated with TheHive and Cortex.

## Features

✅ **Log Collection**: Windows Event Logs + Linux syslog  
✅ **Parsing**: Automatic field extraction from logs  
✅ **Enrichment**: GeoIP lookups with caching  
✅ **Detection**: Rule-based threat detection with deduplication  
✅ **Alerting**: MongoDB storage + Redis pub/sub for real-time  
✅ **TheHive Integration**: Auto-create cases from high/critical alerts  
✅ **Smart Retention**: Auto-delete logs without alerts after 30 days  

## Architecture

```
Agent → Ingest API → MongoDB (raw_logs)
                         ↓
                    Parser Worker
                         ↓
                    Enricher Worker (GeoIP)
                         ↓
                    Detector Worker (Rules)
                         ↓
                    Alerts → TheHive
                         ↓
                    Redis Pub/Sub (Real-time)
```

## Quick Start

###Installation

See **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** for complete instructions.

**TL;DR**:
```bash
# Copy server folder to your Linux server
scp -r server/ root@your-server:/tmp/soc-server

# SSH to server
ssh root@your-server

# Run automated installer
cd /tmp/soc-server
sudo ./install.sh

# Follow prompts for configuration
```

### What the Installer Does

1. Installs MongoDB 6.0
2. Installs Redis
3. Downloads MaxMind GeoIP database
4. Sets up Python environment
5. Creates MongoDB schemas and indexes
6. Seeds detection rules
7. Creates systemd service
8. Starts the platform

### Configuration

All configuration is in `/opt/soc-platform/.env`:

```bash
MONGO_URI=mongodb://soc_admin:PASSWORD@localhost:27017/soc_platform
REDIS_HOST=localhost
REDIS_PASSWORD=your-redis-password
API_TOKEN=Server@123  # Change this!
THEHIVE_URL=http://thehive.local:9000
THEHIVE_API_KEY=your-thehive-key
GEOIP_DB=/opt/geoip/GeoLite2-City.mmdb
```

## Project Structure

```
server/
├── install.sh                 # Automated installer
├── main.py                    # Main server (starts all workers)
├── DEPLOYMENT_GUIDE.md        # Complete deployment guide
├── README.md                  # This file
│
├── api/
│   ├── __init__.py
│   └── ingest.py              # FastAPI ingest endpoint
│
├── parsers/
│   └── __init__.py            # Windows/Linux log parsers
│
└── workers/
    ├── __init__.py
    ├── parser_worker.py       # Parses raw logs
    ├── enricher_worker.py     # GeoIP enrichment
    ├── detector_worker.py     # Rule-based detection
    └── thehive_worker.py      # TheHive integration
```

## Management Commands

```bash
# Start/Stop/Restart
sudo systemctl start soc-platform
sudo systemctl stop soc-platform
sudo systemctl restart soc-platform

# View status
sudo systemctl status soc-platform

# View logs
sudo journalctl -u soc-platform -f
tail -f /var/log/soc-platform.log

# MongoDB access
mongosh soc_platform -u soc_admin -p
```

## API Endpoints

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/api/v1/logs` | POST | Ingest log batch | Bearer token |
| `/api/v1/heartbeat` | POST | Agent heartbeat | Bearer token |
| `/health` | GET | Health check | None |
| `/stats` | GET | Platform statistics | None |

### Example: Send Logs

```bash
curl -X POST http://localhost:8080/api/v1/logs \
  -H "Authorization: Bearer Server@123" \
  -H "Content-Type: application/json" \
  -d '[{
    "timestamp": "2025-12-18T10:00:00Z",
    "hostname": "WEB-01",
    "ip_address": "10.0.1.50",
    "os_type": "Windows",
    "log_source": "windows_Security",
    "event_id": 4625,
    "severity": 3,
    "message": "Failed login from 192.168.1.100"
  }]'
```

## MongoDB Collections

| Collection | Purpose | TTL |
|------------|---------|-----|
| `raw_logs` | Unprocessed logs | 30 days (if no alert) |
| `alerts` | Detected threats | Permanent |
| `cases` | TheHive cases | Permanent |
| `agents` | Agent inventory | Permanent |
| `rules` | Detection rules | Permanent |

### Query Examples

```javascript
// Count logs by agent
db.raw_logs.aggregate([
  {$group: {_id: "$agent_id", count: {$sum: 1}}}
])

// Latest alerts
db.alerts.find().sort({timestamp: -1}).limit(10).pretty()

// High-severity alerts
db.alerts.find({severity: "high", status: "new"}).pretty()

// Active agents
db.agents.find({status: "active"}).pretty()
```

## Detection Rules

Rules are stored in MongoDB `rules` collection.

### Example Rule: Brute Force Detection

```javascript
{
  "rule_id": "WIN-AUTH-001",
  "name": "Multiple Failed Logon Attempts",
  "description": "Detected 5+ failed logins within 5 minutes",
  "severity": "high",
  "enabled": true,
  "conditions": {
    "event_code": 4625,
    "outcome": "failure",
    "threshold": 5,
    "timeframe": "5m"
  },
  "mitre_technique": ["T1110.001"]
}
```

### Adding a New Rule

```bash
mongosh soc_platform -u soc_admin -p

> db.rules.insert({
  rule_id: "CUSTOM-001",
  name: "My Custom Rule",
  severity: "medium",
  enabled: true,
  conditions: {event_code: 4688}  // Process creation
})
```

## Real-Time Alerts (Redis Pub/Sub)

Subscribe to real-time critical/high alerts:

```python
import redis
r = redis.Redis(host='localhost', password='your-password', decode_responses=True)
pubsub = r.pubsub()
pubsub.subscribe('soc:alerts:realtime')

for message in pubsub.listen():
    if message['type'] == 'message':
        print(f"🚨 ALERT: {message['data']}")
```

## Troubleshooting

### No Logs Coming In

1. Check agent configuration (server URL, API token)
2. Check firewall: `sudo ufw allow 8080/tcp`
3. Verify API is running: `curl http://localhost:8080/health`
4. Check agent logs for connection errors

### No Alerts Generated

1. Check if logs are processed: `db.raw_logs.find({processed: true}).count()`
2. Check if rules exist: `db.rules.find({enabled: true}).count()`
3. View detector logs: `sudo journalctl -u soc-platform -f | grep Detector`
4. Manually trigger: Send a 4625 event 5 times quickly

### Service Won't Start

```bash
# Check logs
sudo journalctl -u soc-platform -n 50 --no-pager

# Verify MongoDB is running
sudo systemctl status mongod

# Verify Redis is running
sudo systemctl status redis

# Check permissions
ls -la /opt/soc-platform
```

## Performance Tuning

### For 100 Agents

Default configuration is sufficient.

### For 200-300 Agents

```bash
# Increase MongoDB cache size
sudo nano /etc/mongod.conf

# Add under storage.wiredTiger:
storage:
  wiredTiger:
    engineConfig:
      cacheSizeGB: 2

sudo systemctl restart mongod
```

### For >300 Agents

Upgrade to full architecture with RabbitMQ (see `architecture.md`).

## Backup

Automated daily backup (installed via cron):

```bash
# Manual backup
mongodump --uri="mongodb://soc_admin:PASSWORD@localhost:27017/soc_platform" --out=/backup/mongodb/$(date +%Y%m%d)

# Compress
tar -czf /backup/mongodb-$(date +%Y%m%d).tar.gz /backup/mongodb/$(date +%Y%m%d)

# Restore
mongorestore --uri="mongodb://soc_admin:PASSWORD@localhost:27017/soc_platform" /backup/mongodb/20231218/soc_platform
```

## Security

1. **Change default API token** in `.env`
2. **Enable TLS** for production (use Let's Encrypt)
3. **Restrict port 8080** to known agent IPs only
4. **Use strong MongoDB/Redis passwords**
5. **Enable MongoDB authentication**
6. **Regular backups** to external location

## Resource Requirements

| Agents | RAM | Disk (30 days) | CPU |
|--------|-----|----------------|-----|
| 50 | 4GB | 10GB | 2 vCPU |
| 100 | 4GB | 20GB | 2 vCPU |
| 200 | 6GB | 40GB | 4 vCPU |
| 300 | 8GB | 60GB | 4 vCPU |

## Documentation

- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Complete deployment guide
- **[architecture_simplified.md](../brain/...)** - Architecture overview
- **[implementation_plan_simplified.md](../brain/...)** - Implementation details
- **[mongodb_schema.md](../brain/...)** - Database schema

## Support

Check logs first:
```bash
sudo journalctl -u soc-platform -f
tail -f /var/log/soc-platform.log
```

Query MongoDB:
```bash
mongosh soc_platform -u soc_admin -p
> db.raw_logs.count()
> db.alerts.count()
```

## License

Proprietary - Internal SOC Use Only

---

**Ready to deploy? Run `./install.sh` and follow the prompts!**
