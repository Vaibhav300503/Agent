# SOC Platform - Deployment Guide

## 🚀 Quick Start - Server Installation

This guide will help you deploy the SOC Platform server on a Linux machine.

### Prerequisites
- Ubuntu 20.04+ or CentOS 8+ 
- Root or sudo access
- 4GB RAM minimum, 8GB recommended
- 50GB disk space
- Public IP or reachable hostname

---

## Step 1: Copy Server Files to Your Server

```bash
# On your local machine, package the server folder
cd /path/to/soc-agent
tar -czf soc-server.tar.gz server/

# Copy to your server
scp soc-server.tar.gz root@YOUR_SERVER_IP:/tmp/
```

---

## Step 2: Run the Automated Installer

**On your server**, run these commands:

```bash
# Extract files
cd /tmp
tar -xzf soc-server.tar.gz

# Make installer executable
chmod +x server/install.sh

# Run installer (as root)
sudo ./server/install.sh
```

The installer will:
1. ✓ Detect your OS
2. ✓ Check for MongoDB and Redis (install if missing)
3. ✓ Ask you for configuration (passwords, API tokens, etc.)
4. ✓ Set up MongoDB database with proper indexes
5. ✓ Install Python dependencies
6. ✓ Download GeoIP database
7. ✓ Create systemd service
8. ✓ Start the SOC platform

### Interactive Configuration Prompts

The installer will ask you for:

```
1. Installation directory [/opt/soc-platform]
   → Press Enter for default or type your path

2. MongoDB database name [soc_platform]
   → Press Enter for default

3. MongoDB admin password
   → Type a strong password (won't be visible)

4. Redis password
   → Type a strong password

5. API authentication token [Server@123]
   → Change this for production!

6. TheHive URL (optional)
   → Leave blank if not using TheHive
   → Example: http://thehive.local:9000

7. TheHive API key (if URL provided)
   → Your TheHive API key
```

---

## Step 3: Verify Installation

After installation completes:

```bash
# Check service status
sudo systemctl status soc-platform

# Should show: Active (running)
```

Test the API:

```bash
# Health check
curl http://localhost:8080/health

# Should return: {"status":"healthy","service":"soc-ingest-api","mongodb":"connected"}

# Stats endpoint
curl http://localhost:8080/stats

# Should show agent, log, and alert counts
```

---

## Step 4: Configure Your Agents

On each endpoint (Windows/Linux), update the agent config:

**File**: `config/agent_config.yaml`

```yaml
server:
  url: "http://YOUR_SERVER_IP:8080/api/v1/logs"
  api_token: "YOUR_API_TOKEN"  # Match what you entered during install
  verify_ssl: false  # Set true if using HTTPS
```

Then restart the agent:

**Windows**:
```powershell
Restart-Service SocAgent
```

**Linux**:
```bash
sudo systemctl restart soc-agent
```

---

## Managing the SOC Platform

### Service Commands

```bash
# Start the platform
sudo systemctl start soc-platform

# Stop the platform
sudo systemctl stop soc-platform

# Restart the platform
sudo systemctl restart soc-platform

# View status
sudo systemctl status soc-platform

# View live logs
sudo journalctl -u soc-platform -f

# View specific log file
tail -f /var/log/soc-platform.log
```

### View Alerts in MongoDB

```bash
# Connect to MongoDB
mongosh soc_platform -u soc_admin -p

# List all alerts
db.alerts.find().pretty()

# Count alerts by severity
db.alerts.aggregate([
  {$group: {_id: "$severity", count: {$sum: 1}}}
])

# Get latest 10 high-severity alerts
db.alerts.find({severity: "high"}).sort({timestamp: -1}).limit(10).pretty()

# Check active agents
db.agents.find({status: "active"}).pretty()

# View recent logs
db.raw_logs.find().sort({timestamp: -1}).limit(10).pretty()
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs for errors
sudo journalctl -u soc-platform -n 100 --no-pager

# Common issues:
# 1. MongoDB not running
sudo systemctl status mongod
sudo systemctl start mongod

# 2. Redis not running
sudo systemctl status redis
sudo systemctl start redis

# 3. Permission issues
ls -la /opt/soc-platform
sudo chown -R root:root /opt/soc-platform
```

### No Alerts Being Generated

```bash
# Check if logs are being ingested
mongo soc_platform -u soc_admin -p
> db.raw_logs.count()

# Check if logs are being parsed
> db.raw_logs.find({processed: true}).count()

# Check if logs are being enriched
> db.raw_logs.find({enriched: true}).count()

# Check if detection rules exist
> db.rules.find({enabled: true}).pretty()

# View worker logs
sudo journalctl -u soc-platform -f | grep -E "Parser|Enricher|Detector"
```

### Agents Can't Connect

```bash
# Check firewall
sudo ufw status
sudo ufw allow 8080/tcp

# Check if API is listening
sudo netstat -tlnp | grep 8080

# Test from agent machine
curl http://SERVER_IP:8080/health
```

### MongoDB Issues

```bash
# Check MongoDB status
sudo systemctl status mongod

# View MongoDB logs
sudo tail -f /var/log/mongodb/mongod.log

# Restart MongoDB
sudo systemctl restart mongod

# Verify authentication works
mongosh soc_platform -u soc_admin -p
```

---

## Performance Monitoring

### Check Resource Usage

```bash
# CPU and Memory
top
htop

# Disk usage
df -h
du -sh /var/lib/mongodb
du -sh /opt/soc-platform

# MongoDB stats
mongosh soc_platform -u soc_admin -p --eval "db.stats()"

# Check log processing rate
sudo journalctl -u soc-platform --since "1 hour ago" | grep "Ingested.*logs"
```

### MongoDB Performance

```bash
# Check slow queries
mongosh soc_platform -u soc_admin -p
> db.setProfilingLevel(1, {slowms: 100})
> db.system.profile.find().sort({ts: -1}).limit(5).pretty()

# Check index usage
> db.raw_logs.stats()
> db.alerts.stats()
```

---

## Backup & Recovery

### Backup MongoDB

```bash
# Create backup directory
sudo mkdir -p /backup/mongodb

# Backup with authentication
mongodump --uri="mongodb://soc_admin:PASSWORD@localhost:27017/soc_platform" --out=/backup/mongodb/$(date +%Y%m%d)

# Compress backup
tar -czf /backup/mongodb-$(date +%Y%m%d).tar.gz /backup/mongodb/$(date +%Y%m%d)
```

### Restore MongoDB

```bash
# Extract backup
tar -xzf /backup/mongodb-20231218.tar.gz -C /tmp/

# Restore
mongorestore --uri="mongodb://soc_admin:PASSWORD@localhost:27017/soc_platform" /tmp/20231218/soc_platform
```

### Automated Daily Backup

Create a cron job:

```bash
sudo crontab -e

# Add this line (backup at 2 AM daily)
0 2 * * * /usr/bin/mongodump --uri="mongodb://soc_admin:PASSWORD@localhost:27017/soc_platform" --out=/backup/mongodb/$(date +\%Y\%m\%d) && tar -czf /backup/mongodb-$(date +\%Y\%m\%d).tar.gz /backup/mongodb/$(date +\%Y\%m\%d) && find /backup -name "mongodb-*.tar.gz" -mtime +30 -delete
```

---

## Security Hardening

### 1. Enable TLS for Agents

```bash
# Install certbot (Let's Encrypt)
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d your-soc-server.com

# Update agent config to use HTTPS
# server.url: https://your-soc-server.com:8080/api/v1/logs
# server.verify_ssl: true
```

### 2. Restrict API Access

```bash
# Only allow agent IPs
sudo ufw allow from AGENT_IP to any port 8080

# Or use nginx as reverse proxy with IP whitelist
```

### 3. Change Default Passwords

```bash
# MongoDB password
mongosh
> use admin
> db.changeUserPassword("soc_admin", "NEW_STRONG_PASSWORD")

# Update /opt/soc-platform/.env with new password

# Redis password
sudo nano /etc/redis/redis.conf
# Change: requirepass NEW_STRONG_PASSWORD

# Update /opt/soc-platform/.env

# Restart services
sudo systemctl restart soc-platform
```

---

## Scaling Beyond 300 Agents

When you outgrow the single-server setup:

1. **Add RabbitMQ**: Decouple ingest from processing
2. **MongoDB Replica Set**: Add redundancy
3. **Separate Workers**: Run workers on different servers
4. **Load Balancer**: Distribute agent connections

See `architecture.md` for the full-scale architecture.

---

## Support & Documentation

- **Architecture**: See `architecture_simplified.md`
- **Implementation**: See `implementation_plan_simplified.md`
- **MongoDB Schema**: See `mongodb_schema.md`
- **Audit Report**: See `audit_report.md`

---

## Quick Reference

| Component | Location | Purpose |
|-----------|----------|---------|
| Main Server | `/opt/soc-platform/main.py` | Orchestrates all workers |
| Ingest API | `/opt/soc-platform/api/ingest.py` | Receives logs from agents |
| Parsers | `/opt/soc-platform/parsers/` | Windows/Linux log parsing |
| Workers | `/opt/soc-platform/workers/` | Parser, Enricher, Detector, TheHive |
| Configuration | `/opt/soc-platform/.env` | Environment variables |
| Logs | `/var/log/soc-platform.log` | Application logs |
| Service | `/etc/systemd/system/soc-platform.service` | Systemd service |
| MongoDB Data | `/var/lib/mongodb` | Database files |

---

## Next Steps

1. ✓ Server installed and running
2. → Configure agents to send logs
3. → Monitor `/var/log/soc-platform.log` for activity
4. → Check MongoDB for incoming logs: `db.raw_logs.count()`
5. → Wait for alerts: `db.alerts.find().pretty()`
6. → If using TheHive, verify cases are created
7. → Set up daily backups
8. → Configure your SOC dashboard to query MongoDB

**Your SOC platform is ready!** 🎉
