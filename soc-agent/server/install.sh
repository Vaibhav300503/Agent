#!/bin/bash
#
# SOC Platform - Automated Server Installation
# This script will install and configure all required components
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "  SOC Platform Server Installation"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: Please run as root (sudo)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}ERROR: Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Detected OS: $OS $VER${NC}"

# Check prerequisites
echo ""
echo "Checking prerequisites..."

command -v python3 >/dev/null 2>&1 || { echo -e "${RED}✗ Python3 not found${NC}"; exit 1; }
echo -e "${GREEN}✓ Python3 found: $(python3 --version)${NC}"

# Check if MongoDB is installed
if command -v mongod >/dev/null 2>&1; then
    echo -e "${GREEN}✓ MongoDB already installed${NC}"
    INSTALL_MONGODB=false
else
    echo -e "${YELLOW}! MongoDB not found - will install${NC}"
    INSTALL_MONGODB=true
fi

# Check if Redis is installed
if command -v redis-server >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Redis already installed${NC}"
    INSTALL_REDIS=false
else
    echo -e "${YELLOW}! Redis not found - will install${NC}"
    INSTALL_REDIS=true
fi

# Interactive configuration
echo ""
echo "========================================"
echo "  Configuration"
echo "========================================"
echo ""

read -p "Enter installation directory [/opt/soc-platform]: " INSTALL_DIR
INSTALL_DIR=${INSTALL_DIR:-/opt/soc-platform}

read -p "Enter MongoDB database name [soc_platform]: " DB_NAME
DB_NAME=${DB_NAME:-soc_platform}

read -sp "Enter MongoDB admin password: " MONGO_PASSWORD
echo ""

read -sp "Enter Redis password: " REDIS_PASSWORD
echo ""

read -p "Enter API authentication token [Server@123]: " API_TOKEN
API_TOKEN=${API_TOKEN:-Server@123}

read -p "Enter TheHive URL (optional, e.g., http://thehive.local:9000): " THEHIVE_URL

if [ -n "$THEHIVE_URL" ]; then
    read -p "Enter TheHive API key: " THEHIVE_API_KEY
fi

echo ""
echo "========================================"
echo "  Installation Summary"
echo "========================================"
echo "Install Directory: $INSTALL_DIR"
echo "MongoDB Database: $DB_NAME"
echo "MongoDB User: soc_admin"
echo "TheHive Integration: ${THEHIVE_URL:-Disabled}"
echo ""
read -p "Proceed with installation? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Start installation
echo ""
echo "========================================"
echo "  Installing Components"
echo "========================================"
echo ""

# Update system
echo "Updating system packages..."
apt update -qq

# Install MongoDB
if [ "$INSTALL_MONGODB" = true ]; then
    echo "Installing MongoDB..."
    
    # Import MongoDB GPG key
    wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add - >/dev/null 2>&1
    
    # Add MongoDB repository
    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list >/dev/null
    
    apt update -qq
    apt install -y mongodb-org >/dev/null 2>&1
    
    # Start and enable MongoDB
    systemctl start mongod
    systemctl enable mongod >/dev/null 2>&1
    
    echo -e "${GREEN}✓ MongoDB installed and started${NC}"
fi

# Install Redis
if [ "$INSTALL_REDIS" = true ]; then
    echo "Installing Redis..."
    apt install -y redis-server >/dev/null 2>&1
    
    echo -e "${GREEN}✓ Redis installed${NC}"
fi

# Configure Redis password
echo "Configuring Redis..."

# Detect Redis config path
if [ -f /etc/redis/redis.conf ]; then
    REDIS_CONF="/etc/redis/redis.conf"
elif [ -f /etc/redis.conf ]; then
    REDIS_CONF="/etc/redis.conf"
else
    echo -e "${RED}ERROR: Redis config file not found${NC}"
    exit 1
fi

# Set password (handles both commented and uncommented lines)
sed -i "s/# requirepass .*/requirepass $REDIS_PASSWORD/" $REDIS_CONF
sed -i "s/^requirepass .*/requirepass $REDIS_PASSWORD/" $REDIS_CONF

systemctl restart redis
echo -e "${GREEN}✓ Redis configured at $REDIS_CONF${NC}"

# Install Python dependencies
echo "Installing Python packages..."
apt install -y python3-pip python3-venv >/dev/null 2>&1

# Create installation directory
echo "Creating installation directory..."
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Copy server files
echo "Copying server files..."
cp -r /tmp/soc-server/* .

# Create Python virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
echo "Installing Python dependencies..."
cat > requirements.txt <<EOF
fastapi==0.104.1
uvicorn[standard]==0.24.0
pymongo==4.6.0
redis==5.0.1
geoip2==4.7.0
requests==2.31.0
pydantic==2.5.0
python-multipart==0.0.6
slowapi==0.1.9
EOF

pip install -q --upgrade pip
pip install -q -r requirements.txt

echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Download MaxMind GeoIP database
echo "Downloading GeoIP database..."
mkdir -p /opt/geoip
if [ ! -f /opt/geoip/GeoLite2-City.mmdb ]; then
    wget -q https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb -O /opt/geoip/GeoLite2-City.mmdb
    echo -e "${GREEN}✓ GeoIP database downloaded${NC}"
else
    echo -e "${GREEN}✓ GeoIP database already exists${NC}"
fi

# Configure MongoDB
echo "Configuring MongoDB..."

# Wait for MongoDB to be ready
sleep 5

# Detect MongoDB shell command
if command -v mongosh >/dev/null 2>&1; then
    MONGO_CMD="mongosh"
elif command -v mongo >/dev/null 2>&1; then
    MONGO_CMD="mongo"
else
    echo -e "${RED}ERROR: MongoDB shell not found${NC}"
    exit 1
fi

echo "Using MongoDB shell: $MONGO_CMD"

# Create MongoDB user and database
$MONGO_CMD --quiet <<EOF
use $DB_NAME
db.createUser({
  user: "soc_admin",
  pwd: "$MONGO_PASSWORD",
  roles: [{role: "readWrite", db: "$DB_NAME"}]
})
EOF

echo -e "${GREEN}✓ MongoDB configured${NC}"

# Initialize MongoDB schema
echo "Initializing database schema..."
cat > init_db_temp.py <<EOF
from pymongo import MongoClient, ASCENDING, DESCENDING

client = MongoClient("mongodb://soc_admin:$MONGO_PASSWORD@localhost:27017/$DB_NAME")
db = client.$DB_NAME

print("Creating indexes...")

# raw_logs
db.raw_logs.create_index([("created_at", ASCENDING)], expireAfterSeconds=2592000, partialFilterExpression={"has_alert": False})
db.raw_logs.create_index([("processed", ASCENDING)])
db.raw_logs.create_index([("agent_id", ASCENDING), ("timestamp", DESCENDING)])

# alerts
db.alerts.create_index("alert_id", unique=True)
db.alerts.create_index([("severity", ASCENDING), ("status", ASCENDING), ("timestamp", DESCENDING)])
db.alerts.create_index([("timestamp", DESCENDING)])

# cases
db.cases.create_index("case_id", unique=True)
db.cases.create_index("thehive_case_id")

# agents
db.agents.create_index("agent_id", unique=True)
db.agents.create_index([("status", ASCENDING), ("last_seen", DESCENDING)])

# rules
db.rules.create_index("rule_id", unique=True)
db.rules.create_index("enabled")

print("✓ Database initialized")
EOF

python3 init_db_temp.py
rm init_db_temp.py

echo -e "${GREEN}✓ Database schema initialized${NC}"

# Seed detection rules
echo "Seeding detection rules..."
cat > seed_rules_temp.py <<EOF
from pymongo import MongoClient

client = MongoClient("mongodb://soc_admin:$MONGO_PASSWORD@localhost:27017/$DB_NAME")
db = client.$DB_NAME

rules = [
    {
        "rule_id": "WIN-AUTH-001",
        "name": "Multiple Failed Logon Attempts",
        "description": "Detected 5+ failed login attempts within 5 minutes",
        "severity": "high",
        "enabled": True,
        "conditions": {
            "event_code": 4625,
            "outcome": "failure",
            "threshold": 5,
            "timeframe": "5m"
        },
        "mitre_technique": ["T1110.001"]
    },
    {
        "rule_id": "WIN-AUTH-002",
        "name": "Successful Logon After Multiple Failures",
        "description": "Successful login after brute force attempt",
        "severity": "critical",
        "enabled": True,
        "conditions": {
            "event_code": 4624,
            "outcome": "success"
        },
        "mitre_technique": ["T1110"]
    }
]

for rule in rules:
    db.rules.update_one({"rule_id": rule["rule_id"]}, {"\\$set": rule}, upsert=True)

print(f"✓ Seeded {len(rules)} detection rules")
EOF

python3 seed_rules_temp.py
rm seed_rules_temp.py

echo -e "${GREEN}✓ Detection rules seeded${NC}"

# Create environment configuration
echo "Creating configuration file..."
cat > .env <<EOF
MONGO_URI=mongodb://soc_admin:$MONGO_PASSWORD@localhost:27017/$DB_NAME
REDIS_HOST=localhost
REDIS_PASSWORD=$REDIS_PASSWORD
API_TOKEN=$API_TOKEN
THEHIVE_URL=$THEHIVE_URL
THEHIVE_API_KEY=$THEHIVE_API_KEY
GEOIP_DB=/opt/geoip/GeoLite2-City.mmdb
EOF

chmod 600 .env
echo -e "${GREEN}✓ Configuration saved${NC}"

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/soc-platform.service <<EOF
[Unit]
Description=SOC Platform Server
After=network.target mongod.service redis.service
Requires=mongod.service redis.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/main.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/soc-platform.log
StandardError=append:/var/log/soc-platform-error.log

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}✓ Systemd service created${NC}"

# Create log rotation configuration
echo "Setting up log rotation..."
cat > /etc/logrotate.d/soc-platform <<'LOGROTATE_EOF'
/var/log/soc-platform.log /var/log/soc-platform-error.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload soc-platform >/dev/null 2>&1 || true
    endscript
}
LOGROTATE_EOF

echo -e "${GREEN}✓ Log rotation configured${NC}"

# Start the service
echo "Starting SOC Platform..."
systemctl enable soc-platform >/dev/null 2>&1
systemctl start soc-platform

# Wait for service to start
sleep 3

# Check service status
if systemctl is-active --quiet soc-platform; then
    echo -e "${GREEN}✓ SOC Platform started successfully${NC}"
else
    echo -e "${RED}✗ SOC Platform failed to start${NC}"
    echo "Check logs: journalctl -u soc-platform -n 50"
    exit 1
fi

# Print summary
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "Installation Directory: $INSTALL_DIR"
echo "API Endpoint: http://$(hostname -I | awk '{print $1}'):8080"
echo "Health Check: http://$(hostname -I | awk '{print $1}'):8080/health"
echo ""
echo "Service Management:"
echo "  Start:   sudo systemctl start soc-platform"
echo "  Stop:    sudo systemctl stop soc-platform"
echo "  Status:  sudo systemctl status soc-platform"
echo "  Logs:    sudo journalctl -u soc-platform -f"
echo ""
echo "Configuration: $INSTALL_DIR/.env"
echo "Log File: /var/log/soc-platform.log"
echo ""
echo -e "${GREEN}Ready to receive logs from agents!${NC}"
echo ""
echo "Next steps:"
echo "1. Configure agents to send logs to: http://YOUR_SERVER_IP:8080/api/v1/logs"
echo "2. Set API token in agent config: $API_TOKEN"
echo "3. Monitor alerts: MongoDB -> $DB_NAME.alerts collection"
echo ""
