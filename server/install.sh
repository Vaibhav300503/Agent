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

# Helper function to ensure a service is enabled and running
ensure_service_running() {
    local SERVICE_NAME=$1
    echo -n "Checking $SERVICE_NAME status... "
    
    if systemctl list-unit-files | grep -q "^$SERVICE_NAME.service"; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}Running${NC}"
        else
            echo -e "${YELLOW}Stopped. Attempting to start...${NC}"
            if sudo systemctl start "$SERVICE_NAME"; then
                echo -e "${GREEN}✓ Started $SERVICE_NAME${NC}"
            else
                echo -e "${RED}✗ Failed to start $SERVICE_NAME. Please check logs: journalctl -u $SERVICE_NAME${NC}"
            fi
        fi
        
        if ! systemctl is-enabled --quiet "$SERVICE_NAME"; then
            echo -e "${YELLOW}Service is disabled. Enabling...${NC}"
            sudo systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
        fi
    else
        echo -e "${RED}Not installed${NC}"
        return 1
    fi
}

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

# Check for AVX support (required for MongoDB 5.0+)
if ! grep -q "avx" /proc/cpuinfo; then
    echo -e "${YELLOW}WARNING: CPU does not support AVX instructions. MongoDB 5.0+ may fail to run.${NC}"
    echo -e "${YELLOW}Falling back to older MongoDB version check or manual installation might be required.${NC}"
fi

# Check if MongoDB is installed and running
if command -v mongod >/dev/null 2>&1; then
    INSTALL_MONGODB=false
    ensure_service_running "mongod" || INSTALL_MONGODB=true
else
    echo -e "${YELLOW}! MongoDB not found - will install${NC}"
    INSTALL_MONGODB=true
fi

# Check if Redis is installed and running
if command -v redis-server >/dev/null 2>&1; then
    INSTALL_REDIS=false
    ensure_service_running "redis" || INSTALL_REDIS=true
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
apt update

# Install MongoDB
if [ "$INSTALL_MONGODB" = true ]; then
    echo "Installing MongoDB..."
    
    # Ensure gnupg, wget, curl and lsb-release are installed
    apt update && apt install -y gnupg wget curl lsb-release
    
    # Detect OS specifics for MongoDB
    LSB_CODENAME=$(lsb_release -cs)
    MONGODB_VERSION_GPG="6.0"
    
    if [ "$OS" = "ubuntu" ]; then
        REPO_URL="https://repo.mongodb.org/apt/ubuntu"
        REPO_COMP="multiverse"
        if [ "$VER" = "24.04" ] || [ "$LSB_CODENAME" = "noble" ]; then
            MONGODB_VERSION_GPG="7.0"
            REPO_DIST="noble/mongodb-org/7.0"
            echo -e "${YELLOW}! Ubuntu 24.04 detected: Using MongoDB 7.0 for compatibility${NC}"
        else
            MONGODB_VERSION_GPG="6.0"
            REPO_DIST="${LSB_CODENAME}/mongodb-org/6.0"
        fi
    elif [ "$OS" = "debian" ]; then
        REPO_URL="https://repo.mongodb.org/apt/debian"
        REPO_COMP="main"
        if [ "$VER" = "12" ] || [ "$LSB_CODENAME" = "bookworm" ]; then
            MONGODB_VERSION_GPG="7.0"
            REPO_DIST="bookworm/mongodb-org/7.0"
            echo -e "${YELLOW}! Debian 12 detected: Using MongoDB 7.0 for compatibility${NC}"
        else
            MONGODB_VERSION_GPG="6.0"
            REPO_DIST="${LSB_CODENAME}/mongodb-org/6.0"
        fi
    else
        echo -e "${RED}ERROR: Unsupported OS for automated MongoDB install. Please install MongoDB manually.${NC}"
        exit 1
    fi

    # Import MongoDB GPG key (modern way)
    echo "Importing MongoDB ${MONGODB_VERSION_GPG} GPG key..."
    curl -fsSL https://www.mongodb.org/static/pgp/server-${MONGODB_VERSION_GPG}.asc | \
        gpg --dearmor --yes -o /usr/share/keyrings/mongodb-server.gpg
    
    # Add MongoDB repository
    echo "Adding MongoDB ${MONGODB_VERSION_GPG} repository..."
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server.gpg ] $REPO_URL $REPO_DIST $REPO_COMP" | \
        tee /etc/apt/sources.list.d/mongodb-org-${MONGODB_VERSION_GPG}.list > /dev/null
    
    apt update
    echo "Installing mongodb-org packet..."
    DEBIAN_FRONTEND=noninteractive apt install -y mongodb-org || {
        echo -e "${RED}ERROR: MongoDB installation failed.${NC}"
        echo "Try installing MongoDB manually following official instructions for $(lsb_release -d)"
        exit 1
    }
    
    # Start and enable MongoDB
    systemctl start mongod
    systemctl enable mongod >/dev/null 2>&1
    
    echo -e "${GREEN}✓ MongoDB ${MONGODB_VERSION_GPG} installed and started${NC}"
fi

# Install Redis
if [ "$INSTALL_REDIS" = true ]; then
    echo "Installing Redis..."
    DEBIAN_FRONTEND=noninteractive apt install -y redis-server
    
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
DEBIAN_FRONTEND=noninteractive apt install -y python3-pip python3-venv

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create installation directory
echo "Creating installation directory..."
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Copy server files
echo "Copying server files from $SCRIPT_DIR..."
cp -r "$SCRIPT_DIR/"* .

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
python-dotenv==1.0.0
EOF

pip install --upgrade pip
pip install -r requirements.txt

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
echo "Initializing optimized database schema..."
cat > init_db_temp.py <<EOF
from pymongo import MongoClient, ASCENDING, DESCENDING
import time

client = MongoClient("mongodb://soc_admin:$MONGO_PASSWORD@localhost:27017/$DB_NAME")
db = client.$DB_NAME

print("Dropping legacy collections if they exist...")
# We only do this for raw_logs to convert to time-series if it's a fresh install
# In a real migration we'd be more careful, but this is an installation script.
if "raw_logs" in db.list_collection_names():
    # If it's NOT a time-series collection, we might need to recreate it.
    # For simplicity in this script, we'll assume fresh setup or manual migration.
    pass

print("Creating optimized collections...")

# 1. raw_logs (Time-Series)
if "raw_logs" not in db.list_collection_names():
    db.create_collection("raw_logs", timeseries={
        "timeField": "timestamp",
        "metaField": "metadata",
        "granularity": "minutes"
    })
    # Set retention: 30 days
    db.command("collMod", "raw_logs", expireAfterSeconds=2592000)

# 2. Add indexes to raw_logs
db.raw_logs.create_index([("metadata.hostname", ASCENDING), ("timestamp", DESCENDING)])
db.raw_logs.create_index([("metadata.agent_id", ASCENDING)])
db.raw_logs.create_index([("processed", ASCENDING)])
db.raw_logs.create_index([("has_alert", ASCENDING)])

# 3. alerts (Standard)
db.alerts.create_index("alert_id", unique=True)
db.alerts.create_index([("severity", ASCENDING), ("status", ASCENDING), ("timestamp", DESCENDING)])
db.alerts.create_index([("timestamp", DESCENDING)])
db.alerts.create_index([("dedupe_hash", ASCENDING)])

# 4. agents (Standard)
db.agents.create_index("agent_id", unique=True)
db.agents.create_index([("status", ASCENDING), ("last_seen", DESCENDING)])

# 5. reputation (New)
db.reputation.create_index("ip", unique=True)
db.reputation.create_index("type")

# 6. rules
db.rules.create_index("rule_id", unique=True)
db.rules.create_index("enabled")

print("✓ Optimized Database Schema initialized")
EOF

python3 init_db_temp.py
rm init_db_temp.py

echo -e "${GREEN}✓ Database schema initialized${NC}"

# Seed detection rules
echo "Seeding SOC/OWASP detection rules..."
# Use the environment variable for MONGO_URI
export MONGO_URI="mongodb://soc_admin:$MONGO_PASSWORD@localhost:27017/$DB_NAME"
# Use the virtual environment Python to avoid library mismatches
./venv/bin/python3 seed_owasp_rules.py

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
RestartSec=5

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

# Final status check of core dependencies
echo ""
echo "Verifying core services before startup..."
ensure_service_running "mongod" || { echo -e "${RED}ERROR: MongoDB is required but not running.${NC}"; exit 1; }
ensure_service_running "redis" || { echo -e "${RED}ERROR: Redis is required but not running.${NC}"; exit 1; }

# Start the service
echo ""
echo "Starting SOC Platform..."
systemctl daemon-reload
systemctl enable soc-platform >/dev/null 2>&1
systemctl start soc-platform

# Wait for service to start
sleep 3

# Check service status using our helper function
ensure_service_running "soc-platform" || {
    echo -e "${RED}✗ SOC Platform failed to start${NC}"
    echo "Check logs: sudo journalctl -u soc-platform -n 100 --no-pager"
    exit 1
}

# Print summary
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "Installation Directory: $INSTALL_DIR"
echo "API Endpoint: http://$(hostname -I | awk '{print $1}'):5000"
echo "Health Check: http://$(hostname -I | awk '{print $1}'):5000/health"
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
echo "1. Configure agents to send logs to: http://YOUR_SERVER_IP:5000/api/v1/logs"
echo "2. Set API token in agent config: $API_TOKEN"
echo "3. Monitor alerts: MongoDB -> $DB_NAME.alerts collection"
echo ""
