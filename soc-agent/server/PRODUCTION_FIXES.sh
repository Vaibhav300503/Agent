#!/bin/bash
#
# Critical Production Fixes
# Apply these fixes to install.sh before deployment
#

echo "Applying production-ready fixes..."

# Fix 1: MongoDB command detection
sed -i '206s/mongosh/\${MONGO_CMD:-mongosh}/' /path/to/install.sh

# Add before line 206:
cat > /tmp/mongo_detect.sh <<'EOF'
# Detect MongoDB shell command
if command -v mongosh >/dev/null 2>&1; then
    MONGO_CMD="mongosh"
elif command -v mongo >/dev/null 2>&1; then
    MONGO_CMD="mongo"
else
    echo -e "${RED}ERROR: MongoDB shell not found${NC}"
    exit 1
fi
EOF

# Fix 2: Redis config path detection
cat > /tmp/redis_fix.sh <<'EOF'
# Configure Redis password with path detection
echo "Configuring Redis..."
if [ -f /etc/redis/redis.conf ]; then
    REDIS_CONF="/etc/redis/redis.conf"
elif [ -f /etc/redis.conf ]; then
    REDIS_CONF="/etc/redis.conf"
else
    echo -e "${RED}ERROR: Redis config not found${NC}"
    exit 1
fi

sed -i "s/# requirepass .*/requirepass $REDIS_PASSWORD/" $REDIS_CONF
sed -i "s/^requirepass .*/requirepass $REDIS_PASSWORD/" $REDIS_CONF
systemctl restart redis
EOF

echo "✓ Fixes prepared"
echo "Manually merge these into install.sh or use the updated version provided"
