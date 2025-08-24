#!/bin/bash

# Universal Outline + Cloak Install Script
# Works on both fresh and existing installations

set -e

echo "🚀 Starting Universal Outline + Cloak Installation..."

# Set environment to avoid interactive prompts
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

# Update system
echo "📦 Updating system packages..."
sudo apt update

# Install required packages
sudo apt install -y curl wget ufw python3 jq

# Configure UFW firewall
echo "🔥 Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 8443/tcp
sudo ufw allow 8443/udp
sudo ufw allow 57531/tcp
sudo ufw allow 57531/udp
sudo ufw allow 24847/tcp

# Check if Outline is already installed
echo "🔍 Checking existing installations..."
OUTLINE_EXISTS=false
CLOAK_EXISTS=false

if sudo docker ps -a --format "{{.Names}}" | grep -q "shadowbox"; then
    echo "✅ Outline already installed"
    OUTLINE_EXISTS=true
else
    echo "❌ Outline not found"
fi

if sudo systemctl list-unit-files | grep -q "cloak.service"; then
    echo "✅ Cloak service exists"
    CLOAK_EXISTS=true
else
    echo "❌ Cloak not found"
fi

# Install or update Outline
if [ "$OUTLINE_EXISTS" = false ]; then
    echo "🔧 Installing Outline Server..."
    sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/Jigsaw-Code/outline-server/master/src/server_manager/install_scripts/install_server.sh)"
    echo "⏳ Waiting for Outline to initialize..."
    sleep 15
else
    echo "🔄 Outline already installed, ensuring containers are running..."
    sudo docker start shadowbox watchtower 2>/dev/null || true
    sleep 5
fi

# Clean up existing Cloak installation
if [ "$CLOAK_EXISTS" = true ]; then
    echo "🧹 Cleaning existing Cloak installation..."
    sudo systemctl stop cloak 2>/dev/null || true
    sudo systemctl disable cloak 2>/dev/null || true
    sudo rm -f /etc/systemd/system/cloak.service
    sudo rm -f /etc/cloak-server.json
fi

# Install Cloak
echo "🔐 Installing/Updating Cloak..."
if [ ! -f "/usr/local/bin/ck-server" ]; then
    wget -q https://github.com/cbeuw/Cloak/releases/download/v2.6.0/ck-server-linux-amd64-v2.6.0
    chmod +x ck-server-linux-amd64-v2.6.0
    sudo mv ck-server-linux-amd64-v2.6.0 /usr/local/bin/ck-server
else
    echo "✅ Cloak binary already exists"
fi

# Generate fresh Cloak keys
echo "🔑 Generating fresh Cloak keys..."
# Disable color output to avoid ANSI escape sequences
export NO_COLOR=1
CLOAK_KEY_OUTPUT=$(ck-server -key 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
PRIVATE_KEY=$(echo "$CLOAK_KEY_OUTPUT" | grep "PRIVATE key" | sed 's/.*: *//' | tr -d '\r\n\t ' | sed 's/\x1b\[[0-9;]*m//g')
PUBLIC_KEY=$(echo "$CLOAK_KEY_OUTPUT" | grep "PUBLIC key" | sed 's/.*: *//' | tr -d '\r\n\t ' | sed 's/\x1b\[[0-9;]*m//g')

UID_OUTPUT=$(ck-server -uid 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
ADMIN_UID=$(echo "$UID_OUTPUT" | grep "Your UID is:" | sed 's/.*: *//' | tr -d '\r\n\t ' | sed 's/\x1b\[[0-9;]*m//g')

# Validate keys
if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$ADMIN_UID" ]; then
    echo "❌ Error: Failed to generate valid keys"
    echo "Retrying key generation..."
    sleep 2
    
    # Retry once
    CLOAK_KEY_OUTPUT=$(ck-server -key 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
    PRIVATE_KEY=$(echo "$CLOAK_KEY_OUTPUT" | grep "PRIVATE key" | sed 's/.*: *//' | tr -d '\r\n\t ' | sed 's/\x1b\[[0-9;]*m//g')
    PUBLIC_KEY=$(echo "$CLOAK_KEY_OUTPUT" | grep "PUBLIC key" | sed 's/.*: *//' | tr -d '\r\n\t ' | sed 's/\x1b\[[0-9;]*m//g')
    
    UID_OUTPUT=$(ck-server -uid 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
    ADMIN_UID=$(echo "$UID_OUTPUT" | grep "Your UID is:" | sed 's/.*: *//' | tr -d '\r\n\t ' | sed 's/\x1b\[[0-9;]*m//g')
    
    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$ADMIN_UID" ]; then
        echo "❌ Critical Error: Cannot generate valid keys"
        exit 1
    fi
fi

echo "✅ Keys generated successfully"

# Detect Shadowsocks port dynamically
echo "🔍 Detecting Shadowsocks port..."
SS_PORT=""
for i in {1..30}; do
    # Check for common Shadowsocks ports
    for port in 57531 57226 8388; do
        if sudo ss -tulpn | grep -q ":$port "; then
            SS_PORT="$port"
            echo "✅ Found Shadowsocks on port $port"
            break 2
        fi
    done
    echo "Waiting for Shadowsocks... ($i/30)"
    sleep 2
done

if [ -z "$SS_PORT" ]; then
    echo "⚠️ Warning: Shadowsocks port not detected, using default 57531"
    SS_PORT="57531"
fi

# Determine Cloak port (use 8443 to avoid conflicts with Outline management on 443)
CLOAK_PORT="8443"
echo "🔍 Using port $CLOAK_PORT for Cloak to avoid conflicts"

# Create clean Cloak configuration using jq to ensure proper JSON formatting
echo "⚙️ Creating Cloak configuration..."
jq -n \
  --arg ss_port "$SS_PORT" \
  --arg cloak_port "$CLOAK_PORT" \
  --arg admin_uid "$ADMIN_UID" \
  --arg private_key "$PRIVATE_KEY" \
  '{
    "ProxyBook": {
      "shadowsocks": ["tcp", ("127.0.0.1:" + $ss_port)]
    },
    "BindAddr": [(":" + $cloak_port)],
    "BypassUID": [$admin_uid],
    "RedirAddr": "www.bing.com:443",
    "PrivateKey": $private_key
  }' | sudo tee /etc/cloak-server.json > /dev/null

# Validate JSON configuration
echo "🔍 Validating JSON configuration..."
if jq empty /etc/cloak-server.json 2>/dev/null; then
    echo "✅ JSON configuration is valid"
else
    echo "⚠️ JSON validation failed, creating fallback config..."
    # Create fallback config without jq
    sudo tee /etc/cloak-server.json > /dev/null << EOF
{
  "ProxyBook": {
    "shadowsocks": ["tcp", "127.0.0.1:${SS_PORT}"]
  },
  "BindAddr": [":${CLOAK_PORT}"],
  "BypassUID": ["${ADMIN_UID}"],
  "RedirAddr": "www.bing.com:443",
  "PrivateKey": "${PRIVATE_KEY}"
}
EOF
    echo "✅ Fallback JSON configuration created"
fi

# Create Cloak systemd service
sudo tee /etc/systemd/system/cloak.service > /dev/null << 'EOF'
[Unit]
Description=Cloak Server
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ck-server -c /etc/cloak-server.json
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# Start Cloak service
echo "🚀 Starting Cloak service..."
sudo systemctl daemon-reload
sudo systemctl enable cloak
sudo systemctl restart cloak

# Wait for Cloak to start
sleep 5

# Get server IP
SERVER_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me)

# Find Outline API info
echo "🔍 Locating Outline configuration..."
OUTLINE_CONFIG=""
for path in "/opt/outline/access.txt" "/root/access.txt" "/home/ubuntu/access.txt"; do
    if sudo test -f "$path"; then
        OUTLINE_CONFIG="$path"
        break
    fi
done

if [ -n "$OUTLINE_CONFIG" ]; then
    API_INFO=$(sudo cat "$OUTLINE_CONFIG")
else
    API_INFO=$(sudo docker logs shadowbox 2>/dev/null | grep -E "(apiUrl|certSha256)" | tail -2 | tr '\n' ' ' || echo "Check docker logs: sudo docker logs shadowbox")
fi

# Get access key
echo "🔐 Getting access key information..."
if [[ "$API_INFO" =~ \"apiUrl\":\"([^\"]+)\" ]]; then
    API_URL="${BASH_REMATCH[1]}"
    ACCESS_KEYS=$(curl -k -s "$API_URL/access-keys" 2>/dev/null || echo "")
    
    if [[ "$ACCESS_KEYS" =~ \"password\":\"([^\"]+)\" ]]; then
        FIRST_PASSWORD="${BASH_REMATCH[1]}"
    else
        FIRST_PASSWORD="Check Outline Manager for password"
    fi
else
    FIRST_PASSWORD="Check Outline Manager for password"
fi

# Display results
echo ""
echo "🎉 Installation/Update Complete!"
echo "=================================="
echo ""
echo "🌐 SERVER IP: $SERVER_IP"
echo ""
echo "📋 OUTLINE MANAGER CONFIG:"
echo "$API_INFO"
echo ""
echo "🔐 OBFUSCATED CONNECTION (Port $CLOAK_PORT):"
echo "Server: $SERVER_IP:$CLOAK_PORT"
echo "Public Key: $PUBLIC_KEY"
echo "UID: $ADMIN_UID"
echo "Password: $FIRST_PASSWORD"
echo ""
echo "📱 SHADOWSOCKS ANDROID PLUGIN OPTIONS:"
echo "UID=$ADMIN_UID;PublicKey=$PUBLIC_KEY;ServerName=www.bing.com"
echo ""

# Comprehensive Status Testing
echo "🔍 RUNNING COMPREHENSIVE STATUS TESTS..."
echo "========================================="

FAILED_TESTS=0

# Test Docker Service
echo -n "🐳 Docker Service: "
if sudo systemctl is-active docker >/dev/null 2>&1; then
    echo "✅ RUNNING"
else
    echo "❌ FAILED"
    ((FAILED_TESTS++))
fi

# Test Docker Containers
echo -n "📦 Shadowbox Container: "
if sudo docker ps --format "{{.Names}}" | grep -q "shadowbox"; then
    echo "✅ RUNNING"
else
    echo "❌ FAILED"
    ((FAILED_TESTS++))
fi

echo -n "🔄 Watchtower Container: "
if sudo docker ps --format "{{.Names}}" | grep -q "watchtower"; then
    echo "✅ RUNNING"
else
    echo "⚠️ WARNING"
fi

# Test Cloak Service
echo -n "🔐 Cloak Service: "
if sudo systemctl is-active cloak >/dev/null 2>&1; then
    echo "✅ RUNNING"
else
    echo "❌ FAILED"
    ((FAILED_TESTS++))
    echo "Last 3 Cloak log entries:"
    sudo journalctl -u cloak --no-pager -n 3
fi

# Test Ports
echo -n "🌐 Port $CLOAK_PORT (Cloak): "
if sudo ss -tulpn | grep -q ":$CLOAK_PORT "; then
    echo "✅ LISTENING"
else
    echo "❌ NOT LISTENING"
    ((FAILED_TESTS++))
fi

echo -n "🌐 Port $SS_PORT (Outline): "
if sudo ss -tulpn | grep -q ":$SS_PORT "; then
    echo "✅ LISTENING"
else
    echo "❌ NOT LISTENING"
    ((FAILED_TESTS++))
fi

echo -n "🌐 Port 24847 (Management): "
if sudo ss -tulpn | grep -q ":24847 "; then
    echo "✅ LISTENING"
else
    echo "⚠️ WARNING"
fi

# Test Connectivity
echo -n "🔗 Cloak Connectivity: "
if timeout 5 bash -c "</dev/tcp/127.0.0.1/$CLOAK_PORT" >/dev/null 2>&1; then
    echo "✅ ACCESSIBLE"
else
    echo "❌ NOT ACCESSIBLE"
    ((FAILED_TESTS++))
fi

echo -n "🔗 Shadowsocks Connectivity: "
if timeout 5 bash -c "</dev/tcp/127.0.0.1/$SS_PORT" >/dev/null 2>&1; then
    echo "✅ ACCESSIBLE"
else
    echo "❌ NOT ACCESSIBLE"
    ((FAILED_TESTS++))
fi

# Overall Status
echo ""
echo "📊 OVERALL STATUS:"
echo "=================="

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 ALL SYSTEMS OPERATIONAL!"
    echo "✅ Your Outline + Cloak VPN is ready to use"
else
    echo "⚠️ $FAILED_TESTS ISSUES DETECTED"
    echo "❌ Check the failed tests above"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "sudo systemctl status cloak"
    echo "sudo journalctl -u cloak -f"
    echo "sudo docker logs shadowbox"
fi

echo ""
echo "⚠️ LIGHTSAIL FIREWALL REMINDER:"
echo "Add these rules in Lightsail console:"
echo "- Custom TCP $CLOAK_PORT (Cloak obfuscation)"
echo "- Custom TCP $SS_PORT (Shadowsocks backup)" 
echo "- Custom TCP 24847 (Management)"
echo ""
echo "💡 Save this information securely!"
echo "🔗 Your obfuscated VPN connection uses port $CLOAK_PORT"