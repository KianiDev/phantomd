#!/usr/bin/env sh
set -eu

# phantomd installer (headless interactive)
# Fetches repository tarball, sets up virtualenv, installs deps, creates systemd service,
# and writes config/phantomd.conf interactively.

REPO_URL="https://codeload.github.com/KianiDev/phantomd/tar.gz/master"
INSTALL_DIR="/opt/phantomd"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="phantomd"

echo "phantomd installer (headless)"

# ensure running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must be run as root (it will create /opt/phantomd and a systemd service)."
  echo "Please run with sudo."
  exit 1
fi

# create install dir
mkdir -p "$INSTALL_DIR"
chown root:root "$INSTALL_DIR"

echo "Fetching repository tarball..."
TMP_TAR="/tmp/phantomd.tar.gz"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$REPO_URL" -o "$TMP_TAR"
else
  echo "curl not found. Please install curl and re-run."
  exit 1
fi

echo "Extracting..."
tar xzf "$TMP_TAR" -C /tmp
# extracted dir will be /tmp/phantomd-master
if [ ! -d /tmp/phantomd-master ]; then
  echo "Unexpected archive layout. Please inspect /tmp"
  exit 1
fi

# copy files
cp -a /tmp/phantomd-master/* "$INSTALL_DIR/"
rm -f "$TMP_TAR"

# create venv
if [ ! -x "$(command -v python3)" ]; then
  echo "python3 not found. Please install python3."; exit 1
fi
python3 -m venv "$VENV_DIR"
. "$VENV_DIR/bin/activate"

echo "Upgrading pip and installing python dependencies..."
# Best-effort install dependencies
pip install --upgrade pip
pip install httpx aiohttp dnspython requests cachetools || true

# create logs directory
mkdir -p /var/log/phantomd
chown root:root /var/log/phantomd
# create var lib directory for leases
mkdir -p /var/lib/phantomd
chown root:root /var/lib/phantomd

# Create systemd service
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=phantomd DNS server
After=network.target

[Service]
Type=simple
ExecStart=/opt/phantomd/venv/bin/python /opt/phantomd/main.py
Restart=on-failure
User=root
WorkingDirectory=/opt/phantomd
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" || true

# Interactive config generation (headless prompts)
CONFIG_FILE="$INSTALL_DIR/config/phantomd.conf"
if [ ! -f "$CONFIG_FILE" ]; then
  cat > "$CONFIG_FILE" <<'EOF'
[upstream]
dns_server = 1.1.1.1
dns_protocol = udp # Supported: udp, tcp, tls, https, quic
disable_ipv6 = false
# DNS hostname resolve cache (seconds)
dns_cache_ttl = 300
# Max entries in DNS hostname cache
dns_cache_max_size = 1024

[interface]
listen_ip = 0.0.0.0
listen_port = 53

[logging]
verbose = false
# DNS server to use for resolving upstream hostnames (for HTTPS, TLS, QUIC)
dns_resolver_server = 1.1.1.1:53

[blocklists]
enabled = false
urls = 
interval_seconds = 86400
action = NXDOMAIN

[dhcp]
enabled = false
subnet = 192.168.1.0
netmask = 255.255.255.0
start_ip = 192.168.1.100
end_ip = 192.168.1.200
lease_ttl = 86400
static_leases = 
# Path to lease DB file
dhcp_lease_db = /var/lib/phantomd/dhcp_leases.json
EOF
fi

echo "Configuration template written to $CONFIG_FILE"

# Guide user through options
echo "Configuring phantomd. Press ENTER to accept the shown default in []"
read -r -p "Upstream DNS (ip or host) [1.1.1.1]: " INPUT; INPUT=${INPUT:-1.1.1.1}
sed -i "s/^dns_server =.*$/dns_server = $INPUT/" "$CONFIG_FILE"
read -r -p "Upstream protocol (udp/tcp/tls/https/quic) [udp]: " INPUT; INPUT=${INPUT:-udp}
sed -i "s/^dns_protocol =.*$/dns_protocol = $INPUT/" "$CONFIG_FILE"
read -r -p "Disable IPv6 resolution? (true/false) [false]: " INPUT; INPUT=${INPUT:-false}
sed -i "s/^disable_ipv6 =.*$/disable_ipv6 = $INPUT/" "$CONFIG_FILE"
read -r -p "Listen IP [0.0.0.0]: " INPUT; INPUT=${INPUT:-0.0.0.0}
sed -i "s/^listen_ip =.*$/listen_ip = $INPUT/" "$CONFIG_FILE"
read -r -p "Listen port [53]: " INPUT; INPUT=${INPUT:-53}
sed -i "s/^listen_port =.*$/listen_port = $INPUT/" "$CONFIG_FILE"
read -r -p "Verbose logging? (true/false) [false]: " INPUT; INPUT=${INPUT:-false}
sed -i "s/^verbose =.*$/verbose = $INPUT/" "$CONFIG_FILE"
read -r -p "DNS resolver server for upstream hostname resolution (ip:port) [1.1.1.1:53]: " INPUT; INPUT=${INPUT:-1.1.1.1:53}
sed -i "s/^dns_resolver_server =.*$/dns_resolver_server = $INPUT/" "$CONFIG_FILE"
read -r -p "DNS cache TTL seconds [300]: " INPUT; INPUT=${INPUT:-300}
sed -i "s/^dns_cache_ttl =.*$/dns_cache_ttl = $INPUT/" "$CONFIG_FILE"
read -r -p "DNS cache max size [1024]: " INPUT; INPUT=${INPUT:-1024}
sed -i "s/^dns_cache_max_size =.*$/dns_cache_max_size = $INPUT/" "$CONFIG_FILE"
read -r -p "Enable blocklists? (true/false) [false]: " INPUT; INPUT=${INPUT:-false}
sed -i "s/^enabled =.*$/enabled = $INPUT/" "$CONFIG_FILE"
if [ "$INPUT" = "true" ]; then
  read -r -p "Blocklist URLs (comma-separated) []: " INPUT2
  sed -i "s/^urls =.*$/urls = $INPUT2/" "$CONFIG_FILE"
  read -r -p "Block action (ZEROIP/NXDOMAIN/REFUSED) [NXDOMAIN]: " INPUT3; INPUT3=${INPUT3:-NXDOMAIN}
  sed -i "s/^action =.*$/action = $INPUT3/" "$CONFIG_FILE"
fi

# DHCP configuration prompts (confined to [dhcp] section)
read -r -p "Enable DHCP server? (true/false) [false]: " DHCPE; DHCPE=${DHCPE:-false}
sed -i "/^\[dhcp\]/,/^\[/{s/^enabled =.*$/enabled = $DHCPE/}" "$CONFIG_FILE"
if [ "$DHCPE" = "true" ]; then
  read -r -p "DHCP subnet (network address) [192.168.1.0]: " INPUT; INPUT=${INPUT:-192.168.1.0}
  sed -i "/^\[dhcp\]/,/^\[/{s/^subnet =.*$/subnet = $INPUT/}" "$CONFIG_FILE"
  read -r -p "DHCP netmask [255.255.255.0]: " INPUT; INPUT=${INPUT:-255.255.255.0}
  sed -i "/^\[dhcp\]/,/^\[/{s/^netmask =.*$/netmask = $INPUT/}" "$CONFIG_FILE"
  read -r -p "DHCP range start [192.168.1.100]: " INPUT; INPUT=${INPUT:-192.168.1.100}
  sed -i "/^\[dhcp\]/,/^\[/{s/^start_ip =.*$/start_ip = $INPUT/}" "$CONFIG_FILE"
  read -r -p "DHCP range end [192.168.1.200]: " INPUT; INPUT=${INPUT:-192.168.1.200}
  sed -i "/^\[dhcp\]/,/^\[/{s/^end_ip =.*$/end_ip = $INPUT/}" "$CONFIG_FILE"
  read -r -p "Lease TTL seconds [86400]: " INPUT; INPUT=${INPUT:-86400}
  sed -i "/^\[dhcp\]/,/^\[/{s/^lease_ttl =.*$/lease_ttl = $INPUT/}" "$CONFIG_FILE"
  read -r -p "Static leases (mac=ip,...) []: " INPUT; INPUT=${INPUT:-}
  sed -i "/^\[dhcp\]/,/^\[/{s/^static_leases =.*$/static_leases = $INPUT/}" "$CONFIG_FILE"
  read -r -p "Lease DB path [/var/lib/phantomd/dhcp_leases.json]: " INPUT; INPUT=${INPUT:-/var/lib/phantomd/dhcp_leases.json}
  sed -i "/^\[dhcp\]/,/^\[/{s%^dhcp_lease_db =.*$%dhcp_lease_db = $INPUT%}" "$CONFIG_FILE"
fi

echo "Installation complete. Start the service with: sudo systemctl start phantomd"

echo "You can view logs with: sudo journalctl -u phantomd -f"

exit 0
