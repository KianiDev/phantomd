#!/usr/bin/env sh
set -eu

# Fetches repository tarball, sets up virtualenv, installs deps, creates systemd service,
# and writes config/phantomd.conf interactively.

VERSION="1.0.6"
REPO_URL="https://codeload.github.com/KianiDev/phantomd/tar.gz/refs/tags/v$VERSION"
INSTALL_DIR="/opt/phantomd"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="phantomd"

echo "phantomd installer (version $VERSION, headless)"

# ensure running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must be run as root."
  exit 1
fi

mkdir -p "$INSTALL_DIR"
chown root:root "$INSTALL_DIR"

TMP_TAR="/tmp/phantomd.tar.gz"
echo "Fetching repository tarball..."
curl -fsSL "$REPO_URL" -o "$TMP_TAR"

echo "Extracting..."
tar xzf "$TMP_TAR" -C /tmp
EXTRACTED_DIR="/tmp/phantomd-$VERSION"

if [ ! -d "$EXTRACTED_DIR" ]; then
  echo "Unexpected archive layout. Please inspect /tmp"
  exit 1
fi

cp -a "$EXTRACTED_DIR"/* "$INSTALL_DIR/"
rm -f "$TMP_TAR"

# create venv
if [ ! -x "$(command -v python3)" ]; then
  echo "python3 not found. Please install python3."; exit 1
fi
python3 -m venv "$VENV_DIR"
. "$VENV_DIR/bin/activate"

echo "Upgrading pip and installing runtime dependencies from requirements.txt..."
# Best-effort install runtime dependencies only. Development/test deps are intentionally
# not included in requirements.txt and should be installed by developers in their envs.
pip install --upgrade pip
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  pip install -r "$INSTALL_DIR/requirements.txt" || true
else
  pip install --upgrade pip
  pip install httpx aiohttp dnspython requests cachetools aiosqlite cryptography prometheus_client uvloop || true
fi

# try to install some OS-level helper packages if apt is available
if command -v apt >/dev/null 2>&1; then
  echo "Installing minimal runtime packages via apt..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  # Install only minimal runtime helpers. Do not install heavy build toolchains here.
  apt-get install -y --no-install-recommends \
    python3-venv \
    python3-dev \
    ca-certificates \
    curl \
    iputils-arping \
    libcap2-bin || true
  # update CA certs if available
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates || true
  fi
  echo "Note: If you need to build binary wheels (cryptography, aioquic) on this host,"
  echo "install build-essential, libssl-dev, rustc and cargo separately before running pip."
fi

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
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/phantomd/
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
# DNS request file logging (per-day log files)
dns_logging_enabled = false
dns_log_retention_days = 7
dns_log_dir = /var/log/phantomd
dns_log_prefix = dns-log

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
read -r -p "Enable blocklists? (true/false) [false]: " INPUT; INPUT=${INPUT:-false}
sed -i "s/^enabled =.*$/enabled = $INPUT/" "$CONFIG_FILE"
if [ "$INPUT" = "true" ]; then
  read -r -p "Blocklist URLs (comma-separated) []: " INPUT2
  sed -i "s/^urls =.*$/urls = $INPUT2/" "$CONFIG_FILE"
  read -r -p "Block action (ZEROIP/NXDOMAIN/REFUSED) [NXDOMAIN]: " INPUT3; INPUT3=${INPUT3:-NXDOMAIN}
  sed -i "s/^action =.*$/action = $INPUT3/" "$CONFIG_FILE"
fi

# Skip interactive DHCP, logging and other prompts; defaults from template will be used.

echo "Installation complete. Start the service with: sudo systemctl start phantomd"

echo "You can view logs with: sudo journalctl -u phantomd -f"

exit 0
