#!/usr/bin/env sh
set -eu

# Fetches repository tarball, sets up virtualenv, installs deps, creates systemd service,
# and writes config/phantomd.conf interactively.
#
# Usage:
#   ./installer.sh            # fresh install (interactive)
#   ./installer.sh --update   # update an existing installation (non‑interactive, keeps config)

VERSION="1.5.0"
REPO_URL="https://codeload.github.com/KianiDev/phantomd/tar.gz/refs/tags/v$VERSION"
INSTALL_DIR="/opt/phantomd"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="phantomd"
CONFIG_FILE="$INSTALL_DIR/config/phantomd.conf"

# ---------- Argument parsing ----------
FRESH_INSTALL=true
if [ "${1:-}" = "--update" ]; then
    FRESH_INSTALL=false
    echo "Running in update mode – your configuration will not be changed."
fi

echo "phantomd installer (version $VERSION)"

# ensure running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must be run as root."
  exit 1
fi

# ---------- Fetch and extract ----------
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

# Copy over new files but **never** overwrite the existing config file.
# We use rsync style: copy all except config.
for item in "$EXTRACTED_DIR"/*; do
    base=$(basename "$item")
    if [ "$base" = "config" ]; then
        # Existing config directory is preserved entirely (we only add the template
        # if no config file exists – handled later).
        continue
    fi
    cp -a "$item" "$INSTALL_DIR/"
done
rm -f "$TMP_TAR"

# ---------- Python virtualenv ----------
if [ ! -x "$(command -v python3)" ]; then
  echo "python3 not found. Please install python3."; exit 1
fi
python3 -m venv "$VENV_DIR"
. "$VENV_DIR/bin/activate"

echo "Upgrading pip and installing runtime dependencies from requirements.txt..."
pip install --upgrade pip
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  pip install -r "$INSTALL_DIR/requirements.txt" || true
else
  pip install --upgrade pip
  pip install httpx aiohttp dnspython requests cachetools aiosqlite cryptography prometheus_client uvloop || true
fi

# ---------- OS helpers ----------
if command -v apt-get >/dev/null 2>&1; then
  echo "Installing minimal runtime packages via apt-get..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  apt-get install -y --no-install-recommends \
    python3-venv \
    python3-dev \
    ca-certificates \
    curl \
    iputils-arping \
    libcap2-bin || true
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates || true
  fi
  echo "Note: If you need to build binary wheels (cryptography, aioquic) on this host,"
  echo "install build-essential, libssl-dev, rustc and cargo separately before running pip."
fi

# ---------- Directories ----------
mkdir -p /var/log/phantomd
chown root:root /var/log/phantomd
mkdir -p /var/lib/phantomd
chown root:root /var/lib/phantomd

# ---------- Systemd service ----------
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

# ---------- Configuration ----------
mkdir -p "$(dirname "$CONFIG_FILE")"

if [ "$FRESH_INSTALL" = true ]; then
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

    # Utility function to safely escape a value for use in a sed substitution
    escape_sed() {
      printf '%s' "$1" | sed 's/[\/&]/\\&/g'
    }

    # Guide user through options
    echo "Configuring phantomd. Press ENTER to accept the shown default in []"
    read -r -p "Upstream DNS (ip or host) [1.1.1.1]: " INPUT; INPUT=${INPUT:-1.1.1.1}
    INPUT_ESC="$(escape_sed "$INPUT")"
    sed -i "s/^dns_server =.*$/dns_server = $INPUT_ESC/" "$CONFIG_FILE"

    read -r -p "Upstream protocol (udp/tcp/tls/https/quic) [udp]: " INPUT; INPUT=${INPUT:-udp}
    INPUT_ESC="$(escape_sed "$INPUT")"
    sed -i "s/^dns_protocol =.*$/dns_protocol = $INPUT_ESC/" "$CONFIG_FILE"

    read -r -p "Enable blocklists? (true/false) [false]: " INPUT; INPUT=${INPUT:-false}
    INPUT_ESC="$(escape_sed "$INPUT")"
    sed -i "s/^enabled =.*$/enabled = $INPUT_ESC/" "$CONFIG_FILE"
    if [ "$INPUT" = "true" ]; then
      read -r -p "Blocklist URLs (comma-separated) []: " INPUT2
      INPUT2_ESC="$(escape_sed "$INPUT2")"
      sed -i "s/^urls =.*$/urls = $INPUT2_ESC/" "$CONFIG_FILE"
      read -r -p "Block action (ZEROIP/NXDOMAIN/REFUSED) [NXDOMAIN]: " INPUT3; INPUT3=${INPUT3:-NXDOMAIN}
      INPUT3_ESC="$(escape_sed "$INPUT3")"
      sed -i "s/^action =.*$/action = $INPUT3_ESC/" "$CONFIG_FILE"
    fi
else
    echo "Update mode – existing configuration in $CONFIG_FILE was left untouched."
fi

echo ""
echo "Installation complete."
if [ "$FRESH_INSTALL" = true ]; then
    echo "Start the service with: sudo systemctl start phantomd"
else
    echo "Restart the service to apply changes: sudo systemctl restart phantomd"
fi
echo "You can view logs with: sudo journalctl -u phantomd -f"

exit 0