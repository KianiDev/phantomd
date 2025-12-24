#!/usr/bin/env bash
# phantomd-ap-setup.sh
# Wi-Fi AP bootstrapper for phantomd
# - Detects Wi-Fi AP capabilities
# - Generates hostapd.conf dynamically (band / security / HT/VHT/HE/EHT)
# - Configures routing/NAT to an upstream internet interface
# - Integrates with systemd

set -euo pipefail

# ------------------------- helpers ------------------------- #
err() { echo "[!] $*" >&2; exit 1; }
log() { echo "[*] $*"; }
need() { command -v "$1" >/dev/null 2>&1 || err "Missing dependency: $1"; }

if [[ $EUID -ne 0 ]]; then err "Run as root"; fi

need ip
need iw
need awk
need sed
need grep
need systemctl

# --------------------- detect interfaces ------------------- #

wifi_ifaces=($(iw dev | awk '$1=="Interface"{print $2}'))
[[ ${#wifi_ifaces[@]} -eq 0 ]] && err "No Wi-Fi interfaces found"

log "Detected Wi-Fi interfaces: ${wifi_ifaces[*]}"

read -rp "Select Wi-Fi interface for AP [${wifi_ifaces[0]}]: " AP_IFACE
AP_IFACE=${AP_IFACE:-${wifi_ifaces[0]}}

# check AP mode support
iw list | grep -A20 "Supported interface modes" | grep -q "\<AP\>" \
  || err "Selected card does NOT support AP mode"

# ------------------- detect capabilities ------------------- #

IW_LIST=$(iw list)

HAS_24=1
HAS_5=0
HAS_6=0

grep -q "Band 2:" <<<"$IW_LIST" && HAS_5=1
# Band 3 = 6GHz (Wi-Fi 6E/7)
grep -q "Band 3:" <<<"$IW_LIST" && HAS_6=1

HAS_N=$(grep -q "HT Capabilities" <<<"$IW_LIST" && echo 1 || echo 0)
HAS_AC=$(grep -q "VHT Capabilities" <<<"$IW_LIST" && echo 1 || echo 0)
HAS_AX=$(grep -q "HE Capabilities" <<<"$IW_LIST" && echo 1 || echo 0)
HAS_BE=$(grep -q "EHT Capabilities" <<<"$IW_LIST" && echo 1 || echo 0)

log "Capabilities: 2.4GHz=$HAS_24 5GHz=$HAS_5 6GHz=$HAS_6 | N=$HAS_N AC=$HAS_AC AX=$HAS_AX BE=$HAS_BE"

# ---------------------- user options ----------------------- #

read -rp "AP SSID [phantomd]: " SSID
SSID=${SSID:-phantomd}

read -rsp "AP password (min 8 chars): " PASSPHRASE
echo
[[ ${#PASSPHRASE} -lt 8 ]] && err "Password too short"

log "Select band:"
log "1) 2.4 GHz"
[[ $HAS_5 -eq 1 ]] && log "2) 5 GHz"
[[ $HAS_6 -eq 1 ]] && log "3) 6 GHz"
read -rp "Choice [1]: " BAND
BAND=${BAND:-1}

# ------------------- upstream internet --------------------- #

UPLINKS=($(ip -o link show | awk -F': ' '{print $2}' | grep -v "$AP_IFACE"))
[[ ${#UPLINKS[@]} -eq 0 ]] && err "No uplink interfaces detected"

log "Detected possible uplinks: ${UPLINKS[*]}"
read -rp "Select uplink interface [${UPLINKS[0]}]: " UPLINK
UPLINK=${UPLINK:-${UPLINKS[0]}}

# ------------------- generate hostapd ---------------------- #

HOSTAPD_DIR=/etc/phantomd
HOSTAPD_CONF=$HOSTAPD_DIR/hostapd.conf
mkdir -p "$HOSTAPD_DIR"

{
  echo "interface=$AP_IFACE"
  echo "driver=nl80211"
  echo "ssid=$SSID"

  case "$BAND" in
    1)
      echo "hw_mode=g"
      echo "channel=6"
      ;;
    2)
      echo "hw_mode=a"
      echo "channel=36"
      ;;
    3)
      echo "hw_mode=a"
      echo "channel=5"
      echo "ieee80211ax=1"
      echo "ieee80211w=2"
      ;;
  esac

  [[ $HAS_N -eq 1 ]] && echo "ieee80211n=1"
  [[ $HAS_AC -eq 1 ]] && echo "ieee80211ac=1"
  [[ $HAS_AX -eq 1 ]] && echo "ieee80211ax=1"
  [[ $HAS_BE -eq 1 ]] && echo "ieee80211be=1"

  echo "wpa=2"
  echo "wpa_passphrase=$PASSPHRASE"
  echo "wpa_key_mgmt=WPA-PSK SAE"
  echo "rsn_pairwise=CCMP"
} > "$HOSTAPD_CONF"

log "Generated hostapd config at $HOSTAPD_CONF"

# ------------------- networking setup ---------------------- #

ip addr flush dev "$AP_IFACE" || true
ip addr add 192.168.50.1/24 dev "$AP_IFACE"
ip link set "$AP_IFACE" up

sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$UPLINK" -j MASQUERADE

iptables -C FORWARD -i "$AP_IFACE" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$AP_IFACE" -j ACCEPT

iptables -C FORWARD -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Offer to hijack DNS requests from clients and redirect them to local phantomd
# This helps catch clients that try to bypass the AP's DNS by sending queries
# directly to external resolvers. We only add rules if the user confirms and
# we check for existing rules to avoid duplicates.
read -rp "Redirect DNS (UDP/TCP port 53) from clients on $AP_IFACE to local phantomd? [y/N]: " HJ
HJ=${HJ:-N}
if [[ "$HJ" =~ ^[Yy] ]]; then
  # UDP
  if ! iptables -t nat -C PREROUTING -i "$AP_IFACE" -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    iptables -t nat -A PREROUTING -i "$AP_IFACE" -p udp --dport 53 -j REDIRECT --to-port 53
    log "Added iptables PREROUTING udp redirect on $AP_IFACE"
  else
    log "iptables udp redirect already present on $AP_IFACE"
  fi

  # TCP
  if ! iptables -t nat -C PREROUTING -i "$AP_IFACE" -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp --dport 53 -j REDIRECT --to-port 53
    log "Added iptables PREROUTING tcp redirect on $AP_IFACE"
  else
    log "iptables tcp redirect already present on $AP_IFACE"
  fi
fi

# ------------------- systemd services ---------------------- #

AP_SERVICE=/etc/systemd/system/phantomd-ap.service

cat > "$AP_SERVICE" <<EOF
[Unit]
Description=phantomd Wi-Fi Access Point
After=network.target
Before=phantomd.service

[Service]
Type=simple
ExecStart=/usr/sbin/hostapd $HOSTAPD_CONF
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phantomd-ap.service

log "AP setup complete"
log "Uplink: $UPLINK"
log "AP interface: $AP_IFACE"
log "SSID: $SSID"
log "You can now start phantomd + phantomd-ap.service"
