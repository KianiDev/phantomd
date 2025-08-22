import asyncio
import socket
import struct
import time
import json
import os
import tempfile
from typing import Dict, Tuple, Optional

# Minimal DHCP server (IPv4 only). Supports DISCOVER -> OFFER and REQUEST -> ACK.
# Configurable pool, lease TTL, and static leases (mac->ip).

BOOTREQUEST = 1
BOOTREPLY = 2

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

MAGIC_COOKIE = b"\x63\x82\x53\x63"

OPTION_MESSAGE_TYPE = 53
OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS = 6
OPTION_REQUESTED_IP = 50
OPTION_LEASE_TIME = 51
OPTION_SERVER_ID = 54
OPTION_END = 255


def ip_to_int(ip: str) -> int:
    return struct.unpack('>I', socket.inet_aton(ip))[0]


def int_to_ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack('>I', i))


class DHCPServer:
    def get_primary_ip(self) -> Optional[str]:
        """Return the primary IPv4 address of the host or None if it cannot be determined.
        Tries a UDP socket to a public IP to read the local socket name (no packets sent).
        Falls back to gethostbyname(gethostname())."""
        try:
            # Use UDP socket to infer outbound interface IP (no data is sent).
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to a public DNS server; doesn't send packets but assigns local addr
                s.connect(('8.8.8.8', 53))
                ip = s.getsockname()[0]
                return ip
            finally:
                s.close()
        except Exception:
            pass
        try:
            # Fallback: hostname resolution
            hn = socket.gethostname()
            ip = socket.gethostbyname(hn)
            if ip and not ip.startswith('127.'):
                return ip
        except Exception:
            pass
        return None

    def __init__(self, subnet: str, netmask: str, start_ip: str, end_ip: str, lease_ttl: int = 86400, static_leases: Dict[str, str] = None, server_ip: Optional[str] = None, lease_db_path: Optional[str] = '/var/lib/phantomd/dhcp_leases.json'):
        self.subnet = subnet
        self.netmask = netmask
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.lease_ttl = lease_ttl
        self.static_leases = {mac.lower(): ip for mac, ip in (static_leases or {}).items()}
        self.server_ip = server_ip or self.get_primary_ip() or '0.0.0.0'
        self.leases: Dict[str, Tuple[str, float]] = {}  # mac -> (ip, expiry)
        self.pool_start = ip_to_int(start_ip)
        self.pool_end = ip_to_int(end_ip)
        # don't grab the event loop in __init__; start() will set it when the loop is running
        self.loop = None
        self.transport = None
        self.lease_db_path = lease_db_path
        # load persisted leases if available
        try:
            self._load_leases()
        except Exception:
            # if loading fails, start with empty leases
            self.leases = {}

    def _load_leases(self):
        if not self.lease_db_path:
            return
        try:
            with open(self.lease_db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            now = time.time()
            loaded = {}
            for mac, entry in data.items():
                ip = entry.get('ip')
                expiry = float(entry.get('expiry', 0))
                # only keep unexpired leases
                if expiry > now:
                    loaded[mac.lower()] = (ip, expiry)
            self.leases = loaded
        except FileNotFoundError:
            self.leases = {}
        except Exception:
            self.leases = {}

    def _save_leases(self):
        if not self.lease_db_path:
            return
        dirpath = os.path.dirname(self.lease_db_path)
        try:
            if dirpath and not os.path.isdir(dirpath):
                os.makedirs(dirpath, exist_ok=True)
        except Exception:
            # if we cannot create directory, fallback to local file
            self.lease_db_path = os.path.join(os.getcwd(), 'dhcp_leases.json')
        data = {}
        for mac, (ip, expiry) in self.leases.items():
            data[mac] = {'ip': ip, 'expiry': expiry}
        # atomic write
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(self.lease_db_path) or '.', prefix='.tmp_leases_')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            os.replace(tmp_path, self.lease_db_path)
        except Exception:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def _cleanup_expired(self):
        now = time.time()
        removed = False
        for mac in list(self.leases.keys()):
            _, expiry = self.leases[mac]
            if expiry <= now:
                del self.leases[mac]
                removed = True
        if removed:
            try:
                self._save_leases()
            except Exception:
                pass

    def next_free_ip(self) -> Optional[str]:
        # check static leases first
        used = {ip for ip, _ in [v for v in self.leases.values()]}
        # include static IPs
        used.update(self.static_leases.values())
        for i in range(self.pool_start, self.pool_end + 1):
            ip = int_to_ip(i)
            if ip in used:
                continue
            return ip
        return None

    def allocate_for_mac(self, mac: str, requested: Optional[str] = None) -> Optional[str]:
        mac = mac.lower()
        # static lease
        if mac in self.static_leases:
            return self.static_leases[mac]
        # existing lease
        if mac in self.leases:
            ip, expiry = self.leases[mac]
            if expiry > time.time():
                return ip
        # if requested and available
        if requested:
            if requested not in [v for v, _ in self.leases.values()] and requested not in self.static_leases.values():
                # ensure requested inside pool
                try:
                    ri = ip_to_int(requested)
                    if self.pool_start <= ri <= self.pool_end:
                        self.leases[mac] = (requested, time.time() + self.lease_ttl)
                        try:
                            self._save_leases()
                        except Exception:
                            pass
                        return requested
                except Exception:
                    pass
        ip = self.next_free_ip()
        if ip:
            self.leases[mac] = (ip, time.time() + self.lease_ttl)
            try:
                self._save_leases()
            except Exception:
                pass
            return ip
        return None

    def build_options(self, opts: Dict[int, bytes]) -> bytes:
        data = bytearray(MAGIC_COOKIE)
        for code, value in opts.items():
            data.append(code)
            data.append(len(value))
            data.extend(value)
        data.append(OPTION_END)
        return bytes(data)

    def parse_options(self, data: bytes) -> Dict[int, bytes]:
        opts = {}
        if not data.startswith(MAGIC_COOKIE):
            return opts
        i = 4
        while i < len(data):
            code = data[i]
            i += 1
            if code == OPTION_END:
                break
            if code == 0:
                continue
            length = data[i]
            i += 1
            value = data[i:i+length]
            i += length
            opts[code] = value
        return opts

    def build_reply(self, op: int, xid: int, chaddr: bytes, yiaddr: str, msg_type: int) -> bytes:
        # BOOTP header
        # op, htype(1), hlen(1), hops(1), xid(4), secs(2), flags(2), ciaddr(4), yiaddr(4), siaddr(4), giaddr(4), chaddr(16)
        htype = 1
        hlen = 6
        hops = 0
        secs = 0
        flags = 0
        ciaddr = b'\x00\x00\x00\x00'
        yiaddr_bytes = socket.inet_aton(yiaddr) if yiaddr else b'\x00\x00\x00\x00'
        siaddr = socket.inet_aton(self.server_ip)
        giaddr = b'\x00\x00\x00\x00'
        chaddr_padded = chaddr + b'\x00' * (16 - len(chaddr))
        sname = b'\x00' * 64
        file = b'\x00' * 128
        header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', BOOTREPLY, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr_bytes, siaddr, giaddr, chaddr_padded, sname, file)
        # options
        opts = {}
        opts[OPTION_MESSAGE_TYPE] = bytes([msg_type])
        opts[OPTION_SERVER_ID] = socket.inet_aton(self.server_ip)
        opts[OPTION_SUBNET_MASK] = socket.inet_aton(self.netmask)
        opts[OPTION_ROUTER] = socket.inet_aton(self.server_ip)
        opts[OPTION_DNS] = socket.inet_aton(self.server_ip)
        opts[OPTION_LEASE_TIME] = struct.pack('!I', self.lease_ttl)
        opt_blob = self.build_options(opts)
        return header + opt_blob

    def handle_discover(self, xid: int, chaddr: bytes, requested: Optional[str]) -> Optional[bytes]:
        mac = ':'.join(['%02x' % b for b in chaddr[:6]])
        ip = self.allocate_for_mac(mac, requested)
        if not ip:
            return None
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPOFFER)

    def handle_request(self, xid: int, chaddr: bytes, requested: Optional[str]) -> Optional[bytes]:
        mac = ':'.join(['%02x' % b for b in chaddr[:6]])
        ip = self.allocate_for_mac(mac, requested)
        if not ip:
            # NAK (not implemented full NAK options)
            return None
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK)

    async def start(self, bind_ip: str = '0.0.0.0', bind_port: int = 67):
        loop = asyncio.get_running_loop()
        self.loop = loop
        transport, protocol = await loop.create_datagram_endpoint(lambda: DHCPProtocol(self), local_addr=(bind_ip, bind_port))
        self.transport = transport
        # start maintenance task on the running loop
        self.loop.create_task(self._maintenance_loop())
        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            transport.close()

    async def _maintenance_loop(self):
        while True:
            try:
                await asyncio.sleep(60)
                self._cleanup_expired()
            except Exception:
                await asyncio.sleep(60)


class DHCPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: DHCPServer):
        self.server = server

    def datagram_received(self, data: bytes, addr):
        try:
            # parse BOOTP
            if len(data) < 240:
                return
            op = data[0]
            xid = struct.unpack('!I', data[4:8])[0]
            chaddr = data[28:28+16]
            # options
            opts = self.server.parse_options(data[240:])
            msg_type = opts.get(OPTION_MESSAGE_TYPE)
            requested = None
            if OPTION_REQUESTED_IP in opts:
                requested = socket.inet_ntoa(opts[OPTION_REQUESTED_IP])
            if msg_type:
                t = msg_type[0]
                if t == DHCPDISCOVER:
                    resp = self.server.handle_discover(xid, chaddr, requested)
                    if resp:
                        # send to broadcast port 68
                        self.server.transport.sendto(resp, ('<broadcast>', 68))
                elif t == DHCPREQUEST:
                    resp = self.server.handle_request(xid, chaddr, requested)
                    if resp:
                        self.server.transport.sendto(resp, ('<broadcast>', 68))
        except Exception:
            pass
