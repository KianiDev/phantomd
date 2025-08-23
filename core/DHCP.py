import asyncio
import socket
import struct
import time
import json
import os
import tempfile
try:
    import aiosqlite
except Exception:
    aiosqlite = None
import logging
from typing import Dict, Tuple, Optional

# configure module logger (users can reconfigure in their app)
logger = logging.getLogger("phantomd.dhcp")
if not logger.handlers():
    # default handler for standalone runs; apps should configure logging as needed
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    logger.addHandler(ch)
    logger.setLevel(logging.INFO)

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
OPTION_T1 = 58
OPTION_T2 = 59


def ip_to_int(ip: str) -> int:
    return struct.unpack('>I', socket.inet_aton(ip))[0]


def int_to_ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack('>I', i))


class DHCPServer:
    """
    DHCPServer implements a small DHCPv4 server with the following responsibilities:
    - lease allocation (in-memory JSON fallback or a WAL SQLite DB via aiosqlite)
    - building DHCP BOOTP replies (OFFER/ACK/NAK)
    - maintenance tasks (expiry cleanup)

    The class is intentionally small so it can be extended or replaced by a stronger "store" or
    "policy" module later. Key async DB operations are available when aiosqlite is installed.
    """
    def get_primary_ip(self) -> Optional[str]:
        """Return the primary IPv4 address of the host used as server identifier.

        This tries a UDP connect to a public server to determine the outbound interface IP
        without sending packets; falls back to hostname resolution if needed.
        """
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
        # rate limiting defaults (requests per second and burst)
        self.rate_limit_rps = 1.0
        self.rate_limit_burst = 3.0
        self._mac_buckets: Dict[str, Tuple[float, float]] = {}  # mac -> (tokens, last_ts)
        self._ip_buckets: Dict[str, Tuple[float, float]] = {}   # ip -> (tokens, last_ts)
        # track recently conflicted IPs (cooldown seconds)
        self._conflicted_ips: Dict[str, float] = {}
        # load persisted leases if available
        try:
            self._load_leases()
        except Exception as e:
            logger.warning("Failed to load leases on init: %s", e)
            # if loading fails, start with empty leases
            self.leases = {}

    def _load_leases(self):
        if not self.lease_db_path:
            logger.debug("No lease file path configured")
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
            logger.info("Successfully loaded %d leases from %s", len(loaded), self.lease_db_path)
        except FileNotFoundError:
            logger.info("Lease file not found at %s, starting with empty leases", self.lease_db_path)
            self.leases = {}
        except Exception as e:
            logger.error("Error loading leases from %s: %s", self.lease_db_path, e)
            self.leases = {}

    def _save_leases(self):
        if not self.lease_db_path:
            logger.debug("No lease file path configured")
            return
        dirpath = os.path.dirname(self.lease_db_path)
        try:
            if dirpath and not os.path.isdir(dirpath):
                logger.info("Creating lease directory: %s", dirpath)
                os.makedirs(dirpath, exist_ok=True)
        except Exception as e:
            logger.warning("Cannot create directory %s: %s; falling back to local file", dirpath, e)
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
            logger.info("Successfully saved %d leases to %s", len(data), self.lease_db_path)
        except Exception as e:
            logger.error("Error saving leases to %s: %s", self.lease_db_path, e)
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception as e2:
                logger.debug("Error cleaning up temp file %s: %s", tmp_path, e2)

    async def _init_db(self):
        """Initialize a SQLite WAL-backed lease DB using aiosqlite. If a JSON lease file exists, migrate it."""
        if aiosqlite is None:
            logger.warning("aiosqlite not available; install with: pip install aiosqlite")
            return
        # derive .db path from configured lease_db_path (allow both .json and .db)
        db_path = self.lease_db_path
        if not db_path:
            logger.warning("No lease DB path configured")
            return
        if db_path.endswith('.json'):
            base = os.path.splitext(db_path)[0]
            db_path = base + '.db'
        self._db_path = db_path
        os.makedirs(os.path.dirname(self._db_path) or '.', exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA synchronous=NORMAL;")
        await self._db.execute("""
        CREATE TABLE IF NOT EXISTS leases(
          mac TEXT PRIMARY KEY,
          ip TEXT UNIQUE NOT NULL,
          expiry INTEGER NOT NULL,
          state TEXT NOT NULL
        );
        """)
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_expiry ON leases(expiry);")
        await self._db.commit()
        # migrate existing JSON file if present
        json_path = self.lease_db_path
        if json_path and json_path.endswith('.json') and os.path.exists(json_path):
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                now = int(time.time())
                count = 0
                for mac, entry in data.items():
                    ip = entry.get('ip')
                    expiry = int(entry.get('expiry', 0))
                    if expiry > now:
                        await self._db.execute("INSERT OR REPLACE INTO leases(mac,ip,expiry,state) VALUES(?,?,?,?)", (mac.lower(), ip, expiry, 'bound'))
                        count += 1
                await self._db.commit()
                logger.info("Migrated %d leases from %s to %s", count, json_path, self._db_path)
            except Exception as e:
                logger.error("Failed to migrate leases: %s", e)

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

    async def async_allocate_for_mac(self, mac: str, requested: Optional[str] = None) -> Optional[str]:
        """Async allocation using the SQLite DB. Returns assigned IP or None."""
        if aiosqlite is None or not hasattr(self, '_db'):
            # fallback to in-memory logic
            return self.allocate_for_mac(mac, requested)
        mac = mac.lower()
        now = int(time.time())
        try:
            await self._db.execute("BEGIN IMMEDIATE;")
            # expire old
            await self._db.execute("DELETE FROM leases WHERE expiry <= ?", (now,))
            # check static
            if mac in self.static_leases:
                ip = self.static_leases[mac]
                await self._db.execute("COMMIT;")
                logger.debug("Static lease for %s -> %s", mac, ip)
                return ip
            # existing lease
            cur = await self._db.execute("SELECT ip, expiry FROM leases WHERE mac = ?", (mac,))
            row = await cur.fetchone()
            if row:
                ip, expiry = row
                if expiry > now:
                    await self._db.execute("COMMIT;")
                    logger.debug("Reused active lease for %s -> %s", mac, ip)
                    return ip
            # if requested
            if requested:
                try:
                    ri = ip_to_int(requested)
                    if not (self.pool_start <= ri <= self.pool_end):
                        await self._db.execute("ROLLBACK;")
                        logger.debug("Requested IP %s not in pool", requested)
                        return None
                except Exception:
                    await self._db.execute("ROLLBACK;")
                    logger.debug("Invalid requested IP format: %s", requested)
                    return None
                cur = await self._db.execute("SELECT mac FROM leases WHERE ip = ?", (requested,))
                taken = await cur.fetchone()
                if not taken and requested not in self.static_leases.values():
                    expiry_ts = now + int(self.lease_ttl)
                    await self._db.execute("INSERT INTO leases(mac,ip,expiry,state) VALUES(?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, expiry=excluded.expiry, state='bound'", (mac, requested, expiry_ts, 'bound'))
                    await self._db.execute("COMMIT;")
                    logger.info("Assigned requested IP %s to %s", requested, mac)
                    return requested
                else:
                    await self._db.execute("ROLLBACK;")
                    logger.debug("Requested IP %s already taken", requested)
                    return None
            # find next free ip
            cur = await self._db.execute("SELECT ip FROM leases")
            rows = await cur.fetchall()
            used = {r[0] for r in rows}
            used.update(self.static_leases.values())
            assigned = None
            for i in range(self.pool_start, self.pool_end + 1):
                ip = int_to_ip(i)
                if ip in used:
                    continue
                assigned = ip
                break
            if assigned:
                expiry_ts = now + int(self.lease_ttl)
                await self._db.execute("INSERT INTO leases(mac,ip,expiry,state) VALUES(?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, expiry=excluded.expiry, state='bound'", (mac, assigned, expiry_ts, 'bound'))
                await self._db.execute("COMMIT;")
                logger.info("Allocated %s -> %s", mac, assigned)
                return assigned
            await self._db.execute("ROLLBACK;")
            logger.debug("No free IP available for %s", mac)
            return None
        except Exception as e:
            try:
                await self._db.execute("ROLLBACK;")
            except Exception:
                pass
            logger.error("DB allocation error: %s", e)
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
        n = len(data)
        while i < n:
            code = data[i]
            i += 1
            if code == OPTION_END:
                break
            if code == 0:  # PAD
                continue
            if i >= n: break
            length = data[i]
            i += 1
            if i + length > n: break
            opts[code] = data[i:i+length]
            i += length
        return opts

    def build_reply(self, op: int, xid: int, chaddr: bytes, yiaddr: str, msg_type: int, prl: Optional[bytes]=None, include_t1t2: bool=False) -> bytes:
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
        if include_t1t2:
            opts[OPTION_T1] = struct.pack('!I', int(self.lease_ttl * 0.5))
            opts[OPTION_T2] = struct.pack('!I', int(self.lease_ttl * 0.875))

        # If client sent a Parameter Request List, only include requested options plus essentials
        if prl:
            # prl is a bytes object of option codes
            filtered = {}
            # always include message type and server id
            filtered[OPTION_MESSAGE_TYPE] = opts[OPTION_MESSAGE_TYPE]
            filtered[OPTION_SERVER_ID] = opts[OPTION_SERVER_ID]
            # include lease/time if present
            if OPTION_LEASE_TIME in opts:
                filtered[OPTION_LEASE_TIME] = opts[OPTION_LEASE_TIME]
            if include_t1t2:
                if OPTION_T1 in opts: filtered[OPTION_T1] = opts[OPTION_T1]
                if OPTION_T2 in opts: filtered[OPTION_T2] = opts[OPTION_T2]
            for code in prl:
                if code in opts:
                    filtered[code] = opts[code]
            opt_blob = self.build_options(filtered)
        else:
            opt_blob = self.build_options(opts)
        return header + opt_blob

    def handle_discover(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        mac = ':'.join('%02x' % b for b in chaddr[:6])
        ip = self.allocate_for_mac(mac, requested)
        if not ip:
            return None
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPOFFER, prl=prl, include_t1t2=True)

    def handle_request(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        mac = ':'.join('%02x' % b for b in chaddr[:6])
        ip = self.allocate_for_mac(mac, requested)
        if not ip:
            # return a proper NAK so clients can retry/choose another server
            return self.build_nak(xid, chaddr)
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)

    def build_nak(self, xid: int, chaddr: bytes) -> bytes:
        header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
            BOOTREPLY, 1, 6, 0,  # op,htype,hlen,hops
            xid, 0, 0,           # xid,secs,flags
            b'\0'*4,            # ciaddr
            b'\0'*4,            # yiaddr
            socket.inet_aton(self.server_ip),  # siaddr
            b'\0'*4,            # giaddr
            chaddr + b'\0'*(16-len(chaddr)),   # chaddr
            b'\0'*64,           # sname
            b'\0'*128           # file
        )
        
        opts = {
            OPTION_MESSAGE_TYPE: bytes([DHCPNAK]),
            OPTION_SERVER_ID: socket.inet_aton(self.server_ip)
        }
        return header + self.build_options(opts)

    def _allow_request(self, mac: str, src_ip: str) -> bool:
        """Token-bucket rate limit per-MAC and per-src IP. Returns True if request allowed."""
        now = time.time()
        def _consume(bucket: Dict[str, Tuple[float, float]], key: str) -> bool:
            tokens, last = bucket.get(key, (self.rate_limit_burst, now))
            # refill
            tokens = min(self.rate_limit_burst, tokens + (now - last) * self.rate_limit_rps)
            if tokens < 1.0:
                bucket[key] = (tokens, now)
                return False
            bucket[key] = (tokens - 1.0, now)
            return True

        # check MAC bucket
        if not _consume(self._mac_buckets, mac):
            return False
        # check IP bucket
        if not _consume(self._ip_buckets, src_ip):
            return False
        return True

    async def _arp_conflict_async(self, ip: str, timeout: int = 1) -> bool:
        """Best-effort ARP conflict detection. Uses system `arping` if available. Returns True if conflict detected."""
        try:
            import shutil
            if shutil.which('arping') is None:
                return False
            # run arping -c 1 -w timeout <ip>
            proc = await asyncio.create_subprocess_exec('arping', '-c', '1', '-w', str(timeout), ip, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            rc = await proc.wait()
            return rc == 0
        except Exception:
            return False

    def _arp_conflict_sync(self, ip: str, timeout: int = 1) -> bool:
        try:
            import shutil, subprocess
            if shutil.which('arping') is None:
                logger.debug('arping not available')
                return False
            # subprocess.run will block; used by sync handlers if needed
            r = subprocess.run(['arping', '-c', '1', '-w', str(timeout), ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
            logger.debug('arping exit code for %s: %s', ip, r.returncode)
            return r.returncode == 0
        except Exception as e:
            logger.debug('arping failed for %s: %s', ip, e)
            return False

    def drop_privileges(self, user: str = 'nobody', group: Optional[str] = None, chroot_dir: Optional[str] = None):
        """Drop root privileges to the specified user/group and optionally chroot. Best-effort and logs failures."""
        try:
            if os.geteuid() != 0:
                # not root, nothing to do
                return
        except Exception:
            return
        try:
            import pwd, grp
            pw = pwd.getpwnam(user)
            gid = pw.pw_gid if group is None else grp.getgrnam(group).gr_gid
            if chroot_dir:
                try:
                    os.chroot(chroot_dir)
                    os.chdir('/')
                    logger.info('chroot to %s successful', chroot_dir)
                except Exception as e:
                    logger.warning('chroot failed: %s', e)
            # set groups first
            try:
                os.setgid(gid)
                os.setuid(pw.pw_uid)
                # remove supplementary groups
                try:
                    os.setgroups([])
                except Exception:
                    pass
            except Exception as e:
                logger.warning('Failed to drop privileges: %s', e)
        except Exception as e:
            logger.error('drop_privileges helper error: %s', e)

    # integrate ARP conflict into async request flow
    async def async_handle_request(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        mac = ':'.join('%02x' % b for b in chaddr[:6])
        # check if IP is in recent conflict cooldown
        if requested and requested in self._conflicted_ips:
            if time.time() < self._conflicted_ips.get(requested, 0):
                logger.info('Requested %s is in conflict cooldown, NAKing', requested)
                return self.build_nak(xid, chaddr)
            else:
                del self._conflicted_ips[requested]
        ip = await self.async_allocate_for_mac(mac, requested)
        if not ip:
            logger.info('Failed to allocate IP for %s', mac)
            return self.build_nak(xid, chaddr)
        # ARP probe before ACK; if conflict, mark IP with cooldown and NAK
        try:
            conflict = await self._arp_conflict_async(ip)
            if conflict:
                logger.warning('ARP conflict detected for %s; removing lease and NAKing', ip)
                # cooldown for 60s to avoid flapping
                self._conflicted_ips[ip] = time.time() + 60
                # if DB-backed, remove lease
                if hasattr(self, '_db'):
                    try:
                        await self._db.execute("DELETE FROM leases WHERE ip = ?", (ip,))
                        await self._db.commit()
                    except Exception as e:
                        logger.debug('Error removing conflicted lease from DB: %s', e)
                else:
                    # remove from in-memory leases if present
                    try:
                        for m, (a, _) in list(self.leases.items()):
                            if a == ip:
                                del self.leases[m]
                                break
                    except Exception as e:
                        logger.debug('Error removing conflicted lease from memory: %s', e)
                return self.build_nak(xid, chaddr)
        except Exception as e:
            logger.debug('ARP probe failed for %s: %s', ip, e)
        logger.info('ACKing %s -> %s', mac, ip)
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)

    async def start(self, bind_ip: str = '0.0.0.0', bind_port: int = 67):
        loop = asyncio.get_running_loop()
        self.loop = loop
        # initialize async DB if available
        try:
            await self._init_db()
        except Exception as e:
            logger.debug('DB init failed: %s', e)
         # If server_ip wasn't provided or is wildcard, use the bind_ip so clients see a reachable server identifier
        if not self.server_ip or self.server_ip == '0.0.0.0':
            self.server_ip = bind_ip

        # Create a UDP socket and enable broadcast so responses to '<broadcast>' succeed
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.debug('Set SO_REUSEADDR')
        except Exception:
            pass
        try:
            # allow sending broadcasts
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            logger.debug('Set SO_BROADCAST')
        except Exception:
            pass
        try:
            # allow reuse port for multi-worker setups when available
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_REUSEPORT'), 1)
            logger.debug('Set SO_REUSEPORT')
        except Exception:
            pass
        # bind to the desired address/port
        sock.bind((bind_ip, bind_port))
        logger.info('DHCP server bound to %s:%d', bind_ip, bind_port)

        # hand the pre-bound socket to asyncio so it uses our socket with broadcast enabled
        transport, protocol = await loop.create_datagram_endpoint(lambda: DHCPProtocol(self), sock=sock)
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
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        # Optional: bind to specific interface (Linux only)
        # try:
        #     sock.setsockopt(socket.SOL_SOCKET, 25, b"eth0\0")  # SO_BINDTODEVICE
        # except Exception:
        #     pass

    def _send(self, pkt: bytes, giaddr: bytes, flags: int, yiaddr: bytes, ciaddr: bytes):
        # Respect relay agents: reply to giaddr:67
        if giaddr != b'\x00'*4:
            dst = (socket.inet_ntoa(giaddr), 67)
        elif flags & 0x8000:  # broadcast flag set
            dst = ('255.255.255.255', 68)
        elif ciaddr != b'\x00'*4:
            dst = (socket.inet_ntoa(ciaddr), 68)
        else:
            dst = (socket.inet_ntoa(yiaddr), 68)
        try:
            self.transport.sendto(pkt, dst)
            logger.debug('Sent DHCP response to %s', dst)
        except Exception as e:
            logger.error('Error sending DHCP response to %s: %s', dst, e)

    async def _handle_message(self, t: int, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes], giaddr: bytes, flags: int, yiaddr: bytes, ciaddr: bytes):
        try:
            if t == DHCPDISCOVER:
                if hasattr(self.server, 'async_handle_discover'):
                    resp = await self.server.async_handle_discover(xid, chaddr, requested, prl=prl)
                else:
                    resp = self.server.handle_discover(xid, chaddr, requested)
                if resp:
                    self._send(resp, giaddr, flags, yiaddr, ciaddr)
            elif t == DHCPREQUEST:
                if hasattr(self.server, 'async_handle_request'):
                    resp = await self.server.async_handle_request(xid, chaddr, requested, prl=prl)
                else:
                    resp = self.server.handle_request(xid, chaddr, requested)
                if resp:
                    self._send(resp, giaddr, flags, yiaddr, ciaddr)
            elif t == DHCPRELEASE:
                mac = ':'.join('%02x' % b for b in chaddr[:6])
                if hasattr(self.server, 'async_release_mac'):
                    await self.server.async_release_mac(mac)
                else:
                    try:
                        if mac in self.server.leases:
                            del self.server.leases[mac]
                            try:
                                self.server._save_leases()
                            except Exception:
                                pass
                    except Exception:
                        pass
            elif t == DHCPINFORM:
                resp = self.server.build_reply(BOOTREPLY, xid, chaddr, '', DHCPACK, prl=prl, include_t1t2=False)
                if resp:
                    self._send(resp, giaddr, flags, yiaddr, ciaddr)
        except Exception:
            pass

    def datagram_received(self, data: bytes, addr):
        try:
            # parse BOOTP header fields we care about
            if len(data) < 240:
                return
            op = data[0]
            hlen = data[2]
            xid = struct.unpack('!I', data[4:8])[0]
            flags = struct.unpack('!H', data[10:12])[0]
            ciaddr = data[12:16]
            yiaddr = data[16:20]
            siaddr = data[20:24]
            giaddr = data[24:28]
            chaddr_full = data[28:28+16]
            chaddr = chaddr_full[:hlen]
            # options
            opts = self.server.parse_options(data[240:])
            msg_type = opts.get(OPTION_MESSAGE_TYPE)
            prl = opts.get(55)  # Parameter Request List (bytes)
            requested = None
            if OPTION_REQUESTED_IP in opts:
                requested = socket.inet_ntoa(opts[OPTION_REQUESTED_IP])
            if msg_type:
                t = msg_type[0]
                # handle asynchronously so DB-backed allocations don't block
                try:
                    asyncio.get_running_loop().create_task(self._handle_message(t, xid, chaddr, requested, prl, giaddr, flags, yiaddr, ciaddr))
                except Exception:
                    # fallback to sync handling
                    if t == DHCPDISCOVER:
                        resp = self.server.handle_discover(xid, chaddr, requested, prl=prl)
                        if resp:
                            self._send(resp, giaddr, flags, yiaddr, ciaddr)
                    elif t == DHCPREQUEST:
                        resp = self.server.handle_request(xid, chaddr, requested, prl=prl)
                        if resp:
                            self._send(resp, giaddr, flags, yiaddr, ciaddr)
        except Exception:
            pass
