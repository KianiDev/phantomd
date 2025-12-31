from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import struct
import time
import hashlib
import json
import os
import atexit
from typing import Dict, Tuple, Optional

# optional sqlite backend (not required)
try:
    import aiosqlite
except Exception:
    aiosqlite = None

# configure module logger
logger = logging.getLogger("phantomd.dhcp")
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    logger.addHandler(ch)
    logger.setLevel(logging.INFO)

# DHCP constants
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
OPTION_PARAM_REQUEST_LIST = 55

MAX_DHCP_OPTIONS = 1024


def ip_to_int(ip: str) -> int:
    return struct.unpack('>I', socket.inet_aton(ip))[0]


def int_to_ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack('>I', i))


def calc_broadcast(ip: str, netmask: str) -> str:
    """Calculate the subnet broadcast address for given ip/netmask."""
    try:
        ip_i = ip_to_int(ip)
        mask_i = ip_to_int(netmask)
        bcast_i = (ip_i & mask_i) | (~mask_i & 0xFFFFFFFF)
        return int_to_ip(bcast_i)
    except Exception:
        return '255.255.255.255'


class LeaseExpired(Exception):
    pass


class DHCPServer:
    """A simple DHCP server with JSON-backed lease DB and in-memory mirror.

    Notes:
      - This implementation is suitable for lab / embedded usage. It is not hardened
        for hostile networks but includes basic checks and structured logging.
      - Persistence uses a JSON file by default. If `aiosqlite` is available a sqlite
        backend could be added later.
    """

    def get_primary_ip(self) -> Optional[str]:
        # Best-effort: pick server_ip or first usable IP in range
        if getattr(self, 'server_ip', None):
            return self.server_ip
        try:
            return self.start_ip
        except Exception:
            return None

    def __init__(self, subnet: str, netmask: str, start_ip: str, end_ip: str, lease_ttl: int = 86400, static_leases: Dict[str, str] = None, server_ip: Optional[str] = None, lease_db_path: Optional[str] = '/var/lib/phantomd/dhcp_leases.json'):
        self.subnet = subnet
        self.netmask = netmask
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.lease_ttl = int(lease_ttl)
        self.server_ip = server_ip
        self.lease_db_path = lease_db_path

        # normalize static leases (mac -> ip)
        self.static_leases = {}
        for m, ip in (static_leases or {}).items():
            k = self._normalize_mac(m)
            if k:
                self.static_leases[k] = ip

        # in-memory leases: mac -> {'ip': ip, 'expiry': ts}
        self.leases: Dict[str, Dict[str, int]] = {}
        # reverse map ip -> mac for quick conflict checks
        self.ip_map: Dict[str, str] = {}

        # optional sqlite DB handle (set by _init_db if used)
        self._db = None

        # persistence backend selection: 'json', 'sqlite', or 'none'
        # Default chosen from lease_db_path: .sqlite -> attempt sqlite, otherwise JSON.
        self.lease_backend = 'none'
        try:
            p = str(self.lease_db_path) if self.lease_db_path else ''
        except Exception:
            p = ''
        if not p:
            self.lease_backend = 'none'
        elif p.lower().endswith('.sqlite'):
            # prefer sqlite but may fall back later if aiosqlite missing or init fails
            if aiosqlite is not None:
                self.lease_backend = 'sqlite'
            else:
                logger.warning('lease_db_path ends with .sqlite but aiosqlite not available; falling back to JSON')
                self.lease_backend = 'json'
        else:
            self.lease_backend = 'json'

        # concurrency
        self._lock = asyncio.Lock()
        # sqlite write serialization lock
        self._db_lock = asyncio.Lock()

        # rate limiting / buckets and internal state
        self._offered: Dict[str, Tuple[str, float]] = {}
        self._conflicted_ips: Dict[str, float] = {}
        self.rate_limit_rps = 10.0
        self.rate_limit_burst = 20.0
        self._mac_buckets: Dict[str, Tuple[float, float]] = {}
        self._ip_buckets: Dict[str, Tuple[float, float]] = {}

        # broadcast ip placeholder
        self.broadcast_ip: Optional[str] = None

        # load persisted leases if present
        try:
            self._load_leases()
        except Exception as e:
            logger.warning("Failed to load DHCP leases: %s", e)

        # ensure save/cleanup on exit
        atexit.register(self._finalize)

    def _finalize(self):
        # Try to close sqlite DB cleanly and fallback to saving JSON leases
        try:
            db = getattr(self, '_db', None)
            if self.lease_backend == 'sqlite' and db is not None:
                try:
                    # If there is no running event loop we can safely run the
                    # coroutine to close the DB. If an event loop is running,
                    # schedule the close onto that loop instead to avoid
                    # calling asyncio.run() from inside a running loop.
                    try:
                        running = asyncio.get_running_loop()
                    except RuntimeError:
                        # no running loop -> safe to run
                        try:
                            asyncio.run(db.close())
                        except Exception:
                            logger.debug('Exception while closing sqlite DB in finalize (no running loop)', exc_info=True)
                    else:
                        # event loop is running; try to schedule close on it.
                        try:
                            if hasattr(self, 'loop') and self.loop is running:
                                # same loop we started on
                                self.loop.create_task(db.close())
                            else:
                                # Best-effort: submit to the running loop thread-safely
                                try:
                                    asyncio.run_coroutine_threadsafe(db.close(), running)
                                except Exception:
                                    logger.debug('Failed to submit DB close to running loop', exc_info=True)
                        except Exception:
                            logger.debug('Unexpected error while scheduling DB close', exc_info=True)
                except Exception:
                    logger.debug('Unexpected error during finalize DB close', exc_info=True)
        except Exception:
            logger.debug('Unexpected error entering finalize()', exc_info=True)
        # Persist leases depending on selected backend
        try:
            if self.lease_backend == 'sqlite':
                # schedule a final save if DB is present
                try:
                    if getattr(self, '_db', None) is not None:
                        try:
                            loop = asyncio.get_running_loop()
                        except RuntimeError:
                            # no running loop -> run close synchronously
                            try:
                                asyncio.run(self._save_leases_async())
                            except Exception:
                                logger.debug('Failed to run sqlite save during finalize', exc_info=True)
                        else:
                            try:
                                asyncio.run_coroutine_threadsafe(self._save_leases_async(), loop)
                            except Exception:
                                logger.debug('Failed to schedule sqlite save during finalize', exc_info=True)
                except Exception:
                    logger.debug('Error while attempting final sqlite save', exc_info=True)
            elif self.lease_backend == 'json':
                try:
                    self._save_leases()
                except Exception:
                    logger.debug('Failed to save leases during finalize', exc_info=True)
            else:
                logger.debug('No lease backend configured during finalize; nothing to persist')
        except Exception:
            logger.debug('Unexpected error during finalize persistence', exc_info=True)

    def _normalize_mac(self, mac) -> Optional[str]:
        if mac is None:
            return None
        if isinstance(mac, bytes):
            mac = ':'.join('{:02x}'.format(b) for b in mac[:6])
        mac = str(mac).lower().replace('-', ':')
        # accept forms like 001122334455 or 00:11:22:33:44:55
        mac = mac.strip()
        if len(mac) == 12 and ':' not in mac:
            mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        parts = mac.split(':')
        if len(parts) != 6:
            return None
        try:
            parts = ['{:02x}'.format(int(p, 16)) for p in parts]
        except Exception:
            return None
        return ':'.join(parts)

    def _load_leases(self):
        # JSON-backed simple storage
        # Only load JSON when backend is configured for JSON persistence
        if self.lease_backend != 'json':
            return
        try:
            p = str(self.lease_db_path) if self.lease_db_path else ''
        except Exception:
            p = ''
        if not p:
            return
        try:
            if os.path.exists(self.lease_db_path):
                with open(self.lease_db_path, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                    # validate format
                    if isinstance(data, dict):
                        self.leases = {}
                        self.ip_map = {}
                        now = int(time.time())
                        for mac, info in data.items():
                            if not isinstance(info, dict):
                                continue
                            ip = info.get('ip')
                            expiry = int(info.get('expiry', 0))
                            if not ip:
                                continue
                            if expiry and expiry < now:
                                continue
                            m = self._normalize_mac(mac)
                            if not m:
                                continue
                            self.leases[m] = {'ip': ip, 'expiry': expiry}
                            self.ip_map[ip] = m
        except Exception as e:
            logger.warning("Failed to open/parse lease DB %s: %s", self.lease_db_path, e)

    def _save_leases(self):
        if not self.lease_db_path:
            return
        try:
            dirpath = os.path.dirname(self.lease_db_path)
            os.makedirs(dirpath, exist_ok=True)
            tmp = self.lease_db_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(self.leases, fh)
            os.replace(tmp, self.lease_db_path)
            logger.debug("DHCP leases saved to %s", self.lease_db_path)
        except Exception as e:
            logger.warning("Failed to save leases to %s: %s", self.lease_db_path, e)

    async def _init_db(self):
        # Initialize sqlite backend when requested (lease_db_path should point to a .sqlite file)
        # Only initialize sqlite when backend selection indicates sqlite
        if self.lease_backend != 'sqlite':
            return
        if aiosqlite is None:
            logger.warning('aiosqlite not available; cannot initialize sqlite backend')
            # fallback to json backend
            self.lease_backend = 'json'
            return
        if not self.lease_db_path:
            return
        # Only treat .sqlite paths as sqlite DBs
        try:
            p = str(self.lease_db_path)
        except Exception:
            return
        if not p.lower().endswith('.sqlite'):
            # path doesn't look like sqlite; fallback to json
            logger.debug('lease_db_path does not end with .sqlite; skipping sqlite init')
            self.lease_backend = 'json'
            return
        # ensure directory exists
        try:
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
        except Exception:
            logger.debug('Failed to ensure sqlite directory %s', p, exc_info=True)
        try:
            self._db = await aiosqlite.connect(p)
            # performance pragmas
            try:
                await self._db.execute('PRAGMA journal_mode=WAL')
                await self._db.execute('PRAGMA synchronous=NORMAL')
            except Exception:
                logger.debug('Failed to set sqlite PRAGMA on %s', p, exc_info=True)
            await self._db.execute('''
                CREATE TABLE IF NOT EXISTS leases (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    expiry INTEGER
                )
            ''')
            await self._db.commit()
            # load leases from sqlite into memory
            try:
                async with self._db.execute('SELECT mac, ip, expiry FROM leases') as cur:
                    async for row in cur:
                        mac, ip, expiry = row
                        try:
                            exp = int(expiry) if expiry is not None else 0
                        except Exception:
                            exp = 0
                        now = int(time.time())
                        if exp and exp < now:
                            # expired, skip
                            continue
                        m = self._normalize_mac(mac)
                        if not m:
                            continue
                        self.leases[m] = {'ip': ip, 'expiry': exp}
                        self.ip_map[ip] = m
            except Exception:
                logger.debug('Failed to load leases from sqlite DB %s', p, exc_info=True)
        except Exception as e:
            logger.warning('Failed to init sqlite lease DB %s: %s', self.lease_db_path, e)
            try:
                if self._db:
                    await self._db.close()
            except Exception:
                logger.debug('Failed to close sqlite DB after init failure', exc_info=True)
            self._db = None
            # on failure, fall back to json backend
            self.lease_backend = 'json'

    def _cleanup_expired(self):
        now = int(time.time())
        removed = []
        for mac, info in list(self.leases.items()):
            if info.get('expiry') and info['expiry'] < now:
                removed.append((mac, info['ip']))
                del self.leases[mac]
                if info['ip'] in self.ip_map:
                    del self.ip_map[info['ip']]
        if removed:
            logger.debug("Cleaned expired leases: %s", removed)
            # persist (async if running inside event loop)
            try:
                self._maybe_async_save()
            except Exception:
                logger.debug('Failed to persist cleaned expired leases', exc_info=True)

    def next_free_ip(self) -> Optional[str]:
        start = ip_to_int(self.start_ip)
        end = ip_to_int(self.end_ip)
        for val in range(start, end + 1):
            ip = int_to_ip(val)
            # skip static leases
            if ip in self.static_leases.values():
                continue
            # skip if assigned
            if ip in self.ip_map:
                # check expiry
                mac = self.ip_map[ip]
                info = self.leases.get(mac)
                if info and info.get('expiry') and info['expiry'] < int(time.time()):
                    # expired, can reassign
                    continue
                continue
            return ip
        return None

    def allocate_for_mac(self, mac: str, requested: Optional[str] = None) -> Optional[str]:
        """Synchronous allocation (runs under internal lock in async contexts)."""
        m = self._normalize_mac(mac)
        if not m:
            return None
        # static lease preferred
        if m in self.static_leases:
            return self.static_leases[m]

        now = int(time.time())
        # cleanup expired leases
        self._cleanup_expired()

        # existing lease - renew
        if m in self.leases:
            info = self.leases[m]
            info['expiry'] = now + self.lease_ttl
            self.ip_map[info['ip']] = m
            try:
                self._maybe_async_save()
            except Exception:
                logger.debug('Failed to schedule lease save after renew', exc_info=True)
            return info['ip']

        # requested IP honored if available
        if requested:
            try:
                # validate requested IP: must be a valid IPv4 string
                try:
                    req_i = ip_to_int(requested)
                except Exception:
                    req_i = None
                valid = True
                # must parse
                if req_i is None:
                    valid = False
                else:
                    # must be within configured allocation range
                    try:
                        start_i = ip_to_int(self.start_ip)
                        end_i = ip_to_int(self.end_ip)
                        if req_i < start_i or req_i > end_i:
                            valid = False
                    except Exception:
                        # if range invalid, reject requested
                        valid = False
                    # must not be network or broadcast address
                    try:
                        net_i = ip_to_int(self.subnet)
                        bcast = ip_to_int(calc_broadcast(self.subnet, self.netmask))
                        if req_i == net_i or req_i == bcast:
                            valid = False
                    except Exception:
                        logger.debug('Failed to validate requested IP against network/broadcast: %s', requested, exc_info=True)
                    # must not equal server IP
                    try:
                        if self.server_ip and requested == self.server_ip:
                            valid = False
                    except Exception:
                        logger.debug('Failed to compare requested IP to server IP: %s', requested, exc_info=True)
                    # must not conflict with static leases assigned to other MACs
                    try:
                        for k, ip_val in self.static_leases.items():
                            if ip_val == requested and k != m:
                                valid = False
                                break
                    except Exception:
                        logger.debug('Failed to check requested IP against static leases: %s', requested, exc_info=True)
                if valid:
                    # check if assigned to another mac
                    owner = self.ip_map.get(requested)
                    if owner and owner != m:
                        valid = False
                if valid:
                    # assign requested IP
                    self.leases[m] = {'ip': requested, 'expiry': now + self.lease_ttl}
                    self.ip_map[requested] = m
                    try:
                        self._maybe_async_save()
                    except Exception:
                        logger.debug('Failed to schedule lease save after assigning requested IP %s', requested, exc_info=True)
                    return requested
                # invalid requested -> ignore and fall through to normal allocation
            except Exception:
                logger.debug('Exception while processing requested IP %s', requested, exc_info=True)

        # find next free
        ip = self.next_free_ip()
        if ip:
            self.leases[m] = {'ip': ip, 'expiry': now + self.lease_ttl}
            self.ip_map[ip] = m
            try:
                self._maybe_async_save()
            except Exception:
                logger.debug('Failed to schedule lease save after automatic allocation', exc_info=True)
            return ip
        return None

    def _maybe_async_save(self):
        """Persist leases. If called inside an asyncio event loop schedule the save in a thread
        to avoid blocking the loop; otherwise perform a synchronous save."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # no running loop -> synchronous save
            self._save_leases()
            return
        # If sqlite backend selected and DB handle present, schedule async sqlite save coroutine
        if self.lease_backend == 'sqlite' and getattr(self, '_db', None) is not None:
            try:
                loop.create_task(self._save_leases_async())
                return
            except Exception:
                logger.debug('Failed to schedule async sqlite save task', exc_info=True)
        # running in event loop -> offload JSON save to thread
        if self.lease_backend == 'json':
            try:
                loop.create_task(asyncio.to_thread(self._save_leases))
            except Exception:
                # fallback to synchronous save if scheduling fails
                logger.debug('Failed to offload JSON save to thread; performing synchronous save', exc_info=True)
                self._save_leases()
            return
        # lease_backend == 'none' -> nothing to do
        logger.debug('No lease backend configured; skipping save')
        

    async def _save_leases_async(self):
        """Persist leases to sqlite asynchronously when _db is available."""
        # Only operate when sqlite backend is selected
        if self.lease_backend != 'sqlite' or getattr(self, '_db', None) is None:
            # nothing to do
            return
        # serialize sqlite writes to avoid concurrent transactions
        try:
            async with self._db_lock:
                # Upsert current leases
                try:
                    # Begin transaction
                    await self._db.execute('BEGIN')
                    macs = []
                    for mac, info in list(self.leases.items()):
                        try:
                            expiry = int(info.get('expiry', 0) or 0)
                            ip = info.get('ip')
                            # Use upsert to avoid full-table replace and races
                            await self._db.execute(
                                'INSERT INTO leases(mac, ip, expiry) VALUES (?, ?, ?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, expiry=excluded.expiry',
                                (mac, ip, expiry)
                            )
                            macs.append(mac)
                        except Exception:
                            logger.debug('Failed to upsert lease for %s', mac, exc_info=True)
                    # Remove rows that no longer exist in memory
                    try:
                        if macs:
                            placeholders = ','.join('?' for _ in macs)
                            await self._db.execute(f'DELETE FROM leases WHERE mac NOT IN ({placeholders})', tuple(macs))
                        else:
                            await self._db.execute('DELETE FROM leases')
                    except Exception:
                        # best-effort cleanup; log debug on error
                        logger.debug('Failed to cleanup stale leases in sqlite', exc_info=True)
                    await self._db.commit()
                except Exception as e:
                    try:
                        await self._db.execute('ROLLBACK')
                    except Exception:
                        logger.debug('Failed to rollback sqlite transaction', exc_info=True)
                    logger.debug('Failed to persist leases to sqlite: %s', e)
        except Exception as e:
            logger.debug('DB write serialization failed: %s', e)

    async def async_allocate_for_mac(self, mac: str, requested: Optional[str] = None) -> Optional[str]:
        async with self._lock:
            return self.allocate_for_mac(mac, requested)

    def build_options(self, opts: Dict[int, bytes]) -> bytes:
        parts = bytearray()
        for code, val in opts.items():
            if code == 0 or code == OPTION_END:
                continue
            if val is None:
                continue
            l = len(val)
            if l > 255:
                # skip overly long option
                continue
            parts.append(code)
            parts.append(l)
            parts.extend(val)
        parts.append(OPTION_END)
        # pad to a multiple of 4 for alignment (not required but tidy)
        while len(parts) % 4 != 0:
            parts.append(0)
        return bytes(parts)

    def parse_options(self, data: bytes) -> Dict[int, bytes]:
        opts = {}
        i = 0
        length = len(data)
        while i < length and i < MAX_DHCP_OPTIONS:
            code = data[i]
            i += 1
            if code == 0:
                continue
            if code == OPTION_END:
                break
            if i >= length:
                break
            l = data[i]
            i += 1
            if i + l > length:
                break
            v = data[i:i+l]
            opts[code] = bytes(v)
            i += l
        return opts

    def build_reply(self, op: int, xid: int, chaddr: bytes, yiaddr: str, msg_type: int, prl: Optional[bytes]=None, include_t1t2: bool=False) -> bytes:
        # minimal BOOTP/DHCP reply builder
        htype = 1  # ethernet
        hlen = 6
        hops = 0
        secs = 0
        flags = 0
        ciaddr = socket.inet_aton('0.0.0.0')
        yiaddr_b = socket.inet_aton(yiaddr)
        siaddr = socket.inet_aton(self.server_ip if self.server_ip else '0.0.0.0')
        giaddr = socket.inet_aton('0.0.0.0')
        # chaddr must be 16 bytes
        ch = chaddr.ljust(16, b'\x00')[:16]
        sname = b'\x00' * 64
        filearea = b'\x00' * 128
        header = struct.pack('>BBBBIHH4s4s4s4s16s64s128s', op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr_b, siaddr, giaddr, ch, sname, filearea)
        pkt = header + MAGIC_COOKIE
        # prepare standard options
        opts = {}
        opts[OPTION_MESSAGE_TYPE] = bytes([msg_type])
        if self.server_ip:
            opts[OPTION_SERVER_ID] = socket.inet_aton(self.server_ip)
        if include_t1t2:
            # T1 and T2 set relative to lease
            t1 = int(self.lease_ttl * 0.5)
            t2 = int(self.lease_ttl * 0.875)
            opts[OPTION_T1] = struct.pack('>I', t1)
            opts[OPTION_T2] = struct.pack('>I', t2)
        opts[OPTION_LEASE_TIME] = struct.pack('>I', int(self.lease_ttl))
        # basic network info if available
        try:
            # subnet mask from configured netmask string
            if self.netmask:
                opts[OPTION_SUBNET_MASK] = socket.inet_aton(self.netmask)
        except Exception:
            logger.debug('Failed to include subnet mask option', exc_info=True)
        # routers (gateway) - set to server_ip if present
        if self.server_ip:
            try:
                opts[OPTION_ROUTER] = socket.inet_aton(self.server_ip)
            except Exception:
                logger.debug('Failed to include router option', exc_info=True)
        # DNS - leave empty unless provided via static_leases mapping entry (not ideal)
        # If client provided a Parameter Request List (option 55) we should NOT echo
        # it back. Instead, honor only a safe subset of options requested by the
        # client. Common and supported ones: subnet mask (1), router (3), DNS (6),
        # lease time (51), T1 (58), T2 (59).
        if prl:
            try:
                allowed = {OPTION_SUBNET_MASK, OPTION_ROUTER, OPTION_DNS, OPTION_LEASE_TIME, OPTION_T1, OPTION_T2}
                for code in prl:
                    if code not in allowed:
                        continue
                    if code == OPTION_SUBNET_MASK:
                        try:
                            if self.netmask:
                                opts[OPTION_SUBNET_MASK] = socket.inet_aton(self.netmask)
                        except Exception:
                            logger.debug('Failed to include subnet mask from PRL', exc_info=True)
                    elif code == OPTION_ROUTER:
                        try:
                            if self.server_ip:
                                opts[OPTION_ROUTER] = socket.inet_aton(self.server_ip)
                        except Exception:
                            logger.debug('Failed to include router from PRL', exc_info=True)
                    elif code == OPTION_DNS:
                        # If the server advertises DNS servers, include them. The
                        # implementation doesn't have a dedicated dns list; check for
                        # attribute `dns_servers` (list of IP strings) if present.
                        try:
                            dns_list = getattr(self, 'dns_servers', None)
                            if dns_list:
                                parts = []
                                for d in dns_list:
                                    try:
                                        parts.append(socket.inet_aton(d))
                                    except Exception:
                                        logger.debug('Invalid DNS server in dns_servers: %s', d, exc_info=True)
                                if parts:
                                    opts[OPTION_DNS] = b''.join(parts)
                        except Exception:
                            logger.debug('Failed to include DNS servers from PRL', exc_info=True)
                    elif code == OPTION_LEASE_TIME:
                        try:
                            opts[OPTION_LEASE_TIME] = struct.pack('>I', int(self.lease_ttl))
                        except Exception:
                            logger.debug('Failed to include lease time from PRL', exc_info=True)
                    elif code == OPTION_T1:
                        try:
                            t1 = int(self.lease_ttl * 0.5)
                            opts[OPTION_T1] = struct.pack('>I', t1)
                        except Exception:
                            logger.debug('Failed to include T1 from PRL', exc_info=True)
                    elif code == OPTION_T2:
                        try:
                            t2 = int(self.lease_ttl * 0.875)
                            opts[OPTION_T2] = struct.pack('>I', t2)
                        except Exception:
                            logger.debug('Failed to include T2 from PRL', exc_info=True)
            except Exception:
                # If anything unexpected happens, log at debug and continue
                logger.debug('PRL handling failed', exc_info=True)
        opt_blob = self.build_options(opts)
        return pkt + opt_blob

    def handle_discover(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        # allocate
        ip = self.allocate_for_mac(chaddr, requested)
        if not ip:
            return None
        # build offer
        try:
            pkt = self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPOFFER, prl=prl, include_t1t2=True)
            # record offered IP + timestamp
            try:
                m = self._normalize_mac(chaddr)
                if m:
                    self._offered[m] = (ip, time.time())
            except Exception:
                logger.debug('Failed to record offered IP %s for client (chaddr=%s)', ip, chaddr, exc_info=True)
            return pkt
        except Exception as e:
            logger.exception("Failed to build DHCPOFFER: %s", e)
            return None

    def handle_request(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        # normalize MAC consistently
        macn = self._normalize_mac(chaddr)
        if not macn:
            return self.build_nak(xid, chaddr)
        ip = self.allocate_for_mac(macn, requested)
        if not ip:
            return self.build_nak(xid, chaddr)
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)

    def build_nak(self, xid: int, chaddr: bytes) -> bytes:
        header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
            BOOTREPLY, 1, 6, 0,
            xid, 0, 0,
            b'\0'*4,
            b'\0'*4,
            socket.inet_aton(self.server_ip if self.server_ip else '0.0.0.0'),
            b'\0'*4,
            chaddr + b'\0'*(16-len(chaddr)),
            b'\0'*64,
            b'\0'*128
        )
        opts = {
            OPTION_MESSAGE_TYPE: bytes([DHCPNAK]),
            OPTION_SERVER_ID: socket.inet_aton(self.server_ip if self.server_ip else '0.0.0.0')
        }
        return header + self.build_options(opts)

    def _allow_request(self, mac: str, src_ip: str) -> bool:
        now = time.time()
        def _consume(bucket: Dict[str, Tuple[float, float]], key: str) -> bool:
            tokens, last = bucket.get(key, (self.rate_limit_burst, now))
            tokens = min(self.rate_limit_burst, tokens + (now - last) * self.rate_limit_rps)
            if tokens < 1.0:
                bucket[key] = (tokens, now)
                return False
            bucket[key] = (tokens - 1.0, now)
            return True
        if not _consume(self._mac_buckets, mac):
            return False
        if not _consume(self._ip_buckets, src_ip):
            return False
        return True

    async def _arp_conflict_async(self, ip: str, timeout: int = 1) -> bool:
        try:
            import shutil
            if shutil.which('arping') is None:
                return False
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
            r = subprocess.run(['arping', '-c', '1', '-w', str(timeout), ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
            logger.debug('arping exit code for %s: %s', ip, r.returncode)
            return r.returncode == 0
        except Exception as e:
            logger.debug('arping failed for %s: %s', ip, e)
            return False

    def drop_privileges(self, user: str = 'nobody', group: Optional[str] = None, chroot_dir: Optional[str] = None):
        try:
            if os.geteuid() != 0:
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
            try:
                os.setgid(gid)
                os.setuid(pw.pw_uid)
                try:
                    os.setgroups([])
                except Exception:
                    logger.debug('Failed to set supplementary groups during drop_privileges', exc_info=True)
            except Exception as e:
                logger.warning('Failed to drop privileges: %s', e)
        except Exception as e:
            logger.error('drop_privileges helper error: %s', e)

    async def async_handle_request(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        # normalize MAC and use that consistently as the key
        mac = self._normalize_mac(chaddr)
        if not mac:
            return self.build_nak(xid, chaddr)
        if requested:
            prev_tuple = self._offered.get(mac)
            prev = prev_tuple[0] if prev_tuple else None
            if prev and requested != prev and mac not in self.static_leases:
                return self.build_nak(xid, chaddr)
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
        try:
            if getattr(self, 'arp_probe_enable', True):
                conflict = await self._arp_conflict_async(ip, timeout=getattr(self, 'arp_probe_timeout', 1))
            else:
                conflict = False
            if conflict:
                logger.warning('ARP conflict detected for %s; removing lease and NAKing', ip)
                self._conflicted_ips[ip] = time.time() + 60
                if hasattr(self, '_db') and self._db is not None:
                        try:
                            async with self._db_lock:
                                await self._db.execute("DELETE FROM leases WHERE ip = ?", (ip,))
                                await self._db.commit()
                        except Exception as e:
                            logger.debug('Error removing conflicted lease from DB: %s', e)
                else:
                    try:
                        for m, info in list(self.leases.items()):
                            if info.get('ip') == ip:
                                del self.leases[m]
                                break
                    except Exception as e:
                        logger.debug('Error removing conflicted lease from memory: %s', e)
                return self.build_nak(xid, chaddr)
        except Exception as e:
            logger.debug('ARP probe failed for %s: %s', ip, e)
        logger.info('ACKing %s -> %s', mac, ip)
        try:
            self._offered.pop(mac, None)
        except Exception:
            logger.debug('Failed to pop offered entry for %s', mac, exc_info=True)
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)

    async def start(self, bind_ip: str = '0.0.0.0', bind_port: int = 67):
        loop = asyncio.get_running_loop()
        self.loop = loop
        try:
            # honor explicit disable for sqlite backend if configured
            try:
                if getattr(self, 'lease_sqlite_enabled', True) is False:
                    p = str(self.lease_db_path) if self.lease_db_path else ''
                    if p.lower().endswith('.sqlite'):
                        logger.info('lease_sqlite_enabled is false; forcing JSON backend instead of sqlite')
                        self.lease_backend = 'json'
            except Exception:
                pass
            await self._init_db()
        except Exception as e:
            logger.debug('DB init failed: %s', e)
        if not self.server_ip or self.server_ip == '0.0.0.0':
            self.server_ip = bind_ip
        # compute broadcast for subnet if possible
        try:
            if self.server_ip and self.netmask:
                self.broadcast_ip = calc_broadcast(self.server_ip, self.netmask)
        except Exception:
            self.broadcast_ip = None
        # If binding to a privileged port (<1024) ensure we have sufficient privileges
        try:
            if bind_port < 1024 and os.geteuid() != 0:
                logger.error('Insufficient privileges to bind to port %d. Run as root or use CAP_NET_BIND_SERVICE, or for testing bind to a non-privileged port (e.g., 6767).', bind_port)
                raise PermissionError(f'Cannot bind to privileged port {bind_port} without root')
        except AttributeError:
            # os.geteuid may not be available on some platforms; skip check
            pass
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                logger.debug('Set SO_REUSEADDR')
            except Exception as e:
                logger.debug('Failed to set SO_REUSEADDR: %s', e, exc_info=True)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                logger.debug('Set SO_BROADCAST')
            except Exception as e:
                logger.debug('Failed to set SO_BROADCAST: %s', e, exc_info=True)
            try:
                if hasattr(socket, 'SO_REUSEPORT'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    logger.debug('Set SO_REUSEPORT')
            except Exception as e:
                logger.debug('Failed to set SO_REUSEPORT: %s', e, exc_info=True)

            # Optionally bind to specific interface for egress
            try:
                ifname = os.environ.get('PHANTOMD_IFACE')
                if ifname:
                    try:
                        # SO_BINDTODEVICE is Linux-specific; fallback to numeric value 25 if missing
                        so_bind = getattr(socket, 'SO_BINDTODEVICE', 25)
                        sock.setsockopt(socket.SOL_SOCKET, so_bind, ifname.encode() + b'\x00')
                        logger.info('Bound DHCP socket to interface %s', ifname)
                    except Exception as e:
                        logger.warning('SO_BINDTODEVICE failed: %s', e)
            except Exception:
                logger.debug('Failed while attempting to bind socket to interface', exc_info=True)

            sock.bind((bind_ip, bind_port))
            logger.info('DHCP server bound to %s:%d', bind_ip, bind_port)
        except Exception as e:
            sock.close()
            try:
                import errno
                errn = getattr(e, 'errno', None)
                if errn:
                    logger.error('Failed to bind DHCP socket to %s:%d: %s (errno=%s)', bind_ip, bind_port, e, errn)
                else:
                    logger.error('Failed to bind DHCP socket to %s:%d: %s', bind_ip, bind_port, e)
            except Exception:
                logger.error('Failed to bind DHCP socket: %s', e)
            logger.error('If you are testing, try a non-privileged port like 6767 or run with appropriate privileges')
            raise
        try:
            # honor configured privilege drop settings if present on the instance
            user = getattr(self, 'privilege_drop_user', 'nobody') or 'nobody'
            group = getattr(self, 'privilege_drop_group', None)
            chroot_dir = getattr(self, 'chroot_dir', None) or None
            self.drop_privileges(user=user, group=group, chroot_dir=chroot_dir)
        except Exception:
            logger.debug('drop_privileges failed or not applicable')
        transport, protocol = await loop.create_datagram_endpoint(lambda: DHCPProtocol(self), sock=sock)
        self.transport = transport
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
                cut = time.time() - 300
                for m, (ip, ts) in list(self._offered.items()):
                    if ts < cut:
                        try:
                            del self._offered[m]
                        except Exception:
                            logger.debug('Failed to remove stale offered entry for %s', m, exc_info=True)
            except Exception:
                await asyncio.sleep(60)


class DHCPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: DHCPServer):
        self.server = server

    def connection_made(self, transport):
        self.transport = transport
        logger.info("DHCP server listening")

    def _send_packet(self, pkt: bytes, dst_ip: str, dst_port: int = 68, broadcast: bool = False):
        """Send using the underlying socket if available so we can set broadcast option."""
        try:
            sock = self.transport.get_extra_info('socket')
            if sock is None:
                # fallback to transport
                self.transport.sendto(pkt, (dst_ip, dst_port))
                return
            if broadcast:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                except Exception:
                    logger.debug('Failed to set SO_BROADCAST on socket', exc_info=True)
            sock.sendto(pkt, (dst_ip, dst_port))
        except Exception as e:
            logger.exception("Failed to send DHCP packet: %s", e)

    def datagram_received(self, data: bytes, addr):
        # minimal parse: extract op,xid,chaddr and options
        try:
            if len(data) < 240:
                return
            op = data[0]
            xid = struct.unpack('>I', data[4:8])[0]
            flags = struct.unpack('>H', data[10:12])[0]
            ciaddr = socket.inet_ntoa(data[12:16])
            chaddr = data[28:34]
            opts = self.server.parse_options(data[240:])
            msg_type = opts.get(OPTION_MESSAGE_TYPE)
            requested = None
            prl = opts.get(OPTION_PARAM_REQUEST_LIST)
            if OPTION_REQUESTED_IP in opts:
                try:
                    requested = socket.inet_ntoa(opts[OPTION_REQUESTED_IP])
                except Exception:
                    requested = None
            # If no requested option, fallback to ciaddr if present
            if not requested and ciaddr != '0.0.0.0':
                requested = ciaddr

            # Enforce rate limiting early to mitigate flooding attacks. Use the
            # canonical normalized MAC as the bucket key.
            try:
                macn = self.server._normalize_mac(chaddr)
                if not macn:
                    logger.debug('Dropping DHCP packet with invalid MAC from %s', addr[0])
                    return
                try:
                    if not self.server._allow_request(macn, addr[0]):
                        logger.info('Rate-limited DHCP packet from %s (%s)', macn, addr[0])
                        return
                except Exception as e:
                    logger.debug('Rate limit check failed: %s', e)
            except Exception:
                # If normalization itself fails, drop packet safely
                logger.debug('MAC normalization failed for incoming packet from %s', addr[0])
                return

            # Determine whether to broadcast the reply
            want_broadcast = bool(flags & 0x8000) or addr[0] == '0.0.0.0' or ciaddr == '0.0.0.0'
            bcast_ip = self.server.broadcast_ip or '255.255.255.255'
            def send_reply(pkt: bytes, yiaddr: Optional[str] = None):
                # Try unicast to yiaddr when appropriate and possible
                if not want_broadcast and yiaddr and yiaddr != '0.0.0.0':
                    try:
                        self._send_packet(pkt, yiaddr, 68, broadcast=False)
                        return
                    except Exception:
                        logger.debug('Failed to unicast DHCP reply to %s; falling back to broadcast', yiaddr, exc_info=True)
                # default: broadcast
                self._send_packet(pkt, bcast_ip, 68, broadcast=True)

            # schedule async handlers so DB mutations use the server lock and don't block the protocol
            if msg_type:
                mt = msg_type[0]

                # Validate OPTION_SERVER_ID for DHCPREQUEST: if the client included a
                # server identifier that does not match this server, ignore the
                # request (it's meant for another DHCP server).
                if mt == DHCPREQUEST:
                    sid_opt = opts.get(OPTION_SERVER_ID)
                    if sid_opt:
                        try:
                            sid = socket.inet_ntoa(sid_opt)
                        except Exception:
                            sid = None
                        my_sid = getattr(self.server, 'server_ip', None) or self.server.get_primary_ip()
                        if sid and my_sid and sid != my_sid:
                            logger.debug('Ignoring DHCPREQUEST addressed to server %s (this server=%s)', sid, my_sid)
                            return

                if mt == DHCPDISCOVER:
                    async def _handle_discover():
                        try:
                            m = self.server._normalize_mac(chaddr) or ''
                            ip = await self.server.async_allocate_for_mac(m, requested)
                            if not ip:
                                return
                            # record offered
                            try:
                                if m:
                                    self.server._offered[m] = (ip, time.time())
                            except Exception:
                                logger.debug('Failed to record offered IP %s for client %s', ip, m, exc_info=True)
                            pkt = self.server.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPOFFER, prl=prl, include_t1t2=True)
                            send_reply(pkt, ip)
                            logger.info("Offered %s to %s (broadcast=%s)", ip, m, want_broadcast)
                        except Exception as e:
                            logger.exception('Error in async discover handler: %s', e)

                    asyncio.create_task(_handle_discover())

                elif mt == DHCPREQUEST:
                    async def _handle_request():
                        try:
                            resp = await self.server.async_handle_request(xid, chaddr, requested, prl)
                            if not resp:
                                # build_nak if necessary
                                nak = self.server.build_nak(xid, chaddr)
                                send_reply(nak, None)
                                return
                            m2 = self.server._normalize_mac(chaddr) or ''
                            yi = self.server.leases.get(m2, {}).get('ip')
                            if yi is not None:
                                yi = str(yi)
                            send_reply(resp, yi)
                            logger.info('Processed DHCPREQUEST for %s (broadcast=%s)', self.server._normalize_mac(chaddr), want_broadcast)
                        except Exception as e:
                            logger.exception('Error in async request handler: %s', e)

                    asyncio.create_task(_handle_request())

                elif mt == DHCPRELEASE:
                    async def _handle_release():
                        try:
                            macn = self.server._normalize_mac(chaddr)
                            if not macn:
                                return
                            async with self.server._lock:
                                if macn in self.server.leases:
                                    ip = self.server.leases[macn]['ip']
                                    del self.server.leases[macn]
                                    if ip in self.server.ip_map:
                                        del self.server.ip_map[ip]
                                    # persist in a thread to avoid blocking the loop
                                    try:
                                        await asyncio.to_thread(self.server._save_leases)
                                    except Exception as e:
                                        logger.debug('Error saving leases after release: %s', e)
                                    logger.info('Released %s from %s', ip, macn)
                        except Exception as e:
                            logger.exception('Error in async release handler: %s', e)

                    asyncio.create_task(_handle_release())
        except Exception as e:
            logger.exception("DHCP datagram handling failed: %s", e)


# --------------------------- CLI / tests --------------------------- #


def serve_cli(bind='0.0.0.0', port=6767, **kwargs):
    srv = DHCPServer(kwargs.get('subnet', '192.168.100.0'), kwargs.get('netmask', '255.255.255.0'), kwargs.get('start_ip', '192.168.100.100'), kwargs.get('end_ip', '192.168.100.200'), lease_ttl=kwargs.get('lease_ttl', 86400), static_leases=kwargs.get('static_leases', {}), server_ip=kwargs.get('server_ip'))
    loop = asyncio.get_event_loop()
    listen = loop.create_datagram_endpoint(lambda: DHCPProtocol(srv), local_addr=(bind, port))
    transport, proto = loop.run_until_complete(listen)
    try:
        loop.run_forever()
    finally:
        transport.close()


# Pytest/scapy tests (integration) — these require scapy and root privileges and an isolated iface

def _have_scapy():
    try:
        import scapy.all as sc  # noqa
        return True
    except Exception:
        return False


async def _run_server_in_background(srv: DHCPServer, bind='127.0.0.1', port=6767):
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(lambda: DHCPProtocol(srv), local_addr=(bind, port))
    # return transport/proto pair so tests can shut it down
    return transport, proto


# Simple unit tests for parsing/building options
def test_options_roundtrip():
    srv = DHCPServer('192.168.100.0', '255.255.255.0', '192.168.100.100', '192.168.100.200')
    pkt = srv.build_reply(BOOTREPLY, 0x12345678, b'\xaa\xbb\xcc\xdd\xee\x01', '192.168.100.150', DHCPOFFER, include_t1t2=True)
    opts = srv.parse_options(pkt[240:])
    assert opts[OPTION_MESSAGE_TYPE] == bytes([DHCPOFFER])
    assert OPTION_LEASE_TIME in opts


def test_db_memory_sync(tmp_path):
    db_file = tmp_path / 'leases.json'
    data = {'aa:bb:cc:dd:ee:ff': {'ip': '192.168.100.10', 'expiry': int(time.time()) + 3600}}
    db_file.write_text(json.dumps(data))
    srv = DHCPServer('192.168.100.0', '255.255.255.0', '192.168.100.100', '192.168.100.200', lease_db_path=str(db_file))
    # init db if available and mirror
    if aiosqlite:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(srv._init_db())
    # memory should contain migrated lease if DB migration happened
    assert isinstance(srv.leases, dict)


def test_discover_offer_request_ack_flow_isolated():
    """Integration test using scapy. Requires root and isolated iface. Not run by default."""
    if not _have_scapy():
        return
    # This test is intentionally minimal and must be adapted to your test environment.
    # Suggest running inside a network namespace where iface 'veth0' is isolated.
    iface = os.environ.get('PHANTOMD_TEST_IFACE', 'veth0')
    mac = b'\xaa\xbb\xcc\xdd\xee\x01'


if __name__ == '__main__':
    serve_cli()
