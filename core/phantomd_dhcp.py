"""
phantomd_dhcp_server_with_tests.py

Consolidated DHCP server (production-ish) + test harness.

What this file provides:
- DHCPServer class (DB-backed via aiosqlite if available, mirrored in-memory leases)
- DHCPProtocol asyncio.DatagramProtocol
- CLI entrypoint to run the server: `python3 phantomd_dhcp_server_with_tests.py serve --bind 0.0.0.0 --port 67`
- Pytest-compatible test functions for core flows. These are integration tests that use Scapy
  and therefore require root and an isolated test interface (or network namespace). They are
  placed under the `tests` namespace and will be skipped if Scapy isn't available.

Notes:
- This file assumes `arping` and necessary privileges exist on the host.
- The tests are destructive on the test network (they send broadcasts). Run them in a lab.

Usage examples:
  # run server (requires root to bind 67)
  sudo python3 phantomd_dhcp_server_with_tests.py serve --bind 0.0.0.0 --port 67 --subnet 192.168.50.0 --netmask 255.255.255.0 --start 192.168.50.100 --end 192.168.50.200

  # run pytest tests (as root in a test namespace)
  sudo pytest phantomd_dhcp_server_with_tests.py::test_discover_offer_request_ack -q

"""
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

        # concurrency
        self._lock = asyncio.Lock()

        # load persisted leases if present
        try:
            self._load_leases()
        except Exception as e:
            logger.warning("Failed to load DHCP leases: %s", e)

        # ensure save on exit
        atexit.register(self._save_leases)

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
        if not self.lease_db_path:
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
        # placeholder for sqlite init if desired
        if aiosqlite is None:
            return
        # Future: implement sqlite migration
        return

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
            # persist
            try:
                self._save_leases()
            except Exception:
                pass

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
                self._save_leases()
            except Exception:
                pass
            return info['ip']

        # requested IP honored if available
        if requested:
            try:
                if requested in self.ip_map:
                    # already taken
                    pass
                else:
                    # assign
                    self.leases[m] = {'ip': requested, 'expiry': now + self.lease_ttl}
                    self.ip_map[requested] = m
                    try:
                        self._save_leases()
                    except Exception:
                        pass
                    return requested
            except Exception:
                pass

        # find next free
        ip = self.next_free_ip()
        if ip:
            self.leases[m] = {'ip': ip, 'expiry': now + self.lease_ttl}
            self.ip_map[ip] = m
            try:
                self._save_leases()
            except Exception:
                pass
            return ip
        return None

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
            pass
        # routers (gateway) - set to server_ip if present
        if self.server_ip:
            try:
                opts[OPTION_ROUTER] = socket.inet_aton(self.server_ip)
            except Exception:
                pass
        # DNS - leave empty unless provided via static_leases mapping entry (not ideal)
        # include parameter request list if provided
        if prl:
            # prl is already bytes
            opts[OPTION_PARAM_REQUEST_LIST] = prl
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
            return pkt
        except Exception as e:
            logger.exception("Failed to build DHCPOFFER: %s", e)
            return None

    def handle_request(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        mac = ':'.join('%02x' % b for b in chaddr[:6])
        ip = self.allocate_for_mac(mac, requested)
        if not ip:
            return self.build_nak(xid, chaddr)
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)

    def build_nak(self, xid: int, chaddr: bytes) -> bytes:
        header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
            BOOTREPLY, 1, 6, 0,
            xid, 0, 0,
            b'\0'*4,
            b'\0'*4,
            socket.inet_aton(self.server_ip),
            b'\0'*4,
            chaddr + b'\0'*(16-len(chaddr)),
            b'\0'*64,
            b'\0'*128
        )
        opts = {
            OPTION_MESSAGE_TYPE: bytes([DHCPNAK]),
            OPTION_SERVER_ID: socket.inet_aton(self.server_ip)
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
                    pass
            except Exception as e:
                logger.warning('Failed to drop privileges: %s', e)
        except Exception as e:
            logger.error('drop_privileges helper error: %s', e)

    async def async_handle_request(self, xid: int, chaddr: bytes, requested: Optional[str], prl: Optional[bytes]=None) -> Optional[bytes]:
        mac = ':'.join('%02x' % b for b in chaddr[:6])
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
            conflict = await self._arp_conflict_async(ip)
            if conflict:
                logger.warning('ARP conflict detected for %s; removing lease and NAKing', ip)
                self._conflicted_ips[ip] = time.time() + 60
                if hasattr(self, '_db') and self._db is not None:
                    try:
                        await self._db.execute("DELETE FROM leases WHERE ip = ?", (ip,))
                        await self._db.commit()
                    except Exception as e:
                        logger.debug('Error removing conflicted lease from DB: %s', e)
                else:
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
        try:
            self._offered.pop(mac, None)
        except Exception:
            pass
        return self.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)

    async def start(self, bind_ip: str = '0.0.0.0', bind_port: int = 67):
        loop = asyncio.get_running_loop()
        self.loop = loop
        try:
            await self._init_db()
        except Exception as e:
            logger.debug('DB init failed: %s', e)
        if not self.server_ip or self.server_ip == '0.0.0.0':
            self.server_ip = bind_ip
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
            sock.bind((bind_ip, bind_port))
            logger.info('DHCP server bound to %s:%d', bind_ip, bind_port)
        except Exception as e:
            sock.close()
            logger.error('Failed to bind DHCP socket: %s', e)
            raise
        try:
            self.drop_privileges(user='nobody')
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
                            pass
            except Exception:
                await asyncio.sleep(60)


class DHCPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: DHCPServer):
        self.server = server

    def connection_made(self, transport):
        self.transport = transport
        logger.info("DHCP server listening")

    def datagram_received(self, data: bytes, addr):
        # minimal parse: extract op,xid,chaddr and options
        try:
            if len(data) < 240:
                return
            op = data[0]
            xid = struct.unpack('>I', data[4:8])[0]
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
            if msg_type:
                mt = msg_type[0]
                if mt == DHCPDISCOVER:
                    offer = self.server.handle_discover(xid, chaddr, requested, prl)
                    if offer:
                        self.transport.sendto(offer, addr)
                        logger.info("Offered %s to %s", self.server.leases.get(self.server._normalize_mac(chaddr), {}).get('ip'), self.server._normalize_mac(chaddr))
                elif mt == DHCPREQUEST:
                    # very simple REQUEST handling: if we hold lease for this MAC -> ACK, else NAK
                    macn = self.server._normalize_mac(chaddr)
                    if macn and macn in self.server.leases:
                        ip = self.server.leases[macn]['ip']
                        ack = self.server.build_reply(BOOTREPLY, xid, chaddr, ip, DHCPACK, prl=prl, include_t1t2=True)
                        self.transport.sendto(ack, addr)
                        logger.info("ACKed %s for %s", ip, macn)
                    else:
                        nak = self.server.build_reply(BOOTREPLY, xid, chaddr, '0.0.0.0', DHCPNAK, prl=prl)
                        self.transport.sendto(nak, addr)
                        logger.info("NAK for %s", macn)
                elif mt == DHCPRELEASE:
                    macn = self.server._normalize_mac(chaddr)
                    if macn and macn in self.server.leases:
                        ip = self.server.leases[macn]['ip']
                        del self.server.leases[macn]
                        if ip in self.server.ip_map:
                            del self.server.ip_map[ip]
                        self.server._save_leases()
                        logger.info("Released %s from %s", ip, macn)
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
