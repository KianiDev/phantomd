import asyncio
import logging
import socket
import ssl
import struct
import time
import hashlib
import ipaddress
import os
from typing import Optional, Tuple, Any, Set, Dict, Union, List, Callable, Coroutine, Iterable
from urllib.parse import urlparse

try:
    from cachetools import TTLCache
    _HAS_CACHETOOLS = True
except Exception:
    _HAS_CACHETOOLS = False
    TTLCache = None

try:
    import aioquic.asyncio
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    _HAS_AIOQUIC = True
except Exception:
    aioquic = None
    QuicConfiguration = None
    QuicConnection = None
    _HAS_AIOQUIC = False

# optional prometheus
try:
    from prometheus_client import Counter, Histogram
    _HAS_PROM = True
except Exception:
    Counter = None
    Histogram = None
    _HAS_PROM = False

# optional dnspython for DNSSEC
try:
    import dns.message
    import dns.dnssec
    import dns.name
    import dns.resolver
    import dns.rdatatype
    _HAS_DNSPY = True
except Exception:
    dns = None
    _HAS_DNSPY = False

# optional uvloop helper (not auto-enabled)
try:
    import uvloop
    _HAS_UVLOOP = True
except Exception:
    uvloop = None
    _HAS_UVLOOP = False


class AsyncTTLCache:
    """Async-capable TTL cache with optional size limit."""
    def __init__(self, maxsize: int = 1024, ttl: int = 300) -> None:
        self._data: Dict[str, Tuple[Any, float]] = {}
        self._ttl: int = ttl
        self._max: int = maxsize
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            value, expire = v
            if time.time() >= expire:
                del self._data[key]
                return None
            return value

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if len(self._data) >= self._max:
                oldest = min(self._data.items(), key=lambda kv: kv[1][1])[0]
                del self._data[oldest]
            self._data[key] = (value, time.time() + self._ttl)

    async def delete(self, key: str) -> None:
        async with self._lock:
            try:
                if key in self._data:
                    del self._data[key]
            except Exception:
                pass


class RateLimiter:
    """Token-bucket rate limiter for DNS queries (per IP)."""
    def __init__(self, rate: float, burst: float) -> None:
        self.rate: float = rate
        self.burst: float = burst
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    async def is_allowed(self, key: str) -> bool:
        async with self._lock:
            now = time.time()
            tokens, last = self._buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return True
            self._buckets[key] = (tokens, now)
            return False


class ConnectionPool:
    """A simple connection pool for TCP and TLS connections."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        async with self._lock:
            if key in self._pools:
                while self._pools[key]:
                    reader, writer, _ = self._pools[key].pop()
                    if not writer.is_closing():
                        return reader, writer
                    try:
                        writer.close()
                    except Exception:
                        pass
        return None

    async def put(self, key: Tuple, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._lock:
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                return

            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) < self.max_size:
                self._pools[key].append((reader, writer, time.time()))
            else:
                writer.close()

    async def start_cleanup(self) -> None:
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    keys_to_purge = []
                    for key in list(self._pools.keys()):
                        keep = []
                        for reader, writer, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout or writer.is_closing():
                                try:
                                    writer.close()
                                except Exception:
                                    pass
                            else:
                                keep.append((reader, writer, last_used))
                        if keep:
                            self._pools[key] = keep
                        else:
                            keys_to_purge.append(key)
                    for key in keys_to_purge:
                        del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
        async with self._lock:
            for key in list(self._pools.values()):
                for _, writer, _ in key:
                    try:
                        writer.close()
                    except Exception:
                        pass
            self._pools.clear()


class ClientPool:
    """A pool that holds arbitrary client objects (httpx clients, QUIC connections, etc.)."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[Any, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[Any]:
        async with self._lock:
            if key in self._pools and self._pools[key]:
                client, _ = self._pools[key].pop()
                return client
        return None

    async def put(self, key: Tuple, client: Any) -> None:
        async with self._lock:
            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) < self.max_size:
                self._pools[key].append((client, time.time()))
            else:
                await self._close_client(client)

    async def start_cleanup(self) -> None:
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    for key in list(self._pools.keys()):
                        keep = []
                        for client, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout:
                                await self._close_client(client)
                            else:
                                keep.append((client, last_used))
                        self._pools[key] = keep
                        if not self._pools[key]:
                            del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
        async with self._lock:
            for key in list(self._pools.values()):
                for client, _ in key:
                    await self._close_client(client)
            self._pools.clear()

    async def _close_client(self, client: Any) -> None:
        try:
            if hasattr(client, 'aclose'):
                await client.aclose()
            elif hasattr(client, 'close'):
                if hasattr(client, 'close'):
                    client.close()
                if hasattr(client, '_transport'):
                    client._transport.close()
        except Exception:
            pass


class DNSResolver:
    """Async, robust DNS resolver/forwarder supporting UDP/TCP/DoT/DoH/DoH2/DoH3/DoQ.

    Features:
      - Async TTL cache (cachetools or internal async cache)
      - Per-protocol timeouts and retry/backoff
      - DoH over TLS with SNI preserved (manual HTTP/1.1, HTTP/2, HTTP/3)
      - Optional certificate pinning and DNSSEC validation
      - Optional Prometheus metrics and uvloop enable
      - Integrated rate limiter (per client IP)
      - Multi-upstream with automatic failover (configurable upstream list)
      - Optimistic caching (serve-stale per RFC 8767)
      - DNS rebinding protection (strip or block private IPs)
      - Connection pooling for TCP, TLS, HTTP/2, HTTP/3, and DoQ

    Logging:
      The resolver emits DEBUG logs for cache hits/misses, request lifecycle,
      retries, and validation steps. Enable verbose=True to see DEBUG output.
    """

    def __init__(self,
                  upstream_dns: str,
                  protocol: str = "udp",
                  dns_resolver_server: Optional[str] = None,
                  verbose: bool = False,
                  disable_ipv6: bool = False,
                  cache_ttl: int = 300,
                  cache_max_size: int = 2048,
                  doh_timeout: float = 5.0,
                  udp_timeout: float = 2.0,
                  tcp_timeout: float = 5.0,
                  retries: int = 2,
                  dns_logging_enabled: bool = False,
                  dns_log_dir: str = "/var/log/phantomd",
                  pinned_certs: Optional[Dict[str, str]] = None,
                  dnssec_enabled: bool = False,
                  trust_anchors: Optional[Union[Dict[str, str], str]] = None,
                  metrics_enabled: bool = False,
                  metrics_port: int = 8000,
                  uvloop_enable: bool = False,
                  rate_limit_rps: float = 0.0,
                  rate_limit_burst: float = 0.0,
                  upstreams: Optional[List[Dict[str, Any]]] = None,
                  optimistic_cache_enabled: bool = False,
                  optimistic_stale_max_age: int = 86400,
                  optimistic_stale_response_ttl: int = 30,
                  rebind_protection_enabled: bool = False,
                  rebind_action: str = 'strip',
                  pool_max_size: int = 5,
                  pool_idle_timeout: float = 60.0,
                  doh_version: str = 'auto',
                  doh_auto_cache_ttl: int = 3600) -> None:
        # --- single upstream fallback ---
        self.upstream_dns: str = upstream_dns
        self.protocol: str = protocol.lower()
        # --- multi-upstream list (optional) ---
        self.upstreams: List[Dict[str, Any]] = upstreams or []

        self.dns_resolver_server: Optional[str] = dns_resolver_server
        self.disable_ipv6: bool = bool(disable_ipv6)
        self.verbose: bool = bool(verbose)
        self.logger: logging.Logger = logging.getLogger("phantomd.DNSResolver")
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.logger.addHandler(h)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        # cache
        if _HAS_CACHETOOLS:
            self._dns_cache: Any = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache: Any = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._cache_is_sync: bool = True
        else:
            self._dns_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._cache_is_sync: bool = False

        self._lock: asyncio.Lock = asyncio.Lock()

        self.doh_timeout: float = doh_timeout
        self.udp_timeout: float = udp_timeout
        self.tcp_timeout: float = tcp_timeout
        self.retries: int = max(1, int(retries))

        self.dns_logging_enabled: bool = dns_logging_enabled
        if dns_logging_enabled:
            try:
                import os
                from logging.handlers import TimedRotatingFileHandler
                os.makedirs(dns_log_dir, exist_ok=True)
                fh = TimedRotatingFileHandler(f"{dns_log_dir}/dns-requests.log", when="midnight", backupCount=7)
                fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
                flog = logging.getLogger("phantomd.DNSRequests")
                flog.setLevel(logging.INFO)
                if not any(isinstance(h, TimedRotatingFileHandler) for h in flog.handlers):
                    flog.addHandler(fh)
                self._file_logger: Optional[logging.Logger] = flog
            except Exception as e:
                self.logger.warning("Failed to init file logger: %s", e)
                self._file_logger = None
        else:
            self._file_logger = None

        self.pinned_certs: Dict[str, str] = pinned_certs or {}
        self.dnssec_enabled: bool = bool(dnssec_enabled)
        self.trust_anchors: Any = trust_anchors or {}
        self._dnssec_raw_anchors: Optional[Any] = None
        self._dnssec_keyring: Optional[Any] = None

        self.metrics_enabled: bool = bool(metrics_enabled) and _HAS_PROM
        self._metrics: Optional[Dict[str, Any]] = None
        if self.metrics_enabled:
            try:
                self._metrics = {
                    'requests_total': Counter('phantomd_dns_requests_total', 'Total DNS upstream requests', ['proto']),
                    'requests_errors': Counter('phantomd_dns_request_errors_total', 'Failed DNS upstream requests', ['proto']),
                    'request_latency_seconds': Histogram('phantomd_dns_request_latency_seconds', 'Upstream request latency seconds', ['proto'])
                }
                try:
                    from prometheus_client import start_http_server
                    try:
                        start_http_server(int(metrics_port))
                        self.logger.info("Prometheus metrics server started on :%s", metrics_port)
                    except Exception as e:
                        self.logger.debug("Could not start prometheus http server on %s: %s", metrics_port, e)
                except Exception as e:
                    self.logger.debug("Could not start prometheus http server: %s", e)
            except Exception:
                self._metrics = None

        if uvloop_enable and _HAS_UVLOOP:
            try:
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                self.logger.info("uvloop enabled")
            except Exception as e:
                self.logger.warning("Failed to enable uvloop: %s", e)

        self._blocklist_exact: Set[str] = set()
        self._blocklist_suffix: Set[str] = set()
        self._hosts_map: Dict[str, Tuple[str, ...]] = {}
        self._block_action: str = 'NXDOMAIN'

        # --- Rate limiter ---
        self.rate_limit_rps: float = rate_limit_rps
        self.rate_limit_burst: float = rate_limit_burst
        if rate_limit_rps > 0 and rate_limit_burst > 0:
            self.rate_limiter: Optional[RateLimiter] = RateLimiter(rate_limit_rps, rate_limit_burst)
        else:
            self.rate_limiter = None

        # --- Optimistic caching ---
        self.optimistic_cache_enabled: bool = optimistic_cache_enabled
        self.stale_max_age: int = optimistic_stale_max_age
        self.stale_response_ttl: int = optimistic_stale_response_ttl
        self._stale_refresh_pending: Set[str] = set()
        self._stale_refresh_lock: asyncio.Lock = asyncio.Lock()

        # --- DNS rebinding protection ---
        self.rebind_protection_enabled: bool = rebind_protection_enabled
        self.rebind_action: str = rebind_action

        # --- Connection pools ---
        self._tcp_pool: ConnectionPool = ConnectionPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._h2_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._h3_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._quic_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)

        # --- DoH version negotiation ---
        self.doh_version: str = doh_version
        self.doh_auto_cache_ttl: int = doh_auto_cache_ttl
        self._doh_auto_cache: Dict[str, Tuple[str, float]] = {}
        self._doh_auto_lock: asyncio.Lock = asyncio.Lock()

    # ---------- blocklist helpers ----------
    def set_blocklist(self, domains: Iterable[str]) -> None:
        self._blocklist_exact.clear()
        self._blocklist_suffix.clear()
        for d in domains:
            d = d.strip().lower().rstrip('.')
            if not d:
                continue
            if d.startswith("."):
                self._blocklist_suffix.add(d.lstrip("."))
            else:
                self._blocklist_exact.add(d)

    def set_hosts_map(self, hosts_map: Dict[str, Tuple[str, ...]]) -> None:
        self._hosts_map = {k.lower().rstrip('.'): tuple(v) for k, v in (hosts_map or {}).items()}

    def get_host_for(self, qname: str) -> Optional[Tuple[str, ...]]:
        if not qname:
            return None
        return self._hosts_map.get(qname.lower().rstrip('.'))

    def add_blocked(self, domain: str) -> None:
        d = domain.strip().lower().rstrip('.')
        if d.startswith("."):
            self._blocklist_suffix.add(d.lstrip("."))
        else:
            self._blocklist_exact.add(d)

    @staticmethod
    def load_blocklists_from_dir(directory: str) -> Tuple[Set[str], Set[str], Dict[str, Tuple[str, ...]]]:
        exact_set: Set[str] = set()
        suffix_set: Set[str] = set()
        hosts_map: Dict[str, Tuple[str, ...]] = {}
        if not os.path.isdir(directory):
            return exact_set, suffix_set, hosts_map
        for fname in os.listdir(directory):
            path = os.path.join(directory, fname)
            if not os.path.isfile(path):
                continue
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.split('#', 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) == 0:
                        continue
                    if len(parts) >= 2 and (parts[0].count('.') == 3 or ':' in parts[0]):
                        ip = parts[0]
                        domain = parts[1].lower().rstrip('.')
                        hosts_map[domain] = (ip,)
                        exact_set.add(domain)
                        continue
                    domain = parts[0].lower().rstrip('.')
                    if domain.startswith('.'):
                        suffix_set.add(domain.lstrip('.'))
                    else:
                        exact_set.add(domain)
        return exact_set, suffix_set, hosts_map

    def is_blocked(self, qname: Optional[str]) -> bool:
        if not qname:
            return False
        q = qname.lower().rstrip('.')
        if q in self._blocklist_exact:
            return True
        for suf in self._blocklist_suffix:
            if q == suf or q.endswith("." + suf):
                return True
        return False

    # ---------- wire-cache helpers (extended for optimistic caching) ----------
    async def _wire_cache_get(self, key: Tuple[str, int, str]) -> Optional[Tuple[bytes, float, bytes, float]]:
        try:
            async with self._lock:
                if self._cache_is_sync:
                    return self._wire_cache.get(key)  # type: ignore[attr-defined]
                else:
                    return await self._wire_cache.get(key)  # type: ignore[attr-defined]
        except Exception as e:
            self.logger.debug("wire cache get error %s: %s", key, e)
            return None

    async def _wire_cache_set(self, key: Tuple[str, int, str], response_bytes: bytes,
                              ttl_seconds: int, query_data: bytes) -> None:
        try:
            expiry = time.time() + max(0, int(ttl_seconds or 0))
            stale_until = expiry + self.stale_max_age if self.optimistic_cache_enabled else expiry
            val = (response_bytes, expiry, query_data, stale_until)
            async with self._lock:
                if self._cache_is_sync:
                    self._wire_cache[key] = val  # type: ignore[index]
                else:
                    await self._wire_cache.set(key, val)  # type: ignore[attr-defined]
            self.logger.debug("wire cache set %s ttl=%s stale_until=%s", key, ttl_seconds, stale_until)
        except Exception as e:
            self.logger.debug("wire cache set error %s: %s", key, e)

    async def _wire_cache_get_valid(self, key: Tuple[str, int, str]) -> Optional[bytes]:
        try:
            async with self._lock:
                entry = await self._wire_cache_get(key) if not self._cache_is_sync else self._wire_cache.get(key)
                if entry is None:
                    return None
                if isinstance(entry, bytes):
                    return entry
                if isinstance(entry, tuple) and len(entry) == 4:
                    resp_bytes, expiry, query_data, stale_until = entry
                    now = time.time()
                    if now < expiry:
                        return resp_bytes
                    if self.optimistic_cache_enabled and now < stale_until:
                        self.logger.debug("serving stale response for %s (age=%.1fs)", key, now - expiry)
                        stale_resp = self._set_response_ttl(resp_bytes, self.stale_response_ttl)
                        await self._maybe_refresh_stale(key, query_data)
                        return stale_resp
                    if self._cache_is_sync:
                        del self._wire_cache[key]  # type: ignore[attr-defined]
                    else:
                        await self._wire_cache.delete(key)  # type: ignore[attr-defined]
                    return None
                return None
        except Exception:
            return None

    async def _maybe_refresh_stale(self, key: Tuple[str, int, str], query_data: bytes) -> None:
        async with self._stale_refresh_lock:
            if key in self._stale_refresh_pending:
                return
            self._stale_refresh_pending.add(key)
        asyncio.create_task(self._background_refresh(key, query_data))

    async def _background_refresh(self, key: Tuple[str, int, str], query_data: bytes) -> None:
        try:
            upstream_list = self.upstreams if self.upstreams else [
                {'address': self.upstream_dns, 'protocol': self.protocol, 'hostname': self.upstream_dns}
            ]
            last_exc = None
            for upstream in upstream_list:
                try:
                    resp = await self._try_upstream(upstream, query_data)
                    if self.dnssec_enabled:
                        qname = key[0] if key[0] else None
                        if qname:
                            try:
                                await self._dnssec_validate(qname, resp)
                            except Exception as e:
                                self.logger.warning("DNSSEC validation failed for stale refresh %s: %s", key, e)
                                continue
                    ttl = self._extract_min_ttl(resp)
                    if ttl <= 0:
                        ttl = 30
                    await self._wire_cache_set(key, resp, ttl, query_data)
                    self.logger.debug("stale refresh succeeded for %s from %s", key, upstream['address'])
                    return
                except Exception as e:
                    last_exc = e
                    self.logger.debug("stale refresh upstream %s failed: %s", upstream['address'], e)
            self.logger.warning("stale refresh failed for %s: %s", key, last_exc)
        finally:
            async with self._stale_refresh_lock:
                self._stale_refresh_pending.discard(key)

    def _set_response_ttl(self, response_bytes: bytes, ttl: int) -> bytes:
        if _HAS_DNSPY:
            try:
                msg = dns.message.from_wire(response_bytes)
                new_msg = dns.message.Message()
                new_msg.id = msg.id
                new_msg.flags = msg.flags
                for q in msg.question:
                    new_msg.question.append(q)

                def _replace_ttl(rrset_list):
                    new_list = []
                    for rrset in rrset_list:
                        new_rr = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                        new_rr.ttl = ttl
                        for rd in rrset:
                            rd.ttl = ttl
                            new_rr.add(rd)
                        new_list.append(new_rr)
                    return new_list

                new_msg.answer = _replace_ttl(msg.answer)
                new_msg.authority = _replace_ttl(msg.authority)
                new_msg.additional = _replace_ttl(msg.additional)
                return new_msg.to_wire()
            except Exception as e:
                self.logger.debug("_set_response_ttl failed: %s", e)
        return response_bytes

    # ---------- parsing helpers ----------
    @staticmethod
    def _parse_dns_name(packet: bytes, offset: int,
                        max_depth: int = 20,
                        _depth: int = 0) -> Tuple[str, int]:
        labels = []
        while True:
            if offset >= len(packet):
                raise ValueError("Out of bounds while parsing DNS name")
            length = packet[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(packet):
                    raise ValueError("Truncated pointer")
                pointer = ((length & 0x3F) << 8) | packet[offset + 1]
                if pointer >= len(packet):
                    raise ValueError("Pointer out of bounds")
                if _depth >= max_depth:
                    raise ValueError("Pointer loop detected")
                recursive_label, _ = DNSResolver._parse_dns_name(
                    packet, pointer, max_depth, _depth + 1
                )
                labels.append(recursive_label)
                offset += 2
                break
            if offset + 1 + length > len(packet):
                raise ValueError("Label extends past packet")
            labels.append(packet[offset + 1:offset + 1 + length].decode('ascii', errors='ignore'))
            offset += 1 + length
        name = '.'.join(labels)
        return name, offset

    def _extract_qname_from_wire(self, data: bytes) -> Optional[str]:
        try:
            if not data or len(data) < 12:
                return None
            qname, _ = self._parse_dns_name(data, 12)
            return qname
        except Exception:
            return None

    def _extract_qtype_from_wire(self, data: bytes) -> Optional[int]:
        try:
            if not data or len(data) < 12:
                return None
            _, off = self._parse_dns_name(data, 12)
            if off + 4 > len(data):
                return None
            qtype = (data[off] << 8) | data[off+1]
            return qtype
        except Exception:
            return None

    def _make_nxdomain_response(self, query_data: bytes) -> bytes:
        if not query_data or len(query_data) < 12:
            tid = 0
            qpart = b''
            req_flags = 0
        else:
            tid = int.from_bytes(query_data[0:2], 'big')
            req_flags = int.from_bytes(query_data[2:4], 'big')
            try:
                _, qend = self._parse_dns_name(query_data, 12)
                qpart = query_data[12:qend + 4]
            except Exception:
                qpart = query_data[12:]
        rd = req_flags & 0x0100
        flags = 0x8000 | rd | 0x0003
        header = (
            tid.to_bytes(2, 'big') +
            flags.to_bytes(2, 'big') +
            (1).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big')
        )
        return header + qpart

    def _build_local_A_response(self, query_data: bytes, ip: str) -> bytes:
        if not query_data or len(query_data) < 12:
            return b''
        tid = int.from_bytes(query_data[0:2], 'big')
        flags = 0x8000
        header = (
            tid.to_bytes(2, 'big') +
            flags.to_bytes(2, 'big') +
            (1).to_bytes(2, 'big') +
            (1).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big')
        )
        _, qend = self._parse_dns_name(query_data, 12)
        qpart = query_data[12:qend + 4]
        name_ptr = b'\xc0\x0c'
        rtype = (1).to_bytes(2, 'big')
        rclass = (1).to_bytes(2, 'big')
        ttl = (60).to_bytes(4, 'big')
        ip_parts = [int(x) for x in ip.split('.')]
        rdata = struct.pack('BBBB', *ip_parts)
        rdlen = (len(rdata)).to_bytes(2, 'big')
        answer = name_ptr + rtype + rclass + ttl + rdlen + rdata
        return header + qpart + answer

    def _extract_min_ttl(self, response: bytes) -> int:
        try:
            if not response or len(response) < 12:
                return 0
            qdcount = (response[4] << 8) | response[5]
            ancount = (response[6] << 8) | response[7]
            offset = 12
            for _ in range(qdcount):
                _, offset = self._parse_dns_name(response, offset)
                offset += 4
            min_ttl: Optional[int] = None
            for _ in range(ancount):
                _, offset = self._parse_dns_name(response, offset)
                if offset + 10 > len(response):
                    raise Exception("truncated answer header")
                ttl = struct.unpack(">I", response[offset+4:offset+8])[0]
                rdlen = (response[offset+8] << 8) | response[offset+9]
                if offset + 10 + rdlen > len(response):
                    raise Exception("truncated rdata")
                offset += 10 + rdlen
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
            return min_ttl or 0
        except Exception:
            return 0

    def _parse_rr_name(self, response: bytes, offset: int) -> Tuple[str, int]:
        return self._parse_dns_name(response, offset)

    async def _cache_get(self, key: Tuple[str, int, str]) -> Optional[str]:
        try:
            if self._cache_is_sync:
                val = self._dns_cache.get(key)  # type: ignore[attr-defined]
            else:
                val = await self._dns_cache.get(key)  # type: ignore[attr-defined]
            if val is not None:
                self.logger.debug("cache hit for %s -> %s", key, val)
            else:
                self.logger.debug("cache miss for %s", key)
            return val
        except Exception as e:
            self.logger.debug("cache get error for %s: %s", key, e)
            return None

    async def _cache_set(self, key: Tuple[str, int, str], value: str) -> None:
        try:
            if self._cache_is_sync:
                self._dns_cache[key] = value  # type: ignore[index]
            else:
                await self._dns_cache.set(key, value)  # type: ignore[attr-defined]
            self.logger.debug("cache set %s -> %s", key, value)
        except Exception as e:
            self.logger.debug("cache set error for %s: %s", key, e)

    async def _with_retries(self, fn: Callable[[bytes], Coroutine[Any, Any, bytes]], data: bytes, timeout: float) -> bytes:
        backoff = 0.1
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                self.logger.debug("attempt %d/%d for %s", attempt + 1, self.retries, fn.__name__)
                start = time.time()
                result = await asyncio.wait_for(fn(data), timeout=timeout)
                dur = time.time() - start
                self.logger.debug("success %s on attempt %d (%.3fs)", fn.__name__, attempt + 1, dur)
                if self.metrics_enabled and self._metrics:
                    try:
                        self._metrics['request_latency_seconds'].labels(proto=self.protocol).observe(dur)
                    except Exception:
                        pass
                return result
            except asyncio.TimeoutError as e:
                last_exc = e
                self.logger.warning("timeout on attempt %d for %s", attempt + 1, fn.__name__)
            except Exception as e:
                last_exc = e
                self.logger.debug("attempt %d failed for %s: %s", attempt + 1, fn.__name__, e)
            await asyncio.sleep(backoff)
            self.logger.debug("backing off %.3fs before next attempt", backoff)
            backoff *= 2
        self.logger.error("all %d attempts failed for %s", self.retries, fn.__name__)
        if self.metrics_enabled and self._metrics:
            try:
                self._metrics['requests_errors'].labels(proto=self.protocol).inc()
            except Exception:
                pass
        raise last_exc or Exception("Unknown forward error")

    def _log_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None) -> None:
        msg = f"{status}\tqname={qname}\tclient={client}\t{details or ''}"
        if status.startswith("Blocked"):
            self.logger.info(msg)
        else:
            self.logger.debug(msg)
        if self._file_logger:
            try:
                self._file_logger.info(msg)
            except Exception:
                pass

    def log_dns_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None) -> None:
        return self._log_event(status, qname, client, details)

    async def _check_cert_pins(self, hostname: str, ssl_obj: Any) -> None:
        if not self.pinned_certs:
            return
        self.logger.debug("checking certificate pin for %s", hostname)
        try:
            der = ssl_obj.getpeercert(binary_form=True)
            if not der:
                raise Exception("No peer cert available for pin-check")
            got = hashlib.sha256(der).hexdigest()
            expected = self.pinned_certs.get(hostname) or self.pinned_certs.get('*')
            if expected and got.lower() != expected.lower():
                self.logger.warning("certificate pin mismatch for %s: got %s expected %s", hostname, got, expected)
                raise Exception(f"Pinned certificate mismatch for {hostname}: got {got}, expected {expected}")
            self.logger.debug("certificate pin match for %s", hostname)
        except Exception:
            self.logger.exception("certificate pin check failed for %s", hostname)
            raise

    def _load_trust_anchors(self) -> None:
        if not self.trust_anchors:
            return
        path = None
        if isinstance(self.trust_anchors, dict):
            path = self.trust_anchors.get('file')
        elif isinstance(self.trust_anchors, str):
            path = self.trust_anchors
        if not path:
            return
        try:
            anchors: Dict[Any, Any] = {}
            with open(path, 'r') as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        self.logger.debug("skipping malformed anchor line: %s", line)
                        continue
                    try:
                        idx = parts.index('DNSKEY')
                    except ValueError:
                        try:
                            idx = parts.index('dnskey')
                        except ValueError:
                            self.logger.debug("no DNSKEY token in line: %s", line)
                            continue
                    if idx < 1:
                        self.logger.debug("unexpected DNSKEY line format: %s", line)
                        continue
                    name_text = parts[0]
                    ttl_text = parts[1] if idx >= 2 else '3600'
                    try:
                        ttl = int(ttl_text)
                    except Exception:
                        ttl = 3600
                    rdata_text = ' '.join(parts[idx+1:])
                    try:
                        rr = dns.rrset.from_text(name_text, ttl, 'IN', 'DNSKEY', rdata_text)
                        name_obj = dns.name.from_text(name_text)
                        if name_obj in anchors:
                            for r in rr:
                                anchors[name_obj].add(r)
                        else:
                            anchors[name_obj] = rr
                    except Exception as e:
                        self.logger.debug("failed to parse anchor line '%s': %s", line, e)
                        continue
            self._dnssec_raw_anchors = anchors
            try:
                simple = {name: [r.to_text() for r in rr] for name, rr in anchors.items()}
                self._dnssec_keyring = dns.dnssec.make_keyring(simple)
                self.logger.debug("built dnssec keyring from %s (%d names)", path, len(simple))
            except Exception:
                self._dnssec_keyring = None
                self.logger.debug("could not build unified keyring; will build per-name at validation time")
        except Exception as e:
            self.logger.warning("failed to load trust anchors from %s: %s", path, e)

    async def _dnssec_validate(self, qname: str, response_wire: bytes) -> None:
        if not self.dnssec_enabled:
            return
        if not _HAS_DNSPY:
            raise RuntimeError("dnspython is required for DNSSEC validation")
        try:
            self._load_trust_anchors()
        except Exception as e:
            self.logger.warning("failed to load trust anchors: %s", e)
            raise
        if not getattr(self, '_dnssec_raw_anchors', None):
            self.logger.warning("DNSSEC enabled but no trust anchors available; aborting validation")
            raise Exception("DNSSEC trust anchors missing")

        def _validate() -> bool:
            try:
                msg = dns.message.from_wire(response_wire)
                rrsig_by_name: Dict[Any, Any] = {}
                for rr in msg.answer:
                    if rr.rdtype == dns.rdatatype.RRSIG:
                        rrsig_by_name.setdefault(rr.name, []).append(rr)
                for rrset in msg.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        continue
                    name = rrset.name
                    candidate = None
                    sig_sets = rrsig_by_name.get(name)
                    if sig_sets:
                        for s in sig_sets:
                            for r in s:
                                if getattr(r, 'type_covered', None) == rrset.rdtype:
                                    candidate = s
                                    break
                            if candidate:
                                break
                    if candidate is None:
                        raise Exception(f"no RRSIG for rrset {name} type {rrset.rdtype}")
                    if getattr(self, '_dnssec_keyring', None):
                        keyring = self._dnssec_keyring
                    else:
                        anchors = getattr(self, '_dnssec_raw_anchors', {})
                        ks: Dict[Any, Any] = {}
                        if name in anchors:
                            ks[name] = [r.to_text() for r in anchors[name]]
                        else:
                            for anc_name in anchors:
                                if name.is_subdomain(anc_name):
                                    ks[anc_name] = [r.to_text() for r in anchors[anc_name]]
                                    break
                        if not ks:
                            raise Exception(f"no trust anchor available for {name}")
                        keyring = dns.dnssec.make_keyring(ks)
                    dns.dnssec.validate(rrset, candidate, keyring)
                return True
            except Exception:
                raise

        try:
            await asyncio.get_running_loop().run_in_executor(None, _validate)
        except Exception as e:
            self.logger.warning("DNSSEC validation error for %s: %s", qname, e)
            raise
        self.logger.debug("DNSSEC validation passed for %s", qname)

    # --- New: try an upstream and return response or raise ---
    async def _try_upstream(self, upstream: Dict[str, Any], data: bytes) -> bytes:
        proto = upstream.get('protocol', 'udp')
        if proto == 'udp':
            return await self._with_retries(
                lambda d: self._forward_udp(d, upstream), data, timeout=self.udp_timeout)
        elif proto == 'tcp':
            return await self._with_retries(
                lambda d: self._forward_tcp(d, upstream), data, timeout=self.tcp_timeout)
        elif proto == 'tls':
            return await self._with_retries(
                lambda d: self._forward_tls(d, upstream), data, timeout=self.tcp_timeout)
        elif proto == 'https':
            return await self._with_retries(
                lambda d: self._forward_https(d, upstream), data, timeout=self.doh_timeout)
        elif proto == 'quic':
            if not _HAS_AIOQUIC:
                raise RuntimeError("aioquic not available for DoQ")
            return await self._with_retries(
                lambda d: self._forward_quic(d, upstream), data, timeout=self.doh_timeout)
        else:
            raise ValueError(f"Unsupported upstream protocol: {proto}")

    async def forward_dns_query(self, data: bytes) -> bytes:
        qname = self._extract_qname_from_wire(data)
        qtype = self._extract_qtype_from_wire(data) or 1
        key = (qname or "", qtype, self.protocol)

        host_values = self.get_host_for(qname)
        if host_values:
            if qtype == 1 and len(host_values) > 0:
                ip = host_values[0]
                try:
                    if _HAS_DNSPY:
                        absolute_qname = qname if qname.endswith('.') else f"{qname}."
                        from dns import message, rdatatype, rdataclass, rrset
                        resp = dns.message.make_response(dns.message.from_wire(data) if data else None)
                        rr = dns.rrset.from_text(absolute_qname, 60, dns.rdataclass.IN, dns.rdatatype.A, ip)
                        resp.answer = [rr]
                        return resp.to_wire()
                    else:
                        return self._build_local_A_response(data, ip)
                except Exception:
                    self.logger.exception("failed to synthesize hosts map response for %s", qname)

        if self.is_blocked(qname):
            self._log_event("Blocked (internal)", qname, None, "blocklist")
            try:
                return self.build_block_response(data)
            except Exception:
                return self._make_nxdomain_response(data)

        cached = await self._wire_cache_get_valid(key)
        if cached:
            self.logger.debug("wire-cache hit %s", key)
            if self.rebind_protection_enabled:
                cached = self._apply_rebind_protection(cached)
            return cached

        # --- prepare upstream list ---
        upstream_list = self.upstreams if self.upstreams else [
            {'address': self.upstream_dns, 'protocol': self.protocol, 'hostname': self.upstream_dns}
        ]

        last_exc = None
        for upstream in upstream_list:
            try:
                resp = await self._try_upstream(upstream, data)
                if self.metrics_enabled and self._metrics:
                    try:
                        self._metrics['requests_total'].labels(proto=upstream['protocol']).inc()
                    except Exception:
                        pass
                if self.dnssec_enabled and qname:
                    try:
                        await self._dnssec_validate(qname, resp)
                    except Exception as e:
                        self.logger.warning("DNSSEC validation failed for %s: %s", qname, e)
                        raise
                if self.rebind_protection_enabled:
                    resp = self._apply_rebind_protection(resp)
                ttl = self._extract_min_ttl(resp)
                if ttl <= 0:
                    ttl = 30
                await self._wire_cache_set(key, resp, ttl, data)
                return resp
            except Exception as e:
                last_exc = e
                self.logger.debug("upstream %s failed: %s", upstream.get('address'), e)
                continue

        self.logger.error("all upstreams failed")
        raise last_exc or Exception("All upstreams exhausted")

    # --- forwarding implementations (with connection pooling) ---

    async def _forward_udp(self, data: bytes, upstream: Optional[Dict[str, Any]] = None) -> bytes:
        if upstream is None:
            host, port = self._split_hostport(self.upstream_dns, default_port=53)
        else:
            host = upstream['address']
            port = upstream.get('port', 53)
        resolved = await self._resolve_upstream_ip(host)
        family = socket.AF_INET6 if self._is_ipv6_address(resolved) else socket.AF_INET
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")
        loop = asyncio.get_running_loop()

        on_response: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.transport: Optional[asyncio.DatagramTransport] = None

            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.transport = transport
                try:
                    transport.sendto(data)
                except Exception as e:
                    if not on_response.done():
                        on_response.set_exception(e)

            def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
                if not on_response.done():
                    on_response.set_result(data)

            def error_received(self, exc: Exception) -> None:
                if not on_response.done():
                    on_response.set_exception(exc)

            def connection_lost(self, exc: Optional[Exception]) -> None:
                if exc and not on_response.done():
                    on_response.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(), remote_addr=(resolved, int(port)), family=family)
        try:
            return await asyncio.wait_for(on_response, timeout=self.udp_timeout)
        finally:
            transport.close()

    async def _forward_tcp(self, data: bytes, upstream: Optional[Dict[str, Any]] = None) -> bytes:
        if upstream is None:
            host, port = self._split_hostport(self.upstream_dns, default_port=53)
        else:
            host = upstream['address']
            port = upstream.get('port', 53)

        key = (host, port)
        pooled = await self._tcp_pool.get(key)
        if pooled:
            reader, writer = pooled
        else:
            resolved = await self._resolve_upstream_ip(host)
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")
            reader, writer = await asyncio.open_connection(resolved, int(port))
        try:
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, "big")
            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)
            await self._tcp_pool.put(key, reader, writer)
            return resp
        except Exception:
            writer.close()
            raise

    async def _forward_tls(self, data: bytes, upstream: Optional[Dict[str, Any]] = None) -> bytes:
        if upstream is None:
            host, port = self._split_hostport(self.upstream_dns, default_port=853)
            hostname = host
        else:
            host = upstream['address']
            port = upstream.get('port', 853)
            hostname = upstream.get('hostname', host)

        key = (host, port, hostname)
        pooled = await self._tcp_pool.get(key)
        if pooled:
            reader, writer = pooled
        else:
            resolved = await self._resolve_upstream_ip(host)
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")
            ssl_ctx = ssl.create_default_context()
            reader, writer = await asyncio.open_connection(resolved, int(port), ssl=ssl_ctx, server_hostname=hostname)
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                await self._check_cert_pins(hostname, ssl_obj)
        try:
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, "big")
            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)
            await self._tcp_pool.put(key, reader, writer)
            return resp
        except Exception:
            writer.close()
            raise

    # --- DoH implementation (HTTP/1.1, HTTP/2, HTTP/3, auto) ---

    async def _forward_https(self, data: bytes, upstream: Optional[Dict[str, Any]] = None) -> bytes:
        if upstream is None:
            host = self.upstream_dns
            port = 443
            hostname = host
            path = "/dns-query"
            version = self.doh_version
        else:
            host = upstream['address']
            port = upstream.get('port', 443)
            hostname = upstream.get('hostname', host)
            path = upstream.get('path', '/dns-query')
            version = upstream.get('doh_version', self.doh_version)

        if version == 'auto':
            version = await self._get_auto_doh_version(hostname, port, host, path)

        if version == '3':
            return await self._with_retries(
                lambda d: self._forward_https3(d, hostname, port, host, path), data, timeout=self.doh_timeout)
        elif version == '2':
            return await self._with_retries(
                lambda d: self._forward_https2(d, hostname, port, host, path), data, timeout=self.doh_timeout)
        else:
            return await self._with_retries(
                lambda d: self._forward_https1(d, hostname, port, host, path), data, timeout=self.doh_timeout)

    async def _get_auto_doh_version(self, hostname: str, port: int, host: str, path: str) -> str:
        now = time.time()
        async with self._doh_auto_lock:
            if hostname in self._doh_auto_cache:
                version, expiry = self._doh_auto_cache[hostname]
                if now < expiry:
                    return version
                else:
                    del self._doh_auto_cache[hostname]

        probe_data = dns.message.make_query('probe.invalid', 'A').to_wire()
        # Try HTTP/3 first
        try:
            await self._with_retries(
                lambda d: self._forward_https3(d, hostname, port, host, path), probe_data, timeout=self.doh_timeout)
            version = '3'
        except Exception:
            try:
                await self._with_retries(
                    lambda d: self._forward_https2(d, hostname, port, host, path), probe_data, timeout=self.doh_timeout)
                version = '2'
            except Exception:
                version = '1.1'

        async with self._doh_auto_lock:
            self._doh_auto_cache[hostname] = (version, now + self.doh_auto_cache_ttl)
        return version

    async def _forward_https1(self, data: bytes, hostname: str, port: int, host: str, path: str) -> bytes:
        resolved = await self._resolve_upstream_ip(host)
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(resolved, port, ssl=ssl_ctx, server_hostname=hostname)

        try:
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                await self._check_cert_pins(hostname, ssl_obj)

            headers = [
                f"POST {path} HTTP/1.1",
                f"Host: {hostname}",
                "User-Agent: phantomd/1.0",
                "Accept: application/dns-message",
                "Content-Type: application/dns-message",
                f"Content-Length: {len(data)}",
                "Connection: close",
                "",
                ""
            ]
            hdr = "\r\n".join(headers).encode("ascii")
            writer.write(hdr + data)
            await writer.drain()

            status_line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
            if not status_line:
                raise Exception("Empty response from DoH upstream")
            status_line = status_line.decode("ascii", errors="ignore").strip()
            if not status_line.startswith("HTTP/"):
                raise Exception(f"Invalid HTTP response start: {status_line}")
            try:
                parts = status_line.split(None, 2)
                status_code = int(parts[1]) if len(parts) > 1 else 0
            except Exception:
                status_code = 0
            if status_code < 200 or status_code >= 300:
                raise Exception(f"DoH upstream returned non-2xx status: {status_line}")

            content_length: Optional[int] = None
            chunked = False
            content_type_ok = False
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
                if not line:
                    break
                s = line.decode("ascii", errors="ignore").strip()
                if s == "":
                    break
                parts = s.split(":", 1)
                if len(parts) == 2:
                    k, v = parts[0].lower(), parts[1].strip()
                    if k == "content-length":
                        try:
                            content_length = int(v)
                        except Exception:
                            content_length = None
                    if k == "transfer-encoding" and "chunked" in v.lower():
                        chunked = True
                    if k == "content-type":
                        if "application/dns-message" in v.lower():
                            content_type_ok = True

            if not chunked and content_length is not None and not content_type_ok:
                self.logger.debug("DoH response content-type not application/dns-message; continuing")

            if chunked:
                body = bytearray()
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
                    if not line:
                        break
                    hexlen = line.decode("ascii", errors="ignore").strip().split(";", 1)[0]
                    try:
                        ln = int(hexlen, 16)
                    except Exception:
                        raise Exception("Invalid chunk length")
                    if ln == 0:
                        await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=self.doh_timeout)
                        break
                    chunk = await asyncio.wait_for(reader.readexactly(ln), timeout=self.doh_timeout)
                    body.extend(chunk)
                    await asyncio.wait_for(reader.readexactly(2), timeout=self.doh_timeout)
                return bytes(body)
            else:
                if content_length is None:
                    self.logger.warning("DoH response missing Content-Length and not chunked; rejecting for determinism")
                    raise Exception("DoH response missing Content-Length and not chunked")
                return await asyncio.wait_for(reader.readexactly(content_length), timeout=self.doh_timeout)
        finally:
            writer.close()
            await writer.wait_closed()

    # ---------- DoH/2 (HTTP/2) with pooling ----------
    async def _forward_https2(self, data: bytes, hostname: str, port: int, host: str, path: str) -> bytes:
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required for HTTP/2 DoH (install with: pip install httpx[h2])")

        key = (hostname, port)
        client: Optional[httpx.AsyncClient] = await self._h2_pool.get(key)
        if client is None:
            client = httpx.AsyncClient(http2=True, verify=ssl.create_default_context())

        url = f"https://{hostname}:{port}{path}"
        try:
            resp = await client.post(
                url,
                headers={
                    "Host": hostname,
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
                content=data,
                timeout=self.doh_timeout,
            )
            if resp.status_code < 200 or resp.status_code >= 300:
                raise Exception(f"HTTP/2 upstream returned status {resp.status_code}")
            result = resp.content
            await self._h2_pool.put(key, client)
            return result
        except Exception:
            try:
                await client.aclose()
            except Exception:
                pass
            raise

    # ---------- DoH/3 (HTTP/3) with pooling ----------
    async def _forward_https3(self, data: bytes, hostname: str, port: int, host: str, path: str) -> bytes:
        if not _HAS_AIOQUIC:
            raise RuntimeError("aioquic is required for HTTP/3 DoH (install with: pip install aioquic)")
        try:
            from aioquic.h3.connection import H3Connection
            from aioquic.h3.events import HeadersReceived, DataReceived
            from aioquic.asyncio.client import connect as quic_connect
        except ImportError:
            raise RuntimeError("aioquic.h3 not available; upgrade aioquic to the latest version")

        resolved = await self._resolve_upstream_ip(host)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        key = (hostname, port)
        ctx = await self._h3_pool.get(key)
        if ctx is not None:
            connection, h3 = ctx
            stream_id = h3.get_next_available_stream_id()
            try:
                h3.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":method", b"POST"),
                        (b":scheme", b"https"),
                        (b":authority", hostname.encode()),
                        (b":path", path.encode()),
                        (b"content-type", b"application/dns-message"),
                        (b"accept", b"application/dns-message"),
                        (b"content-length", str(len(data)).encode()),
                    ],
                    end_stream=False
                )
                h3.send_data(stream_id, data, end_stream=True)

                response_data = bytearray()
                response_complete = asyncio.Event()

                async def handle_events():
                    while not response_complete.is_set():
                        try:
                            event = await asyncio.wait_for(connection.next_event(), timeout=0.1)
                            for h3_event in h3.handle_event(event):
                                if isinstance(h3_event, DataReceived) and h3_event.stream_id == stream_id:
                                    response_data.extend(h3_event.data)
                                    if h3_event.stream_ended:
                                        response_complete.set()
                                elif isinstance(h3_event, HeadersReceived) and h3_event.stream_ended:
                                    response_complete.set()
                        except asyncio.TimeoutError:
                            pass

                await asyncio.wait_for(handle_events(), timeout=self.doh_timeout)
                await self._h3_pool.put(key, (connection, h3))
                return bytes(response_data)
            except Exception:
                try:
                    connection.close()
                except Exception:
                    pass
                raise

        # No pooled connection – create new one
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_REQUIRED)
        configuration.server_name = hostname

        class H3Protocol:
            def __init__(self, conn):
                self.conn = conn
                self.h3 = H3Connection(conn)

            def quic_event_received(self, event):
                for h3_event in self.h3.handle_event(event):
                    pass

        async with quic_connect(resolved, port, configuration=configuration,
                                create_protocol=lambda conn: H3Protocol(conn)) as client:
            proto = client._protocol
            connection = client._quic
            h3 = proto.h3

            stream_id = h3.get_next_available_stream_id()
            h3.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", hostname.encode()),
                    (b":path", path.encode()),
                    (b"content-type", b"application/dns-message"),
                    (b"accept", b"application/dns-message"),
                    (b"content-length", str(len(data)).encode()),
                ],
                end_stream=False
            )
            h3.send_data(stream_id, data, end_stream=True)

            response_data = bytearray()
            response_complete = asyncio.Event()

            async def handle_events():
                while not response_complete.is_set():
                    try:
                        event = await asyncio.wait_for(connection.next_event(), timeout=0.1)
                        for h3_event in h3.handle_event(event):
                            if isinstance(h3_event, DataReceived) and h3_event.stream_id == stream_id:
                                response_data.extend(h3_event.data)
                                if h3_event.stream_ended:
                                    response_complete.set()
                            elif isinstance(h3_event, HeadersReceived) and h3_event.stream_ended:
                                response_complete.set()
                    except asyncio.TimeoutError:
                        pass

            await asyncio.wait_for(handle_events(), timeout=self.doh_timeout)
            await self._h3_pool.put(key, (connection, h3))
            return bytes(response_data)

    # ---------- DoQ with pooling ----------
    async def _forward_quic(self, data: bytes, upstream: Optional[Dict[str, Any]] = None) -> bytes:
        if not _HAS_AIOQUIC:
            raise RuntimeError("aioquic not available for DoQ")
        from aioquic.quic.events import StreamDataReceived

        if upstream is None:
            hostname, port = self._split_hostport(self.upstream_dns, default_port=784)
        else:
            hostname = upstream.get('hostname', upstream['address'])
            port = upstream.get('port', 784)

        resolved = await self._resolve_upstream_ip(hostname)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        key = (hostname, port)
        pooled = await self._quic_pool.get(key)
        if pooled is not None:
            connection, quic_obj = pooled
            try:
                stream_id = quic_obj.get_next_available_stream_id()
                quic_obj.send_stream_data(stream_id, len(data).to_bytes(2, "big") + data, end_stream=True)

                response_data = bytearray()
                response_complete = asyncio.Event()

                async def wait_response():
                    while not response_complete.is_set():
                        try:
                            event = await asyncio.wait_for(connection.next_event(), timeout=0.1)
                            if isinstance(event, StreamDataReceived):
                                response_data.extend(event.data)
                                if event.end_stream:
                                    response_complete.set()
                        except asyncio.TimeoutError:
                            pass

                await asyncio.wait_for(wait_response(), timeout=self.doh_timeout)
                resp = bytes(response_data)
                if len(resp) < 2:
                    raise Exception("Invalid DoQ response")
                resp_len = int.from_bytes(resp[:2], "big")
                if resp_len + 2 > len(resp):
                    raise Exception("DoQ response truncated")
                await self._quic_pool.put(key, (connection, quic_obj))
                return resp[2:2+resp_len]
            except Exception:
                try:
                    connection.close()
                except Exception:
                    pass
                raise

        configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"],
                                          verify_mode=ssl.CERT_REQUIRED)
        from aioquic.asyncio.client import connect as quic_connect

        class DoQProto:
            def quic_event_received(self, event):
                pass

        response_data = bytearray()
        response_event = asyncio.Event()

        async with quic_connect(resolved, port, configuration=configuration,
                                create_protocol=lambda *a, **k: DoQProto()) as client:
            quic_obj = client._quic
            connection = quic_obj
            stream_id = quic_obj.get_next_available_stream_id()
            quic_obj.send_stream_data(stream_id, len(data).to_bytes(2, "big") + data, end_stream=True)

            if self.pinned_certs:
                der = self._get_quic_cert_der(client)
                if der:
                    await self._check_cert_pins(hostname, self._DERPeerWrapper(der))

            async def wait_response():
                while not response_event.is_set():
                    try:
                        event = await asyncio.wait_for(connection.next_event(), timeout=0.1)
                        if isinstance(event, StreamDataReceived):
                            response_data.extend(event.data)
                            if event.end_stream:
                                response_event.set()
                    except asyncio.TimeoutError:
                        pass

            await asyncio.wait_for(wait_response(), timeout=self.doh_timeout)
            resp = bytes(response_data)
            if len(resp) < 2:
                raise Exception("Invalid DoQ response")
            resp_len = int.from_bytes(resp[:2], "big")
            if resp_len + 2 > len(resp):
                raise Exception("DoQ response truncated")
            await self._quic_pool.put(key, (connection, quic_obj))
            return resp[2:2+resp_len]

    def _get_quic_cert_der(self, client: Any) -> Optional[bytes]:
        try:
            if hasattr(client, 'get_peer_certificate'):
                cert = client.get_peer_certificate()
                if cert is not None:
                    if hasattr(cert, 'public_bytes'):
                        from cryptography.hazmat.primitives.serialization import Encoding
                        return cert.public_bytes(Encoding.DER)
                    if isinstance(cert, bytes):
                        return cert
            if hasattr(client, '_quic'):
                quic = client._quic
                if hasattr(quic, 'tls') and hasattr(quic.tls, '_peer_certificate'):
                    cert = quic.tls._peer_certificate
                    if cert is not None:
                        if hasattr(cert, 'public_bytes'):
                            from cryptography.hazmat.primitives.serialization import Encoding
                            return cert.public_bytes(Encoding.DER)
                        if isinstance(cert, bytes):
                            return cert
            get_chain = getattr(client, 'get_peer_cert_chain', None)
            if callable(get_chain):
                chain = get_chain()
                if chain and isinstance(chain, (list, tuple)):
                    first = chain[0]
                    if isinstance(first, bytes):
                        return first
                    if hasattr(first, 'public_bytes'):
                        from cryptography.hazmat.primitives.serialization import Encoding
                        return first.public_bytes(Encoding.DER)
        except Exception:
            pass
        return None

    # --- name resolution helpers ---
    def _split_hostport(self, hostport: str, default_port: int = 53) -> Tuple[str, int]:
        if not hostport:
            return "", default_port
        host = hostport
        port = default_port
        if hostport.startswith("["):
            try:
                end = hostport.index("]")
                host = hostport[1:end]
                rest = hostport[end+1:]
                if rest.startswith(":"):
                    port = int(rest[1:])
            except Exception:
                host = hostport
        else:
            if hostport.count(":") == 1:
                h, p = hostport.rsplit(":", 1)
                try:
                    port = int(p)
                    host = h
                except Exception:
                    host = hostport
            else:
                host = hostport
        return host, int(port)

    def _is_ipv6_address(self, addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr).version == 6
        except Exception:
            return False

    class _DERPeerWrapper:
        def __init__(self, der: bytes) -> None:
            self._der = der
        def getpeercert(self, binary_form: bool = False) -> Optional[bytes]:
            return self._der if binary_form else None

    async def _resolve_upstream_ip(self, hostname: str) -> str:
        key = (hostname, bool(self.disable_ipv6))
        cached = await self._cache_get(key)
        if cached:
            self.logger.debug("resolved %s from cache -> %s", hostname, cached)
            return cached

        self.logger.debug("resolving upstream hostname: %s", hostname)
        try:
            family = socket.AF_INET if self.disable_ipv6 else 0
            infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr:
                    await self._cache_set(key, addr)
                    self.logger.debug("system resolver returned %s for %s", addr, hostname)
                    return addr
        except Exception as e:
            self.logger.debug("system resolver failed for %s: %s", hostname, e)

        if self.dns_resolver_server:
            self.logger.debug("falling back to configured dns_resolver_server: %s", self.dns_resolver_server)
            try:
                parts = self.dns_resolver_server.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    ip, port = parts[0], int(parts[1])
                else:
                    ip, port = parts[0], 53
                addr = await self._udp_query_a_or_aaaa(ip, port, hostname, qtype=1)
                if not addr:
                    addr = await self._udp_query_a_or_aaaa(ip, port, hostname, qtype=28)
                if addr:
                    await self._cache_set(key, addr)
                    self.logger.debug("resolver server returned %s for %s", addr, hostname)
                    return addr
            except Exception as e:
                self.logger.debug("dns_resolver_server lookup failed for %s: %s", hostname, e)

        self.logger.error("unable to resolve upstream hostname: %s", hostname)
        raise Exception(f"Unable to resolve upstream hostname: {hostname}")

    async def _udp_query_a_or_aaaa(self, resolver_ip: str, resolver_port: int, qname: str, qtype: int = 1) -> Optional[str]:
        self.logger.debug("udp lookup of %s via %s:%d", qname, resolver_ip, resolver_port)
        loop = asyncio.get_running_loop()
        try:
            ip_obj = ipaddress.ip_address(resolver_ip)
            fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        except Exception:
            fam = socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            tid = int(time.time() * 1000) & 0xFFFF
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split("."))
            q += b"\x00" + struct.pack(">HH", int(qtype), 1)
            query = header + q
            addr_tuple = (resolver_ip, resolver_port) if fam == socket.AF_INET else (resolver_ip, resolver_port, 0, 0)
            await loop.sock_sendto(sock, query, addr_tuple)
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=self.udp_timeout)
            except asyncio.TimeoutError:
                self.logger.debug("udp lookup timed out for %s (qtype=%s)", qname, qtype)
                return None

            if len(data) < 12:
                raise Exception("short DNS response")
            qdcount = (data[4] << 8) | data[5]
            ancount = (data[6] << 8) | data[7]
            i = 12
            for _ in range(qdcount):
                _, i = self._parse_dns_name(data, i)
                i += 4
            a_addr: Optional[str] = None
            aaaa_addr: Optional[str] = None
            for _ in range(ancount):
                _, i = self._parse_dns_name(data, i)
                if i + 10 > len(data):
                    raise Exception("truncated answer header")
                rtype = (data[i] << 8) | data[i+1]
                ttl = struct.unpack(">I", data[i+4:i+8])[0]
                rdlen = (data[i+8] << 8) | data[i+9]
                if i + 10 + rdlen > len(data):
                    raise Exception("truncated rdata")
                rdata = data[i+10:i+10+rdlen]
                i += 10 + rdlen
                if rtype == 1 and rdlen == 4:
                    a_addr = ".".join(str(b) for b in rdata)
                elif rtype == 28 and rdlen == 16:
                    try:
                        aaaa_addr = socket.inet_ntop(socket.AF_INET6, bytes(rdata))
                    except Exception:
                        aaaa_addr = ":".join("{:02x}{:02x}".format(rdata[j], rdata[j+1]) for j in range(0, 16, 2))
            if qtype == 1:
                return a_addr
            if qtype == 28:
                return aaaa_addr
            return a_addr or aaaa_addr
        finally:
            sock.close()

    # ---------- block action helpers ----------
    def set_block_action(self, action: Optional[str]) -> None:
        try:
            if action is None:
                action = 'NXDOMAIN'
            self._block_action = str(action).upper()
        except Exception:
            self._block_action = 'NXDOMAIN'

    def get_block_action(self) -> str:
        return getattr(self, '_block_action', 'NXDOMAIN')

    def build_block_response(self, request_data: bytes, action: Optional[str] = None) -> bytes:
        use_action = action or self.get_block_action()
        try:
            if _HAS_DNSPY:
                try:
                    request_msg = dns.message.from_wire(request_data)
                except Exception:
                    request_msg = None
                if request_msg is None and use_action != 'ZEROIP':
                    return self._make_nxdomain_response(request_data)
                if request_msg is None:
                    resp = dns.message.Message()
                    if use_action == 'REFUSED':
                        resp.set_rcode(dns.rcode.REFUSED)
                    else:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
                resp = dns.message.make_response(request_msg)
                resp.answer = []
                if use_action == 'REFUSED':
                    resp.set_rcode(dns.rcode.REFUSED)
                    return resp.to_wire()
                if use_action == 'NXDOMAIN':
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
                if use_action == 'ZEROIP':
                    if not request_msg.question:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                        return resp.to_wire()
                    q = request_msg.question[0]
                    qname = q.name
                    qtype = q.rdtype
                    ttl = 60
                    if qtype == dns.rdatatype.A:
                        rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
                        resp.answer.append(rrset)
                        return resp.to_wire()
                    elif qtype == dns.rdatatype.AAAA:
                        if self.disable_ipv6:
                            resp.set_rcode(dns.rcode.NXDOMAIN)
                            return resp.to_wire()
                        rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
                        resp.answer.append(rrset)
                        return resp.to_wire()
                    elif qtype == dns.rdatatype.ANY:
                        a = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
                        resp.answer.append(a)
                        if not self.disable_ipv6:
                            aaaa = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
                            resp.answer.append(aaaa)
                        return resp.to_wire()
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
            if use_action == 'REFUSED':
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        _, qend = self._parse_dns_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000 | 5
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                return header + qpart
            if use_action == 'NXDOMAIN':
                return self._make_nxdomain_response(request_data)
            if use_action == 'ZEROIP':
                qname = self._extract_qname_from_wire(request_data)
                qtype = self._extract_qtype_from_wire(request_data) or 1
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        _, qend = self._parse_dns_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                name_ptr = b'\xc0\x0c'
                if qtype == 1:
                    rtype = (1).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (4).to_bytes(2, 'big')
                    rdata = b'\x00\x00\x00\x00'
                elif qtype == 28:
                    if self.disable_ipv6:
                        return self._make_nxdomain_response(request_data)
                    rtype = (28).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (16).to_bytes(2, 'big')
                    rdata = b'\x00' * 16
                elif qtype == 255:
                    a_ans = name_ptr + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (60).to_bytes(4, 'big') + (4).to_bytes(2, 'big') + b'\x00\x00\x00\x00'
                    if self.disable_ipv6:
                        return header + qpart + a_ans
                    aaaa_ans = name_ptr + (28).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (60).to_bytes(4, 'big') + (16).to_bytes(2, 'big') + (b'\x00' * 16)
                    return header + qpart + a_ans + aaaa_ans
                else:
                    return self._make_nxdomain_response(request_data)
                ans = name_ptr + rtype + rclass + ttl + rdlen + rdata
                return header + qpart + ans
        except Exception:
            return self._make_nxdomain_response(request_data)

    # --- NEW: DNS rebinding protection ---
    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv4Address):
            return (ip.is_private or
                    ip.is_loopback or
                    ip.is_link_local or
                    ip.is_reserved or
                    ip.is_multicast or
                    ip.is_unspecified)
        else:
            return (ip.is_private or
                    ip.is_loopback or
                    ip.is_link_local or
                    ip.is_reserved or
                    ip.is_multicast or
                    ip.is_unspecified)

    def _apply_rebind_protection(self, response_bytes: bytes) -> bytes:
        if not self.rebind_protection_enabled or not _HAS_DNSPY:
            return response_bytes
        try:
            msg = dns.message.from_wire(response_bytes)
            filtered_answer = []
            for rrset in msg.answer:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    new_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                    new_rrset.ttl = rrset.ttl
                    has_public = False
                    for rd in rrset:
                        ip_str = rd.to_text().strip()
                        if not self._is_private_ip(ip_str):
                            new_rrset.add(rd)
                            has_public = True
                    if has_public:
                        filtered_answer.append(new_rrset)
                else:
                    filtered_answer.append(rrset)
            msg.answer = filtered_answer

            if self.rebind_action == 'block' and not filtered_answer:
                return self._make_nxdomain_response(b'\x00'*12)
            return msg.to_wire()
        except Exception as e:
            self.logger.debug("rebind protection failed: %s", e)
            return response_bytes

    def update_config(self, *,
                      upstream_dns: Optional[str] = None,
                      protocol: Optional[str] = None,
                      disable_ipv6: Optional[bool] = None,
                      verbose: Optional[bool] = None,
                      cache_ttl: Optional[int] = None,
                      cache_max_size: Optional[int] = None,
                      doh_timeout: Optional[float] = None,
                      udp_timeout: Optional[float] = None,
                      tcp_timeout: Optional[float] = None,
                      retries: Optional[int] = None,
                      dns_logging_enabled: Optional[bool] = None,
                      pinned_certs: Optional[Dict[str, str]] = None,
                      dnssec_enabled: Optional[bool] = None,
                      trust_anchors: Optional[Union[Dict[str, str], str]] = None,
                      metrics_enabled: Optional[bool] = None,
                      metrics_port: Optional[int] = None,
                      uvloop_enable: Optional[bool] = None,
                      rate_limit_rps: Optional[float] = None,
                      rate_limit_burst: Optional[float] = None,
                      upstreams: Optional[List[Dict[str, Any]]] = None,
                      optimistic_cache_enabled: Optional[bool] = None,
                      optimistic_stale_max_age: Optional[int] = None,
                      optimistic_stale_response_ttl: Optional[int] = None,
                      rebind_protection_enabled: Optional[bool] = None,
                      rebind_action: Optional[str] = None,
                      pool_max_size: Optional[int] = None,
                      pool_idle_timeout: Optional[float] = None,
                      doh_version: Optional[str] = None,
                      doh_auto_cache_ttl: Optional[int] = None) -> None:
        """Hot‑update resolver settings without recreating the object."""
        if upstream_dns is not None:
            self.upstream_dns = upstream_dns
        if protocol is not None:
            self.protocol = protocol.lower()
        if disable_ipv6 is not None:
            self.disable_ipv6 = bool(disable_ipv6)
        if verbose is not None:
            self.verbose = bool(verbose)
            self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        if cache_ttl is not None:
            pass
        if cache_max_size is not None:
            pass
        if doh_timeout is not None:
            self.doh_timeout = doh_timeout
        if udp_timeout is not None:
            self.udp_timeout = udp_timeout
        if tcp_timeout is not None:
            self.tcp_timeout = tcp_timeout
        if retries is not None:
            self.retries = max(1, int(retries))
        if dns_logging_enabled is not None:
            self.dns_logging_enabled = dns_logging_enabled
        if pinned_certs is not None:
            self.pinned_certs = pinned_certs
        if dnssec_enabled is not None:
            self.dnssec_enabled = bool(dnssec_enabled)
        if trust_anchors is not None:
            self.trust_anchors = trust_anchors or {}
        if metrics_enabled is not None:
            self.metrics_enabled = bool(metrics_enabled) and _HAS_PROM
        if metrics_port is not None:
            self.metrics_port = int(metrics_port)
        if uvloop_enable is not None:
            pass
        if rate_limit_rps is not None:
            self.rate_limit_rps = rate_limit_rps
        if rate_limit_burst is not None:
            self.rate_limit_burst = rate_limit_burst
        if self.rate_limit_rps > 0 and self.rate_limit_burst > 0:
            if self.rate_limiter is None:
                self.rate_limiter = RateLimiter(self.rate_limit_rps, self.rate_limit_burst)
            else:
                self.rate_limiter.rate = self.rate_limit_rps
                self.rate_limiter.burst = self.rate_limit_burst
        else:
            self.rate_limiter = None
        if upstreams is not None:
            self.upstreams = upstreams
        if optimistic_cache_enabled is not None:
            self.optimistic_cache_enabled = optimistic_cache_enabled
        if optimistic_stale_max_age is not None:
            self.stale_max_age = optimistic_stale_max_age
        if optimistic_stale_response_ttl is not None:
            self.stale_response_ttl = optimistic_stale_response_ttl
        if rebind_protection_enabled is not None:
            self.rebind_protection_enabled = rebind_protection_enabled
        if rebind_action is not None:
            self.rebind_action = rebind_action.lower()
        if pool_max_size is not None:
            self._tcp_pool.max_size = pool_max_size
            self._h2_pool.max_size = pool_max_size
            self._h3_pool.max_size = pool_max_size
            self._quic_pool.max_size = pool_max_size
        if pool_idle_timeout is not None:
            self._tcp_pool.idle_timeout = pool_idle_timeout
            self._h2_pool.idle_timeout = pool_idle_timeout
            self._h3_pool.idle_timeout = pool_idle_timeout
            self._quic_pool.idle_timeout = pool_idle_timeout
        if doh_version is not None:
            self.doh_version = doh_version
        if doh_auto_cache_ttl is not None:
            self.doh_auto_cache_ttl = doh_auto_cache_ttl

        self.logger.info("DNSResolver configuration updated: upstream=%s, protocol=%s, "
                         "disable_ipv6=%s, verbose=%s, rate_limit=%s/%s, optimistic_cache=%s, "
                         "rebind_protection=%s/%s, doh_version=%s",
                         self.upstream_dns, self.protocol,
                         self.disable_ipv6, self.verbose,
                         self.rate_limit_rps, self.rate_limit_burst,
                         self.optimistic_cache_enabled,
                         self.rebind_protection_enabled, self.rebind_action,
                         self.doh_version)