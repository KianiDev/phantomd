import asyncio
import logging
import socket
import ssl
import struct
import time
import hashlib
import ipaddress
import os
from typing import Optional, Tuple, Any, Set, Dict
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
    _HAS_AIOQUIC = True
except Exception:
    aioquic = None
    QuicConfiguration = None
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
    def __init__(self, maxsize=1024, ttl=300):
        self._data = {}
        self._ttl = ttl
        self._max = maxsize
        self._lock = asyncio.Lock()

    async def get(self, key):
        async with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            value, expire = v
            if time.time() >= expire:
                del self._data[key]
                return None
            return value

    async def set(self, key, value):
        async with self._lock:
            if len(self._data) >= self._max:
                # evict oldest by expiry
                oldest = min(self._data.items(), key=lambda kv: kv[1][1])[0]
                del self._data[oldest]
            self._data[key] = (value, time.time() + self._ttl)

    async def delete(self, key):
        async with self._lock:
            try:
                if key in self._data:
                    del self._data[key]
            except Exception:
                pass


class DNSResolver:
    """Async, robust DNS resolver/forwarder supporting UDP/TCP/DoT/DoH/DoQ (DoQ optional).

    Features:
      - Async TTL cache (cachetools or internal async cache)
      - Per-protocol timeouts and retry/backoff
      - DoH over TLS with SNI preserved (manual HTTP/1.1 POST)
      - Optional certificate pinning and DNSSEC validation
      - Optional Prometheus metrics and uvloop enable

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
                  pinned_certs: Optional[dict] = None,
                  dnssec_enabled: bool = False,
                  trust_anchors: Optional[dict] = None,
                  metrics_enabled: bool = False,
                  uvloop_enable: bool = False):
        self.upstream_dns = upstream_dns
        self.protocol = protocol.lower()
        self.dns_resolver_server = dns_resolver_server
        self.disable_ipv6 = bool(disable_ipv6)
        self.verbose = bool(verbose)
        self.logger = logging.getLogger("phantomd.DNSResolver")
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.logger.addHandler(h)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        # cache
        if _HAS_CACHETOOLS:
            self._dns_cache = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._cache_is_sync = True
        else:
            self._dns_cache = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._cache_is_sync = False

        # timeouts & retry policy
        self.doh_timeout = doh_timeout
        self.udp_timeout = udp_timeout
        self.tcp_timeout = tcp_timeout
        self.retries = max(1, int(retries))

        # file logging (optional)
        self.dns_logging_enabled = dns_logging_enabled
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
                self._file_logger = flog
            except Exception as e:
                self.logger.warning("Failed to init file logger: %s", e)
                self._file_logger = None
        else:
            self._file_logger = None

        # certificate pinning map: hostname -> sha256 hex fingerprint (of DER cert)
        self.pinned_certs = pinned_certs or {}

        # DNSSEC config
        self.dnssec_enabled = bool(dnssec_enabled)
        self.trust_anchors = trust_anchors or {}

        # Prometheus metrics (optional)
        self.metrics_enabled = bool(metrics_enabled) and _HAS_PROM
        self._metrics = None
        if self.metrics_enabled:
            try:
                self._metrics = {
                    'requests_total': Counter('phantomd_dns_requests_total', 'Total DNS upstream requests', ['proto']),
                    'requests_errors': Counter('phantomd_dns_request_errors_total', 'Failed DNS upstream requests', ['proto']),
                    'request_latency_seconds': Histogram('phantomd_dns_request_latency_seconds', 'Upstream request latency seconds', ['proto'])
                }
                # attempt to start a local metrics HTTP server on localhost:8000
                try:
                    from prometheus_client import start_http_server
                    start_http_server(8000)
                    self.logger.info("Prometheus metrics server started on :8000")
                except Exception as e:
                    self.logger.debug("Could not start prometheus http server: %s", e)
            except Exception:
                self._metrics = None

        # optionally enable uvloop for performance
        if uvloop_enable and _HAS_UVLOOP:
            try:
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                self.logger.info("uvloop enabled")
            except Exception as e:
                self.logger.warning("Failed to enable uvloop: %s", e)

        # blocklist structure (fast check). can be updated via set_blocklist()/add_blocked()
        self._blocklist_exact = set()
        self._blocklist_suffix = set()
        # optional hosts map: exact domain -> tuple of fields (e.g. IP)
        self._hosts_map = {}

        # default block action
        self._block_action = 'NXDOMAIN'

    # ---------- blocklist helpers ----------
    def set_blocklist(self, domains):
        """Replace blocklist. domains is an iterable of domain strings.
           Use ".example.com" to block suffix (subdomains), or "bad.example" to block exact name."""
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

    def set_hosts_map(self, hosts_map: dict):
        """Provide an exact-domain -> tuple(...) mapping used to synthesize host responses.

        Example: {'bad.example': ('0.0.0.0',)}
        """
        self._hosts_map = {k.lower().rstrip('.'): tuple(v) for k, v in (hosts_map or {}).items()}

    def get_host_for(self, qname: str) -> Optional[Tuple[str, ...]]:
        """Return tuple associated with exact qname or None."""
        if not qname:
            return None
        return self._hosts_map.get(qname.lower().rstrip('.'))

    def add_blocked(self, domain):
        d = domain.strip().lower().rstrip('.')
        if d.startswith("."):
            self._blocklist_suffix.add(d.lstrip("."))
        else:
            self._blocklist_exact.add(d)

    @staticmethod
    def load_blocklists_from_dir(directory: str) -> Tuple[Set[str], Set[str], Dict[str, Tuple[str]]]:
        """Load blocklist files from a directory. Returns (exact_set, suffix_set, hosts_map).

        Each file may contain lines in hosts format (IP domain) or plain domain entries.
        Lines beginning with # are ignored. Suffix blocks start with a leading dot.
        """
        exact_set = set()
        suffix_set = set()
        hosts_map = {}
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
                    # hosts format: IP domain
                    if len(parts) >= 2 and (parts[0].count('.') == 3 or ':' in parts[0]):
                        ip = parts[0]
                        domain = parts[1].lower().rstrip('.')
                        hosts_map[domain] = (ip,)
                        exact_set.add(domain)
                        continue
                    # simple domain entries
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
        # suffix match: check progressively shorter suffixes
        for suf in self._blocklist_suffix:
            if q == suf or q.endswith("." + suf):
                return True
        return False

    # ---------- wire-cache helpers ----------
    async def _wire_cache_get(self, key):
        """Return cached wire response bytes or None. key should be (qname, qtype)."""
        try:
            if self._cache_is_sync:
                return self._wire_cache.get(key)
            else:
                return await self._wire_cache.get(key)
        except Exception as e:
            self.logger.debug("wire cache get error %s: %s", key, e)
            return None

    async def _wire_cache_set(self, key, response_bytes, ttl_seconds):
        """Store wire response with TTL. If using sync TTLCache we can't set custom TTL per-entry;
           we emulate by storing (response, expiry) in the cache value and still using configured TTL as fallback."""
        try:
            # We store a small tuple (resp, expiry_ts) as cache value so we can honor per-response TTLs even if cachetools only supports global TTL.
            expiry = time.time() + max(1, int(ttl_seconds or 1))
            val = (response_bytes, expiry)
            if self._cache_is_sync:
                # store raw tuple
                self._wire_cache[key] = val
            else:
                await self._wire_cache.set(key, val)
            self.logger.debug("wire cache set %s ttl=%s", key, ttl_seconds)
        except Exception as e:
            self.logger.debug("wire cache set error %s: %s", key, e)

    async def _wire_cache_get_valid(self, key):
        """Return bytes if still valid, else None. Handles tuple expiry used in set."""
        try:
            raw = await self._wire_cache_get(key)
            if raw is None:
                return None
            # raw is either bytes (older behavior) or tuple (resp, expiry)
            if isinstance(raw, tuple):
                resp, expiry = raw
                if time.time() >= expiry:
                    # expired - remove it
                    try:
                        if self._cache_is_sync:
                            try:
                                del self._wire_cache[key]
                            except Exception:
                                pass
                        else:
                            await self._wire_cache.delete(key)
                    except Exception:
                        pass
                    return None
                return resp
            # If it's raw bytes (older), return it (no per-item expiry possible)
            return raw
        except Exception:
            return None

    # ---------- parsing helpers ----------
    def _extract_qname_from_wire(self, data: bytes) -> Optional[str]:
        """Safely extract the question qname from a DNS wire-format message.

        Uses a robust parser with bounds checks and pointer-loop protection similar
        to the packet parser used for UDP responses.
        """
        try:
            if not data or len(data) < 12:
                return None
            length = len(data)
            def _parse_name(resp, offset, depth=0):
                if depth > 20:
                    raise Exception("pointer loop in qname parsing")
                if offset >= len(resp):
                    raise Exception("out of bounds in qname parsing")
                labels = []
                while True:
                    if offset >= len(resp):
                        raise Exception("out of bounds in qname parsing")
                    l = resp[offset]
                    if l == 0:
                        offset += 1
                        break
                    if (l & 0xC0) == 0xC0:
                        if offset + 1 >= len(resp):
                            raise Exception("truncated pointer")
                        ptr = ((l & 0x3F) << 8) | resp[offset+1]
                        lbl, _ = _parse_name(resp, ptr, depth + 1)
                        labels.append(lbl)
                        offset += 2
                        break
                    if offset + 1 + l > len(resp):
                        raise Exception("label extends past packet")
                    labels.append(resp[offset+1:offset+1+l].decode('ascii', errors='ignore'))
                    offset += 1 + l
                return '.'.join(labels), offset
            # question starts at byte 12
            qname, _ = _parse_name(data, 12)
            return qname
        except Exception:
            return None

    def _extract_qtype_from_wire(self, data: bytes) -> Optional[int]:
        try:
            if not data or len(data) < 12:
                return None
            # skip qname
            def _skip_name(resp, offset, depth=0):
                if depth > 20:
                    raise Exception("pointer loop")
                while True:
                    if offset >= len(resp):
                        raise Exception("oob")
                    l = resp[offset]
                    if l == 0:
                        return offset + 1
                    if (l & 0xC0) == 0xC0:
                        return offset + 2
                    offset += 1 + l
            off = _skip_name(data, 12)
            if off + 4 > len(data):
                return None
            qtype = (data[off] << 8) | data[off+1]
            return qtype
        except Exception:
            return None

    def _make_nxdomain_response(self, query_data: bytes) -> bytes:
        """Return NXDOMAIN wire response preserving TID and question section."""
        if not query_data or len(query_data) < 12:
            # fallback: minimal header with random tid
            tid = 0
            qpart = b''
        else:
            tid = int.from_bytes(query_data[0:2], 'big')
            # copy question (from byte 12 to end of question section)
            # we must find end of qname and include qtype/qclass (4 bytes)
            try:
                # reuse skip
                def _skip_name(resp, offset, depth=0):
                    if depth > 40:
                        raise Exception("pointer loop")
                    while True:
                        if offset >= len(resp):
                            raise Exception("oob")
                        l = resp[offset]
                        if l == 0:
                            return offset + 1
                        if (l & 0xC0) == 0xC0:
                            return offset + 2
                        offset += 1 + l
                qend = _skip_name(query_data, 12)
                qpart = query_data[12:qend + 4]  # name + qtype(2)+qclass(2)
            except Exception:
                qpart = query_data[12:]  # best-effort
        # Build header: QR=1 (0x8000), RCODE=3 (NXDOMAIN => add 3) => flags = 0x8000 | 3 = 0x8003
        flags = 0x8000 | 3
        header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
        return header + qpart

    def _extract_min_ttl(self, response: bytes) -> int:
        """Return minimum TTL present in the answer section (or a default)."""
        try:
            if not response or len(response) < 12:
                return 0
            qdcount = (response[4] << 8) | response[5]
            ancount = (response[6] << 8) | response[7]
            offset = 12
            # skip questions
            def _skip_name(resp, off, depth=0):
                if depth > 40:
                    raise Exception("pointer loop")
                while True:
                    if off >= len(resp):
                        raise Exception("oob")
                    l = resp[off]
                    if l == 0:
                        return off + 1
                    if (l & 0xC0) == 0xC0:
                        return off + 2
                    off += 1 + l
            for _ in range(qdcount):
                _skip_name(response, offset)
                offset += 4
            # read answers
            min_ttl = None
            for _ in range(ancount):
                _, i = self._parse_rr_name(response, offset)
                if i + 10 > len(response):
                    raise Exception("truncated answer header")
                rtype = (response[i] << 8) | response[i+1]; rclass = (response[i+2] << 8) | response[i+3]
                ttl = struct.unpack(">I", response[i+4:i+8])[0]
                rdlen = (response[i+8] << 8) | response[i+9]
                if i + 10 + rdlen > len(response):
                    raise Exception("truncated rdata")
                rdata = response[i+10:i+10+rdlen]
                i += 10 + rdlen
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
            return min_ttl or 0
        except Exception:
            return 0

    def _parse_rr_name(self, response: bytes, offset: int) -> Tuple[str, int]:
        """Parse and return the resource record name from a DNS response.

        Advances offset to the next section.
        """
        labels = []
        try:
            while True:
                if offset >= len(response):
                    raise Exception("out of bounds")
                length = response[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    # pointer
                    if offset + 1 >= len(response):
                        raise Exception("truncated pointer")
                    ptr = ((length & 0x3F) << 8) | response[offset+1]
                    lbl, _ = self._parse_rr_name(response, ptr)
                    labels.append(lbl)
                    offset += 2
                    break
                if offset + 1 + length > len(response):
                    raise Exception("label extends past packet")
                labels.append(response[offset+1:offset+1+length].decode('ascii', errors='ignore'))
                offset += 1 + length
            name = '.'.join(labels)
            return name, offset
        except Exception:
            return "", offset

    async def _cache_get(self, key):
        """Retrieve from cache. Logs hit/miss at DEBUG level."""
        try:
            if self._cache_is_sync:
                val = self._dns_cache.get(key)
            else:
                val = await self._dns_cache.get(key)
            if val is not None:
                self.logger.debug("cache hit for %s -> %s", key, val)
            else:
                self.logger.debug("cache miss for %s", key)
            return val
        except Exception as e:
            self.logger.debug("cache get error for %s: %s", key, e)
            return None

    async def _cache_set(self, key, value):
        """Set cache entry and log at DEBUG."""
        try:
            if self._cache_is_sync:
                self._dns_cache[key] = value
            else:
                await self._dns_cache.set(key, value)
            self.logger.debug("cache set %s -> %s", key, value)
        except Exception as e:
            self.logger.debug("cache set error for %s: %s", key, e)

    async def _with_retries(self, fn, data: bytes, timeout: float):
        """Run fn(data) with retries, exponential backoff, and timeout.

        Logs attempts and backoff timings at DEBUG. Increments Prometheus
        error counter if configured.
        """
        backoff = 0.1
        last_exc = None
        for attempt in range(self.retries):
            try:
                self.logger.debug("attempt %d/%d for %s", attempt + 1, self.retries, fn.__name__)
                start = time.time()
                coro = fn(data)
                result = await asyncio.wait_for(coro, timeout=timeout)
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
                if self.metrics_enabled and self._metrics:
                    try:
                        self._metrics['requests_errors'].labels(proto=self.protocol).inc()
                    except Exception:
                        pass
            await asyncio.sleep(backoff)
            self.logger.debug("backing off %.3fs before next attempt", backoff)
            backoff *= 2
        self.logger.error("all %d attempts failed for %s", self.retries, fn.__name__)
        raise last_exc or Exception("Unknown forward error")

    def _log_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None):
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

    # Public alias for external callers (dserver uses this)
    def log_dns_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None):
        """Public wrapper for internal _log_event to avoid accessing a private method."""
        return self._log_event(status, qname, client, details)

    async def _check_cert_pins(self, hostname: str, ssl_obj):
        """Verify peer certificate against pinned_certs (sha256 of DER cert).

        Logs pin verification attempts and failures.
        """
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
        """Load trust anchors from configured path into memory.

        Accepts self.trust_anchors as either a dict with key 'file' or a string path.
        File format: text lines containing DNSKEY records in presentation format, e.g.
          example.com. 3600 IN DNSKEY 257 3 8 AwEAA...==
        Lines beginning with '#' or ';' are ignored.

        The loader builds two structures:
          - self._dnssec_raw_anchors: mapping dns.name -> dns.rrset of DNSKEYs
          - self._dnssec_keyring: a dns.dnssec.make_keyring(...) result when possible
        """
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
            anchors = {}
            with open(path, 'r') as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    # Expect: name ttl IN DNSKEY flags protocol alg pubkey
                    parts = line.split()
                    if len(parts) < 5:
                        self.logger.debug("skipping malformed anchor line: %s", line)
                        continue
                    # find DNSKEY token position
                    try:
                        idx = parts.index('DNSKEY')
                    except ValueError:
                        # maybe lower-case
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
                        # build rrset from text
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
            # try to build a dns.dnssec keyring for fast validation
            try:
                # make_keyring accepts mapping name->list-of-rdata-or-text; convert to text
                simple = {}
                for name_obj, rr in anchors.items():
                    simple[name_obj] = [r.to_text() for r in rr]
                self._dnssec_keyring = dns.dnssec.make_keyring(simple)
                self.logger.debug("built dnssec keyring from %s (%d names)", path, len(simple))
            except Exception:
                # keep raw anchors and build keyring on demand
                self._dnssec_keyring = None
                self.logger.debug("could not build unified keyring; will build per-name at validation time")
        except Exception as e:
            self.logger.warning("failed to load trust anchors from %s: %s", path, e)

    async def _dnssec_validate(self, qname: str, response_wire: bytes):
        """DNSSEC validation using dnspython in a thread executor.

        This implementation:
          - loads trust anchors from self.trust_anchors (file) via _load_trust_anchors
          - parses the response and, for each non-RRSIG answer rrset, finds matching
            RRSIG rrset and calls dns.dnssec.validate(rrset, rrsigset, keyring)
          - builds a per-name keyring from loaded anchors if a unified keyring wasn't built

        Raises on validation failure.
        """
        if not self.dnssec_enabled:
            return
        if not _HAS_DNSPY:
            raise RuntimeError("dnspython is required for DNSSEC validation")
        # ensure anchors are loaded
        try:
            self._load_trust_anchors()
        except Exception as e:
            self.logger.warning("failed to load trust anchors: %s", e)
            raise
        if not getattr(self, '_dnssec_raw_anchors', None):
            self.logger.warning("DNSSEC enabled but no trust anchors available; aborting validation")
            raise Exception("DNSSEC trust anchors missing")

        def _validate():
            try:
                msg = dns.message.from_wire(response_wire)
                # build lookup of RRSIG sets by name
                rrsig_by_name = {}
                for rr in msg.answer:
                    if rr.rdtype == dns.rdatatype.RRSIG:
                        rrsig_by_name.setdefault(rr.name, []).append(rr)
                # validate each non-RRSIG rrset
                for rrset in msg.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        continue
                    name = rrset.name
                    # find corresponding RRSIG set that covers this type
                    candidate = None
                    sig_sets = rrsig_by_name.get(name)
                    if sig_sets:
                        for s in sig_sets:
                            # s contains one or more RRSIG rdatas; pick those whose type_covered matches
                            # we'll pass the entire s (rrsig rrset) to validate() which expects rrsig rdatas
                            # but ensure at least one covers
                            for r in s:
                                if getattr(r, 'type_covered', None) == rrset.rdtype:
                                    candidate = s
                                    break
                            if candidate:
                                break
                    if candidate is None:
                        raise Exception(f"no RRSIG for rrset {name} type {rrset.rdtype}")
                    # prepare keyring: try unified first, else build per-name
                    if getattr(self, '_dnssec_keyring', None):
                        keyring = self._dnssec_keyring
                    else:
                        # build per-name keyring from raw anchors if present
                        anchors = getattr(self, '_dnssec_raw_anchors', {})
                        ks = {}
                        if name in anchors:
                            ks[name] = [r.to_text() for r in anchors[name]]
                        else:
                            # find closest ancestor anchor name (e.g., '.' or parent zone)
                            for anc_name in anchors:
                                if name.is_subdomain(anc_name):
                                    ks[anc_name] = [r.to_text() for r in anchors[anc_name]]
                                    break
                        if not ks:
                            raise Exception(f"no trust anchor available for {name}")
                        keyring = dns.dnssec.make_keyring(ks)
                    # perform validation (may raise)
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

    async def forward_dns_query(self, data: bytes) -> bytes:
        """Top-level: check blocklist, check wire cache, forward to upstream, DNSSEC validate, store in wire cache."""
        # extract qname and qtype for cache key and blocklist
        qname = self._extract_qname_from_wire(data)
        qtype = self._extract_qtype_from_wire(data) or 1
        key = (qname or "", qtype, self.protocol)

        # blocklist check
        if self.is_blocked(qname):
            self._log_event("Blocked (internal)", qname, None, "blocklist")
            # return NXDOMAIN preserving TID/question
            return self._make_nxdomain_response(data)

        # check wire cache
        cached = await self._wire_cache_get_valid(key)
        if cached:
            self.logger.debug("wire-cache hit %s", key)
            return cached

        # forward by protocol (uses your existing _with_retries + _forward_* methods)
        proto = self.protocol
        if proto == "udp":
            resp = await self._with_retries(self._forward_udp, data, timeout=self.udp_timeout)
        elif proto == "tcp":
            resp = await self._with_retries(self._forward_tcp, data, timeout=self.tcp_timeout)
        elif proto == "tls":
            resp = await self._with_retries(self._forward_tls, data, timeout=self.tcp_timeout)
        elif proto == "https":
            resp = await self._with_retries(self._forward_https, data, timeout=self.doh_timeout)
        elif proto == "quic":
            if not _HAS_AIOQUIC:
                raise RuntimeError("aioquic not available for DoQ")
            resp = await self._with_retries(self._forward_quic, data, timeout=self.doh_timeout)
        else:
            raise ValueError(f"Unsupported protocol {proto}")

        # metrics
        if self.metrics_enabled and self._metrics:
            try:
                self._metrics['requests_total'].labels(proto=proto).inc()
            except Exception:
                pass

        # DNSSEC validate if enabled (existing)
        if self.dnssec_enabled:
            if qname:
                try:
                    await self._dnssec_validate(qname, resp)
                except Exception as e:
                    self.logger.warning("DNSSEC validation failed for %s: %s", qname, e)
                    raise

        # compute TTL to store in wire cache
        ttl = self._extract_min_ttl(resp)
        if ttl <= 0:
            ttl = 30  # small fallback TTL
        await self._wire_cache_set(key, resp, ttl)
        return resp

    # --- forwarding implementations ------------------------------------------------

    async def _forward_udp(self, data: bytes) -> bytes:
        host, port = self._split_hostport(self.upstream_dns, default_port=53)
        resolved = await self._resolve_upstream_ip(host)
        family = socket.AF_INET6 if self._is_ipv6_address(resolved) else socket.AF_INET
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")
        loop = asyncio.get_running_loop()

        # use a connected datagram endpoint approach (clean and async)
        on_response = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def __init__(self):
                self.transport = None
            def connection_made(self, transport):
                self.transport = transport
                try:
                    transport.sendto(data)
                except Exception as e:
                    if not on_response.done():
                        on_response.set_exception(e)
            def datagram_received(self, data, addr):
                if not on_response.done():
                    on_response.set_result(data)
            def error_received(self, exc):
                if not on_response.done():
                    on_response.set_exception(exc)
            def connection_lost(self, exc):
                if exc and not on_response.done():
                    on_response.set_exception(exc)

        transport, proto = await loop.create_datagram_endpoint(lambda: _Proto(), remote_addr=(resolved, int(port)), family=family)
        try:
            resp = await asyncio.wait_for(on_response, timeout=self.udp_timeout)
            return resp
        finally:
            transport.close()

    async def _forward_tcp(self, data: bytes) -> bytes:
        host, port = self._split_hostport(self.upstream_dns, default_port=53)
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
            return resp
        finally:
            writer.close()
            await writer.wait_closed()

    async def _forward_tls(self, data: bytes) -> bytes:
        host, port = self._split_hostport(self.upstream_dns, default_port=853)
        resolved = await self._resolve_upstream_ip(host)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(resolved, int(port), ssl=ssl_ctx, server_hostname=host)
        try:
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                try:
                    await self._check_cert_pins(host, ssl_obj)
                except Exception:
                    writer.close()
                    await writer.wait_closed()
                    raise
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, "big")
            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)
            return resp
        finally:
            writer.close()
            await writer.wait_closed()

    async def _forward_https(self, data: bytes) -> bytes:
        # Build DoH URL
        url = self.upstream_dns if (self.upstream_dns.startswith("http://") or self.upstream_dns.startswith("https://")) \
              else (f"https://{self.upstream_dns}" if "/" in self.upstream_dns else f"https://{self.upstream_dns}/dns-query")
        parsed = urlparse(url)
        host = parsed.hostname
        path = parsed.path or "/dns-query"
        port = parsed.port or 443

        resolved = await self._resolve_upstream_ip(host)

        # open TLS socket to resolved IP but SNI = hostname (so certificate validations work)
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(resolved, port, ssl=ssl_ctx, server_hostname=host)

        try:
            # certificate pin check if configured
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                try:
                    await self._check_cert_pins(host, ssl_obj)
                except Exception:
                    writer.close()
                    await writer.wait_closed()
                    raise

            # send a minimal HTTP/1.1 POST (application/dns-message)
            headers = [
                f"POST {path} HTTP/1.1",
                f"Host: {host}",
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

            # read status + headers
            status_line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
            if not status_line:
                raise Exception("Empty response from DoH upstream")
            status_line = status_line.decode("ascii", errors="ignore").strip()
            if not status_line.startswith("HTTP/"):
                raise Exception(f"Invalid HTTP response start: {status_line}")
            # require 2xx status
            try:
                parts = status_line.split(None, 2)
                status_code = int(parts[1]) if len(parts) > 1 else 0
            except Exception:
                status_code = 0
            if status_code < 200 or status_code >= 300:
                raise Exception(f"DoH upstream returned non-2xx status: {status_line}")

            # read headers
            content_length = None
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

            # warn if content-type unexpected (not fatal)
            if not chunked and content_length is not None and not content_type_ok:
                self.logger.debug("DoH response content-type not application/dns-message; continuing")

            # read body
            if chunked:
                # basic chunk reading
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
                        # consume trailer and break
                        await reader.readuntil(b"\r\n")
                        break
                    chunk = await asyncio.wait_for(reader.readexactly(ln), timeout=self.doh_timeout)
                    body.extend(chunk)
                    # consume CRLF
                    await reader.readexactly(2)
                return bytes(body)
            else:
                if content_length is None:
                    # no content-length, read until EOF
                    body = await asyncio.wait_for(reader.read(), timeout=self.doh_timeout)
                    return body
                else:
                    body = await asyncio.wait_for(reader.readexactly(content_length), timeout=self.doh_timeout)
                    return body
        finally:
            writer.close()
            await writer.wait_closed()

    async def _forward_quic(self, data: bytes):
        host, port = self._split_hostport(self.upstream_dns, default_port=784)
        resolved = await self._resolve_upstream_ip(host)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"], verify_mode=ssl.CERT_REQUIRED)
        from aioquic.asyncio.client import connect
        response_data = bytearray()
        response_event = asyncio.Event()

        class DoQProto:
            def quic_event_received(self, event):
                from aioquic.quic.events import StreamDataReceived
                if isinstance(event, StreamDataReceived):
                    response_data.extend(event.data)
                    if event.end_stream:
                        response_event.set()

        proto = DoQProto()
        async with connect(resolved, int(port), configuration=configuration, create_protocol=lambda *a, **k: proto) as client:
            # best-effort certificate pin check for aioquic client
            try:
                if self.pinned_certs:
                    der = None
                    # try common attributes
                    try:
                        get_chain = getattr(client, 'get_peer_cert_chain', None)
                        if callable(get_chain):
                            chain = get_chain()
                            if chain and isinstance(chain, (list, tuple)):
                                first = chain[0]
                                if isinstance(first, bytes):
                                    der = first
                                elif hasattr(first, 'public_bytes'):
                                    try:
                                        from cryptography.hazmat.primitives.serialization import Encoding
                                        der = first.public_bytes(Encoding.DER)
                                    except Exception:
                                        der = None
                    except Exception:
                        der = None
                    if der:
                        await self._check_cert_pins(host, self._DERPeerWrapper(der))
                    else:
                        self.logger.debug("DoQ: peer cert chain not available for pin-check; skipping")
            except Exception:
                self.logger.exception("DoQ certificate pin check failed")

            quic = client._quic
            stream_id = quic.get_next_available_stream_id()
            quic.send_stream_data(stream_id, len(data).to_bytes(2, "big") + data, end_stream=True)
            # ensure connected and wait for response
            try:
                await client.wait_connected()
            except Exception:
                # older aioquic versions may not have wait_connected; ignore
                pass
            await asyncio.wait_for(response_event.wait(), timeout=self.doh_timeout)
            resp = bytes(response_data)
            if len(resp) < 2:
                raise Exception("Invalid DoQ response")
            resp_len = int.from_bytes(resp[:2], "big")
            return resp[2:2+resp_len]

    # --- name resolution helpers --------------------------------------------------

    def _split_hostport(self, hostport: str, default_port: int = 53) -> Tuple[str, int]:
        """Split 'host:port' and handle IPv6 '[::1]:port' notation.

        Returns (host, port).
        """
        if not hostport:
            return "", default_port
        host = hostport
        port = default_port
        # IPv6 with brackets
        if hostport.startswith("["):
            # [addr]:port or [addr]
            try:
                end = hostport.index("]")
                host = hostport[1:end]
                rest = hostport[end+1:]
                if rest.startswith(":"):
                    port = int(rest[1:])
            except Exception:
                host = hostport
        else:
            # maybe host:port for IPv4 or name
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
        """Small wrapper to present a .getpeercert(binary_form=True) API when we only have DER bytes."""
        def __init__(self, der: bytes):
            self._der = der
        def getpeercert(self, binary_form=False):
            return self._der if binary_form else None

    async def _resolve_upstream_ip(self, hostname: str) -> str:
        """Return a single IP address for hostname, respecting disable_ipv6 and using cache.

        Logs the resolution strategy and outcome; falls back to raw UDP query if configured.
        """
        key = (hostname, bool(self.disable_ipv6))
        cached = await self._cache_get(key)
        if cached:
            self.logger.debug("resolved %s from cache -> %s", hostname, cached)
            return cached

        self.logger.debug("resolving upstream hostname: %s", hostname)
        # 1) try system resolver (fast)
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

        # 2) if dns_resolver_server configured - do a raw UDP query asynchronously
        if self.dns_resolver_server:
            self.logger.debug("falling back to configured dns_resolver_server: %s", self.dns_resolver_server)
            try:
                # split on last colon to allow IPv6 literals without brackets or host:port forms
                parts = self.dns_resolver_server.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    ip, port = parts[0], int(parts[1])
                else:
                    ip, port = parts[0], 53
                # First try A, then AAAA if A fails (makes fallback more robust)
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
        """Perform minimal DNS query (A then AAAA) against resolver_ip:port using non-blocking sockets.

        Logs the outgoing lookup and parses the response, returning the first A/AAAA found.
        """
        self.logger.debug("udp lookup of %s via %s:%d", qname, resolver_ip, resolver_port)
        loop = asyncio.get_running_loop()
        # choose socket family based on resolver_ip
        try:
            ip_obj = ipaddress.ip_address(resolver_ip)
            fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        except Exception:
            fam = socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            # build query for provided qtype (1=A, 28=AAAA)
            tid = int(time.time() * 1000) & 0xFFFF
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split("."))
            q += b"\x00" + struct.pack(">HH", int(qtype), 1)
            query = header + q
            # for IPv6, supply a 4-tuple where supported
            addr_tuple = (resolver_ip, resolver_port) if fam == socket.AF_INET else (resolver_ip, resolver_port, 0, 0)
            await loop.sock_sendto(sock, query, addr_tuple)
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=self.udp_timeout)
            except asyncio.TimeoutError:
                self.logger.debug("udp lookup timed out for %s (qtype=%s)", qname, qtype)
                return None
            # parse answers (very small parser)
            def parse_name(resp, offset, depth=0):
                # depth guards against pointer loops
                if depth > 20:
                    raise Exception("pointer loop in name parsing")
                labels = []
                length = len(resp)
                while True:
                    if offset >= length:
                        raise Exception("truncated pointer")
                    l = resp[offset]
                    if l == 0:
                        offset += 1
                        break
                    if (l & 0xC0) == 0xC0:
                        if offset + 1 >= length:
                            raise Exception("truncated pointer")
                        ptr = ((l & 0x3F) << 8) | resp[offset+1]
                        lbl, _ = parse_name(resp, ptr, depth + 1)
                        labels.append(lbl)
                        offset += 2
                        break
                    if offset + 1 + l > length:
                        raise Exception("label extends past packet")
                    labels.append(resp[offset+1:offset+1+l].decode("ascii", errors="ignore"))
                    offset += 1 + l
                return ".".join(labels), offset
            # skip header+question
            if len(data) < 12:
                raise Exception("short DNS response")
            qdcount = (data[4] << 8) | data[5]
            ancount = (data[6] << 8) | data[7]
            i = 12
            for _ in range(qdcount):
                _, i = parse_name(data, i)
                i += 4
            # read answers
            a_addr = None
            aaaa_addr = None
            for _ in range(ancount):
                _, i = parse_name(data, i)
                if i + 10 > len(data):
                    raise Exception("truncated answer header")
                rtype = (data[i] << 8) | data[i+1]; rclass = (data[i+2] << 8) | data[i+3]
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
                        # fallback to hex formatting
                        aaaa_addr = ":".join("{:02x}{:02x}".format(rdata[j], rdata[j+1]) for j in range(0, 16, 2))
            # return according to requested qtype preference
            if qtype == 1:
                self.logger.debug("udp lookup result for %s (A) -> %s", qname, a_addr)
                return a_addr or None
            if qtype == 28:
                self.logger.debug("udp lookup result for %s (AAAA) -> %s", qname, aaaa_addr)
                return aaaa_addr or None
            # fallback: prefer A then AAAA
            self.logger.debug("udp lookup result for %s -> %s", qname, a_addr or aaaa_addr)
            return a_addr or aaaa_addr
        finally:
            sock.close()

    # ---------- block action helpers ----------
    def set_block_action(self, action: str):
        """Set how the server should respond for blocked domains: 'ZEROIP', 'NXDOMAIN', or 'REFUSED'."""
        try:
            if action is None:
                action = 'NXDOMAIN'
            self._block_action = str(action).upper()
        except Exception:
            self._block_action = 'NXDOMAIN'

    def get_block_action(self) -> str:
        """Return currently configured block action (default 'NXDOMAIN')."""
        return getattr(self, '_block_action', 'NXDOMAIN')

    def build_block_response(self, request_data: bytes, action: Optional[str] = None) -> bytes:
        """Build a wire-format DNS response for a blocked query according to action.

        If action is None, uses the resolver's configured block action.
        """
        use_action = action or self.get_block_action()
        try:
            # if dnspython is available, prefer that for correct formatting
            if _HAS_DNSPY:
                try:
                    request_msg = dns.message.from_wire(request_data)
                except Exception:
                    request_msg = None
                # fallback to NXDOMAIN if parsing failed and action isn't ZEROIP
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
                    # If question is A/AAAA/ANY -> return appropriate zero IP answers
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
            # If dnspython not available, build minimal wire responses
            # NXDOMAIN / REFUSED can be made by preserving TID/question; ZEROIP needs manual answer crafting
            if use_action == 'REFUSED':
                # build header with RCODE=5
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        def _skip_name(resp, offset, depth=0):
                            if depth > 40:
                                raise Exception("pointer loop")
                            while True:
                                if offset >= len(resp):
                                    raise Exception("oob")
                                l = resp[offset]
                                if l == 0:
                                    return offset + 1
                                if (l & 0xC0) == 0xC0:
                                    return offset + 2
                                offset += 1 + l
                        qend = _skip_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000 | 5
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                return header + qpart
            if use_action == 'NXDOMAIN':
                return self._make_nxdomain_response(request_data)
            if use_action == 'ZEROIP':
                # parse qname and qtype and build an answer with pointer to question (0xc00c)
                qname = self._extract_qname_from_wire(request_data)
                qtype = self._extract_qtype_from_wire(request_data) or 1
                # build header
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        def _skip_name(resp, offset, depth=0):
                            if depth > 40:
                                raise Exception("pointer loop")
                            while True:
                                if offset >= len(resp):
                                    raise Exception("oob")
                                l = resp[offset]
                                if l == 0:
                                    return offset + 1
                                if (l & 0xC0) == 0xC0:
                                    return offset + 2
                                offset += 1 + l
                        qend = _skip_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000
                # qdcount=1, ancount=1
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                # answer: name pointer to 0xC00C, type, class IN, ttl, rdlen, rdata
                name_ptr = b'\xc0\x0c'
                if qtype == 1:  # A
                    rtype = (1).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (4).to_bytes(2, 'big')
                    rdata = b'\x00\x00\x00\x00'
                elif qtype == 28:  # AAAA
                    if self.disable_ipv6:
                        return self._make_nxdomain_response(request_data)
                    rtype = (28).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (16).to_bytes(2, 'big')
                    rdata = b'\x00' * 16
                elif qtype == 255:  # ANY
                    # build A + AAAA answers
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