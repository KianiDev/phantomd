import asyncio
import logging
import socket
from typing import Optional
import ssl
import httpx
try:
    import aioquic.asyncio
    from aioquic.quic.configuration import QuicConfiguration
except ImportError:
    aioquic = None

class DNSResolver:
    def __init__(self, upstream_dns, protocol, dns_resolver_server=None, verbose=False, disable_ipv6=False, cache_ttl: int = 300, cache_max_size: int = 1024, dns_logging_enabled: bool = False, dns_log_retention_days: int = 7, dns_log_dir: str = '/var/log/phantomd', dns_log_prefix: str = 'dns-log'):
        self.upstream_dns = upstream_dns
        self.protocol = protocol.lower()
        self.dns_resolver_server = dns_resolver_server
        self.verbose = verbose
        self.disable_ipv6 = disable_ipv6
        self.logger = logging.getLogger("DNSResolver")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        self.logger.addHandler(handler)
        # DNS hostname cache (TTL-configurable)
        try:
            from cachetools import TTLCache
            self._dns_cache = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
        except Exception:
            # Fallback to a simple dict with no TTL if cachetools is unavailable
            self._dns_cache = {}
        # DNS request logging configuration
        self.dns_logging_enabled = bool(dns_logging_enabled)
        self.dns_log_retention_days = int(dns_log_retention_days) if dns_logging_enabled else 0
        self.dns_log_dir = dns_log_dir
        self.dns_log_prefix = dns_log_prefix
        self._file_logger = None
        if self.dns_logging_enabled:
            try:
                import os, datetime
                os.makedirs(self.dns_log_dir, exist_ok=True)
                today = datetime.date.today().strftime('%Y-%m-%d')
                logfile = os.path.join(self.dns_log_dir, f"{self.dns_log_prefix}-{today}.log")
                file_logger = logging.getLogger(f"DNS_REQUEST_LOGGER")
                file_logger.setLevel(logging.INFO)
                # avoid adding multiple handlers if re-init
                if not any(isinstance(h, logging.FileHandler) and h.baseFilename == logfile for h in file_logger.handlers):
                    fh = logging.FileHandler(logfile, mode='a')
                    fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
                    file_logger.addHandler(fh)
                self._file_logger = file_logger
                # cleanup old logs
                try:
                    cutoff = datetime.datetime.now() - datetime.timedelta(days=self.dns_log_retention_days)
                    for fname in os.listdir(self.dns_log_dir):
                        if not fname.startswith(self.dns_log_prefix):
                            continue
                        fpath = os.path.join(self.dns_log_dir, fname)
                        try:
                            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(fpath))
                            if mtime < cutoff:
                                os.remove(fpath)
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                # fail quietly and keep file logging disabled
                self.dns_logging_enabled = False
                self._file_logger = None

    async def forward_dns_query(self, data: bytes) -> bytes:
        if self.protocol == "udp":
            return await self._forward_udp(data)
        elif self.protocol == "tcp":
            return await self._forward_tcp(data)
        elif self.protocol == "tls":
            return await self._forward_tls(data)
        elif self.protocol == "https":
            return await self._forward_https(data)
        elif self.protocol == "quic" and aioquic:
            return await self._forward_quic(data)
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

    async def _forward_udp(self, data: bytes) -> bytes:
        # parse host:port (allow host names)
        hostport = self.upstream_dns
        if ':' in hostport and not hostport.startswith('http'):
            host, port = hostport.rsplit(':', 1)
        else:
            host = hostport
            port = 53
        resolved_ip = await self._resolve_upstream_ip(host)
        # select address family
        family = socket.AF_INET6 if ':' in resolved_ip else socket.AF_INET
        if self.disable_ipv6 and family == socket.AF_INET6:
            raise Exception("IPv6 resolution disabled but upstream resolved to IPv6")
        loop = asyncio.get_running_loop()
        # Use an asyncio DatagramProtocol so UDP I/O doesn't block the event loop
        class _ClientProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.transport = None
                # future that will be set when a response arrives or an error occurs
                self.on_response = loop.create_future()
            def connection_made(self, transport):
                self.transport = transport
                try:
                    # send immediately to the connected remote
                    self.transport.sendto(data)
                except Exception as e:
                    if not self.on_response.done():
                        self.on_response.set_exception(e)
            def datagram_received(self, data_bytes, addr):
                if not self.on_response.done():
                    self.on_response.set_result(data_bytes)
            def error_received(self, exc):
                if not self.on_response.done():
                    self.on_response.set_exception(exc)
            def connection_lost(self, exc):
                if exc and not self.on_response.done():
                    self.on_response.set_exception(exc)
        protocol = _ClientProtocol()
        # create a connected datagram endpoint to the resolved upstream
        transport, _ = await loop.create_datagram_endpoint(lambda: protocol, remote_addr=(resolved_ip, int(port)), family=family)
        try:
            resp = await asyncio.wait_for(protocol.on_response, timeout=2)
            return resp
        finally:
            transport.close()

    async def _forward_tcp(self, data: bytes) -> bytes:
        hostport = self.upstream_dns
        if ':' in hostport and not hostport.startswith('http'):
            host, port = hostport.rsplit(':', 1)
        else:
            host = hostport
            port = 53
        resolved_ip = await self._resolve_upstream_ip(host)
        if self.disable_ipv6 and ':' in resolved_ip:
            raise Exception("IPv6 resolution disabled but upstream resolved to IPv6")
        reader, writer = await asyncio.open_connection(resolved_ip, int(port))
        length = len(data).to_bytes(2, 'big')
        writer.write(length + data)
        await writer.drain()
        resp_len = int.from_bytes(await reader.readexactly(2), 'big')
        response = await reader.readexactly(resp_len)
        writer.close()
        await writer.wait_closed()
        return response

    async def _forward_tls(self, data: bytes) -> bytes:
        hostport = self.upstream_dns
        if ':' in hostport:
            host, port = hostport.rsplit(':', 1)
        else:
            host = hostport
            port = 853
        ssl_ctx = ssl.create_default_context()
        resolved_ip = await self._resolve_upstream_ip(host)
        if self.disable_ipv6 and ':' in resolved_ip:
            raise Exception("IPv6 resolution disabled but upstream resolved to IPv6")
        reader, writer = await asyncio.open_connection(resolved_ip, int(port), ssl=ssl_ctx, server_hostname=host)
        length = len(data).to_bytes(2, 'big')
        writer.write(length + data)
        await writer.drain()
        resp_len = int.from_bytes(await reader.readexactly(2), 'big')
        response = await reader.readexactly(resp_len)
        writer.close()
        await writer.wait_closed()
        return response

    async def _forward_https(self, data: bytes) -> bytes:
        # DNS-over-HTTPS (RFC 8484)
        # If upstream_dns looks like a full path, use it as the URL. Otherwise, append /dns-query.
        if self.upstream_dns.startswith("http://") or self.upstream_dns.startswith("https://"):
            url = self.upstream_dns
        elif "/" in self.upstream_dns:
            url = f"https://{self.upstream_dns}"
        else:
            url = f"https://{self.upstream_dns}/dns-query"
        from urllib.parse import urlparse
        parsed = urlparse(url)
        resolved_ip = await self._resolve_upstream_ip(parsed.hostname)
        # If disable_ipv6 and resolved_ip is IPv6, raise
        if self.disable_ipv6 and ':' in resolved_ip:
            raise Exception("IPv6 resolution disabled but upstream resolved to IPv6")
        # Use original hostname in URL, set Host header, and monkeypatch getaddrinfo for custom DNS resolution
        import socket as pysocket
        orig_getaddrinfo = pysocket.getaddrinfo
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host == parsed.hostname:
                # choose family matching resolved_ip
                fam = pysocket.AF_INET6 if ':' in resolved_ip else pysocket.AF_INET
                return [(fam, pysocket.SOCK_STREAM, 6, '', (resolved_ip, port))]
            return orig_getaddrinfo(host, port, family, type, proto, flags)
        pysocket.getaddrinfo = fake_getaddrinfo
        try:
            async with httpx.AsyncClient(http2=True) as client:
                headers = {"Content-Type": "application/dns-message", "Host": parsed.hostname}
                resp = await client.post(url, content=data, headers=headers)
                resp.raise_for_status()
                return resp.content
        finally:
            pysocket.getaddrinfo = orig_getaddrinfo

    async def _forward_quic(self, data: bytes) -> bytes:
        # DNS-over-QUIC (RFC 9250) implementation using aioquic
        # upstream_dns should be in the form "host:port"
        host, port = self.upstream_dns.split(":")
        port = int(port)
        resolved_ip = await self._resolve_upstream_ip(host)
        # if disable_ipv6 ensure resolved_ip is IPv4
        if self.disable_ipv6 and ':' in resolved_ip:
            raise Exception("IPv6 resolution disabled but upstream resolved to IPv6")
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"], verify_mode=ssl.CERT_REQUIRED)
        from aioquic.asyncio.client import connect
        response_data = bytearray()
        response_event = asyncio.Event()
        class DoQProtocol:
            def __init__(self):
                self.response = None
            def quic_event_received(self, event):
                from aioquic.quic.events import StreamDataReceived
                if isinstance(event, StreamDataReceived):
                    response_data.extend(event.data)
                    if event.end_stream:
                        response_event.set()
        protocol = DoQProtocol()
        async with connect(
            resolved_ip,
            port,
            configuration=configuration,
            create_protocol=lambda *_: protocol
        ) as client:
            quic = client._quic
            stream_id = quic.get_next_available_stream_id()
            length_prefix = len(data).to_bytes(2, "big")
            quic.send_stream_data(stream_id, length_prefix + data, end_stream=True)
            await client.wait_connected()
            await response_event.wait()
            response = bytes(response_data)
            if len(response) < 2:
                raise Exception("Invalid DoQ response")
            resp_len = int.from_bytes(response[:2], "big")
            return response[2:2+resp_len]


    async def _resolve_upstream_ip(self, hostname):
        # basic caching: key includes disable_ipv6 to avoid returning an IPv6 address when IPv6 is disabled
        key = (hostname, bool(self.disable_ipv6))
        try:
            cached = self._dns_cache.get(key)
        except Exception:
            cached = None
        if cached:
            return cached

        selected = None
        # Use custom DNS server to resolve hostname
        if not self.dns_resolver_server:
            # prefer IPv4 when disable_ipv6
            try:
                if self.disable_ipv6:
                    selected = socket.gethostbyname(hostname)
                else:
                    # try to return any address (v4 or v6)
                    infos = socket.getaddrinfo(hostname, None)
                    for info in infos:
                        addr = info[4][0]
                        if addr:
                            if self.disable_ipv6 and ':' in addr:
                                continue
                            selected = addr
                            break
            except Exception:
                selected = None
            if selected:
                try:
                    self._dns_cache[key] = selected
                except Exception:
                    pass
                return selected
        # fall back to querying configured DNS resolver server
        ip, port = self.dns_resolver_server.split(":")
        import random, struct
        tid = random.randint(0, 65535)
        flags = 0x0100
        qdcount = 1
        header = struct.pack('>HHHHHH', tid, flags, qdcount, 0, 0, 0)
        parts = hostname.split('.')
        question = b''.join([bytes([len(p)]) + p.encode() for p in parts]) + b'\x00' + struct.pack('>HH', 1, 1)
        query = header + question
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(query, (ip, int(port)))
        resp, _ = s.recvfrom(512)
        s.close()
        # Parse response for A and AAAA records, follow CNAMEs
        def parse_name(resp, offset):
            labels = []
            while True:
                length = resp[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0 == 0xC0:
                    ptr = ((length & 0x3F) << 8) | resp[offset+1]
                    labels.append(parse_name(resp, ptr)[0])
                    offset += 2
                    break
                labels.append(resp[offset+1:offset+1+length].decode())
                offset += 1 + length
            return '.'.join(labels), offset
        i = 12
        # Skip question section
        for _ in range(qdcount):
            _, i = parse_name(resp, i)
            i += 4
        a_answers = []
        aaaa_answers = []
        ancount = (resp[6] << 8) | resp[7]
        for _ in range(ancount):
            name, i = parse_name(resp, i)
            rtype = (resp[i] << 8) | resp[i+1]
            rclass = (resp[i+2] << 8) | resp[i+3]
            ttl = struct.unpack('>I', resp[i+4:i+8])[0]
            rdlength = (resp[i+8] << 8) | resp[i+9]
            rdata = resp[i+10:i+10+rdlength]
            i += 10 + rdlength
            if rtype == 1 and rdlength == 4:  # A record
                a_answers.append('.'.join(str(b) for b in rdata))
            elif rtype == 28 and rdlength == 16:  # AAAA record
                aaaa_answers.append(':'.join('{:x}'.format((rdata[j]<<8)|rdata[j+1]) for j in range(0,16,2)))
            elif rtype == 5:  # CNAME
                cname, _ = parse_name(resp, i - rdlength)
                # Recursively resolve CNAME
                selected = await self._resolve_upstream_ip(cname)
                # cache and return
                try:
                    self._dns_cache[key] = selected
                except Exception:
                    pass
                return selected
        # Decide which answer to return
        # Prefer A records for IPv4-first behavior
        if self.disable_ipv6:
            if a_answers:
                selected = a_answers[0]
            else:
                # try system resolver for IPv4 fallback
                try:
                    infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
                    for info in infos:
                        addr = info[4][0]
                        if addr:
                            selected = addr
                            break
                except Exception:
                    pass
                # if only AAAA available and IPv6 disabled, raise
                if not selected and aaaa_answers:
                    raise Exception("IPv6 resolution disabled and only AAAA records found for %s" % hostname)
        else:
            if a_answers:
                selected = a_answers[0]
            elif aaaa_answers:
                selected = aaaa_answers[0]
        # fallback: try system resolver (both families)
        if not selected:
            try:
                infos = socket.getaddrinfo(hostname, None)
                for info in infos:
                    addr = info[4][0]
                    if addr:
                        if self.disable_ipv6 and ':' in addr:
                            continue
                        selected = addr
                        break
            except Exception:
                pass
        if selected:
            try:
                self._dns_cache[key] = selected
            except Exception:
                pass
            return selected
        raise Exception("No A or AAAA record found in DNS response")

    def log_dns_event(self, status: str, qname: Optional[str], client_addr: Optional[str], details: Optional[str] = None):
        """Log DNS request event to configured file logger (if enabled).
        status: one of 'Processed', 'Blocked (provider)', 'Blocked (internal)'
        qname: queried domain
        client_addr: client ip:port or peer identifier
        details: optional additional information
        """
        entry = f"{status}\tqname={qname}\tclient={client_addr}"
        if details:
            entry += f"\t{details}"
        # console logger as well
        if status.startswith('Blocked'):
            self.logger.info(entry)
        else:
            self.logger.debug(entry)
        if self.dns_logging_enabled and self._file_logger:
            try:
                self._file_logger.info(entry)
            except Exception:
                pass