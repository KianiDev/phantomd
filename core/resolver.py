import asyncio
from asyncio import DatagramProtocol
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

class DNSResolver(DatagramProtocol):
    def __init__(self, listen_ip, listen_port, upstream_dns, protocol, dns_resolver_server=None, verbose=False):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.protocol = protocol.lower()
        self.dns_resolver_server = dns_resolver_server
        self.verbose = verbose
        self.logger = logging.getLogger("DNSResolver")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        self.logger.addHandler(handler)

    async def start(self):
        self.logger.info(f"Starting DNS resolver on {self.listen_ip}:{self.listen_port} using {self.protocol.upper()} upstream {self.upstream_dns}")
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=(self.listen_ip, self.listen_port)
        )
        self.logger.info("DNS resolver is running.")
        try:
            await asyncio.Future()  # Run forever
        finally:
            transport.close()

    def connection_made(self, transport):
        self.transport = transport
        self.logger.debug("Connection made.")

    def datagram_received(self, data, addr):
        self.logger.debug(f"Received DNS query from {addr}")
        asyncio.create_task(self.handle_dns_query(data, addr))

    async def handle_dns_query(self, data, addr):
        try:
            response = await self.forward_dns_query(data)
            self.transport.sendto(response, addr)
            self.logger.debug(f"Sent DNS response to {addr}")
        except Exception as e:
            self.logger.error(f"Error handling DNS query: {e}")

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
        ip, port = self.upstream_dns.split(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(data, (ip, int(port)))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response

    async def _forward_tcp(self, data: bytes) -> bytes:
        ip, port = self.upstream_dns.split(":")
        reader, writer = await asyncio.open_connection(ip, int(port))
        length = len(data).to_bytes(2, 'big')
        writer.write(length + data)
        await writer.drain()
        resp_len = int.from_bytes(await reader.readexactly(2), 'big')
        response = await reader.readexactly(resp_len)
        writer.close()
        await writer.wait_closed()
        return response

    async def _forward_tls(self, data: bytes) -> bytes:
        ip, port = self.upstream_dns.split(":")
        ssl_ctx = ssl.create_default_context()
        resolved_ip = await self._resolve_upstream_ip(ip)
        reader, writer = await asyncio.open_connection(resolved_ip, int(port), ssl=ssl_ctx, server_hostname=ip)
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
        # Use original hostname in URL, set Host header, and monkeypatch getaddrinfo for custom DNS resolution
        import socket as pysocket
        orig_getaddrinfo = pysocket.getaddrinfo
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host == parsed.hostname:
                return [(pysocket.AF_INET, pysocket.SOCK_STREAM, 6, '', (resolved_ip, port))]
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
        # Use custom DNS server to resolve hostname
        if not self.dns_resolver_server:
            return socket.gethostbyname(hostname)
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
        answers = []
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
                answers.append('.'.join(str(b) for b in rdata))
            elif rtype == 28 and rdlength == 16:  # AAAA record
                answers.append(':'.join('{:x}'.format((rdata[j]<<8)|rdata[j+1]) for j in range(0,16,2)))
            elif rtype == 5:  # CNAME
                cname, _ = parse_name(resp, i - rdlength)
                # Recursively resolve CNAME
                return await self._resolve_upstream_ip(cname)
        if answers:
            return answers[0]
        raise Exception("No A or AAAA record found in DNS response")

def run_resolver(listen_ip, listen_port, upstream_dns, protocol, dns_resolver_server=None, verbose=False):
    resolver = DNSResolver(listen_ip, listen_port, upstream_dns, protocol, dns_resolver_server, verbose)
    asyncio.run(resolver.start())