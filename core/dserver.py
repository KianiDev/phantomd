import asyncio
import logging
import os
from typing import Dict, Set, Tuple, Optional

from core.resolver import DNSResolver
from utils.ListUpdater import fetch_blocklists, periodic_fetch

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.rcode
import dns.resolver


BLOCK_ACTION_ZEROIP = 'ZEROIP'
BLOCK_ACTION_NX = 'NXDOMAIN'
BLOCK_ACTION_REFUSED = 'REFUSED'

# runtime block data
BLOCK_EXACT: Set[str] = set()
BLOCK_SUFFIX: Set[str] = set()
BLOCK_HOSTS: Dict[str, Tuple[str]] = {}
BLOCK_ACTION = BLOCK_ACTION_NX


def load_blocklists_from_dir(directory: str) -> Tuple[Set[str], Set[str], Dict[str, Tuple[str]]]:
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


def _is_blocked(qname: str) -> bool:
    q = qname.lower().rstrip('.')
    if q in BLOCK_EXACT:
        return True
    # suffix match
    labels = q.split('.')
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in BLOCK_SUFFIX:
            return True
    return False


def _build_block_response(request_msg: dns.message.Message, action: str) -> bytes:
    # defensive: if parsing failed, return a simple RCODE response
    if request_msg is None:
        resp = dns.message.Message()
        if action == BLOCK_ACTION_REFUSED:
            resp.set_rcode(dns.rcode.REFUSED)
        else:
            resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp.to_wire()

    # create a response based on action
    resp = dns.message.make_response(request_msg)
    # clear any accidentally included answer sections
    resp.answer = []

    if action == BLOCK_ACTION_REFUSED:
        resp.set_rcode(dns.rcode.REFUSED)
        return resp.to_wire()

    if action == BLOCK_ACTION_NX:
        resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp.to_wire()

    if action == BLOCK_ACTION_ZEROIP:
        # If question is A/AAAA/ANY -> return appropriate zero IP answers
        q = request_msg.question[0]
        qname = q.name
        qtype = q.rdtype
        ttl = 60
        if qtype == dns.rdatatype.A:
            rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
            resp.answer.append(rrset)
            return resp.to_wire()
        elif qtype == dns.rdatatype.AAAA:
            rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
            resp.answer.append(rrset)
            return resp.to_wire()
        elif qtype == dns.rdatatype.ANY:
            a = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
            aaaa = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
            resp.answer.append(a)
            resp.answer.append(aaaa)
            return resp.to_wire()
        # fallback NXDOMAIN for other types
        resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp.to_wire()

    # default NXDOMAIN
    resp.set_rcode(dns.rcode.NXDOMAIN)
    return resp.to_wire()


class UDPResolverProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: DNSResolver):
        self.resolver = resolver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logging.debug("UDP listener started")

    def datagram_received(self, data, addr):
        logging.debug(f"Received UDP DNS query from {addr}")
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        try:
            # parse
            qname = None
            request_msg = None
            try:
                request_msg = dns.message.from_wire(data)
                if request_msg.question:
                    qname = str(request_msg.question[0].name).rstrip('.')
            except Exception:
                qname = None
            if qname and _is_blocked(qname):
                resp_wire = _build_block_response(request_msg, BLOCK_ACTION)
                self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked UDP DNS query for {qname} -> action {BLOCK_ACTION}")
                return
            # forward to resolver
            response = await self.resolver.forward_dns_query(data)
            self.transport.sendto(response, addr)
            logging.debug(f"Sent UDP DNS response to {addr}")
        except Exception as e:
            logging.error(f"Error handling UDP DNS query from {addr}: {e}")


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resolver: DNSResolver):
    peer = writer.get_extra_info('peername')
    logging.debug(f"Accepted TCP connection from {peer}")
    try:
        length_bytes = await reader.readexactly(2)
        length = int.from_bytes(length_bytes, 'big')
        data = await reader.readexactly(length)
        # Check blocking before forwarding
        qname = None
        request_msg = None
        try:
            request_msg = dns.message.from_wire(data)
            if request_msg.question:
                qname = str(request_msg.question[0].name).rstrip('.')
        except Exception:
            qname = None
        if qname and _is_blocked(qname):
            resp_wire = _build_block_response(request_msg, BLOCK_ACTION)
            # send with length prefix
            writer.write(len(resp_wire).to_bytes(2, 'big') + resp_wire)
            await writer.drain()
            logging.debug(f"Blocked TCP DNS query for {qname} -> action {BLOCK_ACTION}")
            return
        response = await resolver.forward_dns_query(data)
        resp_len = len(response).to_bytes(2, 'big')
        writer.write(resp_len + response)
        await writer.drain()
        logging.debug(f"Sent TCP DNS response to {peer}")
    except Exception as e:
        logging.error(f"Error handling TCP DNS query from {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_server(listen_ip: str, listen_port: int, upstream_dns: str, protocol: str, dns_resolver_server: str = None, verbose: bool = False, blocklists: dict = None, disable_ipv6: bool = False):
    """Start UDP and TCP DNS listeners and forward queries to DNSResolver.forward_dns_query.

    This function does NOT start the resolver's internal listener; it instantiates the resolver object only
    to reuse its forwarding logic.
    """
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)

    # pass disable_ipv6 into resolver so it avoids IPv6 resolution
    resolver = DNSResolver(upstream_dns, protocol, dns_resolver_server, verbose, disable_ipv6=disable_ipv6)

    loop = asyncio.get_running_loop()

    # load blocklists
    global BLOCK_EXACT, BLOCK_HOSTS, BLOCK_SUFFIX, BLOCK_ACTION
    BLOCK_EXACT = set()
    BLOCK_HOSTS = {}
    BLOCK_SUFFIX = set()
    BLOCK_ACTION = BLOCK_ACTION_NX
    if blocklists:
        BLOCK_ACTION = blocklists.get('action', BLOCK_ACTION_NX)
        exact_set, suffix_set, hosts_map = load_blocklists_from_dir('blocklists')
        BLOCK_EXACT.update(exact_set)
        BLOCK_SUFFIX.update(suffix_set)
        BLOCK_HOSTS.update(hosts_map)

    # UDP listener
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPResolverProtocol(resolver),
        local_addr=(listen_ip, listen_port)
    )
    logging.info(f"DNS UDP listener running on {listen_ip}:{listen_port}")

    # TCP listener
    server = await asyncio.start_server(lambda r, w: _tcp_handler(r, w, resolver), listen_ip, listen_port)
    logging.info(f"DNS TCP listener running on {listen_ip}:{listen_port}")

    # Handle blocklists: perform initial fetch (wait) and schedule periodic refresh
    if blocklists and blocklists.get('enabled'):
        urls = blocklists.get('urls', [])
        interval = blocklists.get('interval_seconds', 86400)
        if urls:
            try:
                results = await fetch_blocklists(urls)
                # results is list of (source, True/False)
                failed = [src for src, ok in results if not ok]
                if failed:
                    logging.warning(f"Some blocklist sources failed to fetch: {failed}")
            except Exception as e:
                logging.warning(f"Initial blocklist fetch failed: {e}")
            # schedule periodic refresh in background
            loop.create_task(periodic_fetch(urls, interval, 'blocklists'))
            # schedule reload of parsed lists after each fetch (simple approach: poll files periodically)
            async def reload_loop():
                while True:
                    await asyncio.sleep(interval)
                    exact_set, hosts_map = load_blocklists_from_dir('blocklists')[:2]
                    # load_blocklists_from_dir returns (exact, suffix, hosts)
                    exact_set, suffix_set, hosts_map = load_blocklists_from_dir('blocklists')
                    BLOCK_EXACT.clear(); BLOCK_EXACT.update(exact_set)
                    BLOCK_HOSTS.clear(); BLOCK_HOSTS.update(hosts_map)
                    BLOCK_SUFFIX.clear(); BLOCK_SUFFIX.update(suffix_set)
            loop.create_task(reload_loop())

    try:
        await server.serve_forever()
    finally:
        udp_transport.close()
        server.close()
        await server.wait_closed()


def run_server_sync(listen_ip: str, listen_port: int, upstream_dns: str, protocol: str, dns_resolver_server: str = None, verbose: bool = False, blocklists: dict = None, disable_ipv6: bool = False):
    asyncio.run(run_server(listen_ip, listen_port, upstream_dns, protocol, dns_resolver_server, verbose, blocklists, disable_ipv6))