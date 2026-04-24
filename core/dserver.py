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
            qname = None
            request_msg = None
            qtype = None
            try:
                request_msg = dns.message.from_wire(data)
                if request_msg.question:
                    qname = str(request_msg.question[0].name).rstrip('.')
                    qtype = request_msg.question[0].rdtype
            except Exception:
                qname = None

            # Block AAAA queries if disable_ipv6 is True
            if self.resolver.disable_ipv6 and qtype == dns.rdatatype.AAAA:
                # Use the resolver's current block action (not a global)
                action = self.resolver.get_block_action()
                resp_wire = self.resolver.build_block_response(data, action=BLOCK_ACTION_NX)
                self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked AAAA query for {qname} due to disable_ipv6")
                try:
                    self.resolver.log_dns_event('Blocked (internal)', qname, f"{addr[0]}:{addr[1]}", 'Disabled IPv6')
                except Exception:
                    pass
                return

            if qname and self.resolver.is_blocked(qname):
                action = self.resolver.get_block_action()
                resp_wire = self.resolver.build_block_response(data, action=action)
                self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked UDP DNS query for {qname} -> action {action}")
                try:
                    self.resolver.log_dns_event('Blocked (internal)', qname, f"{addr[0]}:{addr[1]}", f"Action={action}")
                except Exception:
                    pass
                return

            # forward to resolver
            response = await self.resolver.forward_dns_query(data)
            # If IPv6 disabled, strip AAAA records from the upstream response
            if self.resolver.disable_ipv6:
                try:
                    resp_msg = dns.message.from_wire(response)
                    resp_msg.answer = [rr for rr in resp_msg.answer if rr.rdtype != dns.rdatatype.AAAA]
                    resp_msg.additional = [rr for rr in resp_msg.additional if rr.rdtype != dns.rdatatype.AAAA]
                    response = resp_msg.to_wire()
                except Exception:
                    # leave original response if parsing fails
                    pass
            self.transport.sendto(response, addr)
            logging.debug(f"Sent UDP DNS response to {addr}")
            try:
                self.resolver.log_dns_event('Processed', qname, f"{addr[0]}:{addr[1]}")
            except Exception:
                pass
        except Exception as e:
            logging.error(f"Error handling UDP DNS query from {addr}: {e}")


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resolver: DNSResolver):
    peer = writer.get_extra_info('peername')
    logging.debug(f"Accepted TCP connection from {peer}")
    try:
        length_bytes = await reader.readexactly(2)
        length = int.from_bytes(length_bytes, 'big')
        data = await reader.readexactly(length)
        qname = None
        request_msg = None
        qtype = None
        try:
            request_msg = dns.message.from_wire(data)
            if request_msg.question:
                qname = str(request_msg.question[0].name).rstrip('.')
                qtype = request_msg.question[0].rdtype
        except Exception:
            qname = None

        # Block AAAA queries if disable_ipv6 is True
        if resolver.disable_ipv6 and qtype == dns.rdatatype.AAAA:
            resp_wire = resolver.build_block_response(data, action='NXDOMAIN')
            writer.write(len(resp_wire).to_bytes(2, 'big') + resp_wire)
            await writer.drain()
            logging.debug(f"Blocked AAAA query for {qname} due to disable_ipv6")
            try:
                resolver.log_dns_event('Blocked (internal)', qname, f"{peer[0]}:{peer[1]}", 'Disabled IPv6')
            except Exception:
                pass
            return

        if qname and resolver.is_blocked(qname):
            action = resolver.get_block_action()
            resp_wire = resolver.build_block_response(data, action=action)
            writer.write(len(resp_wire).to_bytes(2, 'big') + resp_wire)
            await writer.drain()
            logging.debug(f"Blocked TCP DNS query for {qname} -> action {action}")
            try:
                resolver.log_dns_event('Blocked (internal)', qname, f"{peer[0]}:{peer[1]}", f"Action={action}")
            except Exception:
                pass
            return

        response = await resolver.forward_dns_query(data)
        # Strip AAAA records if IPv6 is disabled (matching UDP behaviour)
        if resolver.disable_ipv6:
            try:
                resp_msg = dns.message.from_wire(response)
                resp_msg.answer = [rr for rr in resp_msg.answer if rr.rdtype != dns.rdatatype.AAAA]
                resp_msg.additional = [rr for rr in resp_msg.additional if rr.rdtype != dns.rdatatype.AAAA]
                response = resp_msg.to_wire()
            except Exception:
                pass
        try:
            resolver.log_dns_event('Processed', qname, f"{peer[0]}:{peer[1]}")
        except Exception:
            pass
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


async def run_server(listen_ip: str, listen_port: int, upstream_dns: str, protocol: str,
                     dns_resolver_server: str = None, verbose: bool = False,
                     blocklists: dict = None, disable_ipv6: bool = False,
                     dns_cache_ttl: int = 300, dns_cache_max_size: int = 1024,
                     dns_logging_enabled: bool = False, dns_log_retention_days: int = 7,
                     dns_log_dir: str = '/var/log/phantomd', dns_log_prefix: str = 'dns-log',
                     dns_pinned_certs: dict = None, dnssec_enabled: bool = False,
                     trust_anchors_file: str = None, metrics_enabled: bool = False,
                     metrics_port: int = 8000, uvloop_enable: bool = False,
                     upstream_retries: int = 2, upstream_initial_backoff: float = 0.1,
                     upstream_udp_timeout: float = 2.0, upstream_tcp_timeout: float = 5.0,
                     upstream_doh_timeout: float = 5.0):
    # Set root logger level
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)

    resolver = DNSResolver(
        upstream_dns=upstream_dns,
        protocol=protocol,
        dns_resolver_server=dns_resolver_server,
        verbose=verbose,
        disable_ipv6=disable_ipv6,
        cache_ttl=dns_cache_ttl,
        cache_max_size=dns_cache_max_size,
        doh_timeout=upstream_doh_timeout,
        udp_timeout=upstream_udp_timeout,
        tcp_timeout=upstream_tcp_timeout,
        retries=upstream_retries,
        dns_logging_enabled=dns_logging_enabled,
        dns_log_dir=dns_log_dir,
        pinned_certs=dns_pinned_certs,
        dnssec_enabled=dnssec_enabled,
        trust_anchors=None if not trust_anchors_file else {'file': trust_anchors_file},
        metrics_enabled=metrics_enabled,
        metrics_port=metrics_port,
        uvloop_enable=uvloop_enable,
    )

    loop = asyncio.get_running_loop()

    # --- Blocklist loading and scheduling (single consolidated block) ---
    if blocklists:
        action = blocklists.get('action', 'NXDOMAIN')
        resolver.set_block_action(action)

        urls = blocklists.get('urls', []) or []
        local_dir = blocklists.get('local_blocklist_dir', 'blocklists')

        # Initial fetch + immediate load
        if urls:
            try:
                await fetch_blocklists(urls, destination_dir=local_dir)
                logging.info("Initial blocklist fetch complete")
            except Exception as e:
                logging.warning("Initial async blocklist fetch failed: %s", e)

        # Load from disk after fetch (so fresh data is used)
        try:
            exact_set, suffix_set, hosts_map = resolver.load_blocklists_from_dir(local_dir)
            domains = list(exact_set) + ['.' + s for s in suffix_set]
            resolver.set_blocklist(domains)
            resolver.set_hosts_map(hosts_map)
        except Exception as e:
            logging.warning("Failed to load blocklists from %s: %s", local_dir, e)

        # Schedule periodic refresh if enabled and urls are configured
        if blocklists.get('enabled') and urls:
            interval = blocklists.get('interval_seconds', 86400)

            # Background task for fetching and then reloading parsed lists
            async def periodic_reload():
                while True:
                    await asyncio.sleep(interval)
                    try:
                        await fetch_blocklists(urls, destination_dir=local_dir)
                        exact_set, suffix_set, hosts_map = resolver.load_blocklists_from_dir(local_dir)
                        domains = list(exact_set) + ['.' + s for s in suffix_set]
                        resolver.set_blocklist(domains)
                        resolver.set_hosts_map(hosts_map)
                        logging.debug("Blocklists reloaded")
                    except Exception as e:
                        logging.warning("Periodic blocklist reload failed: %s", e)

            loop.create_task(periodic_reload())
            logging.info("Scheduled periodic blocklist refresh every %s seconds", interval)

    # UDP listener
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPResolverProtocol(resolver),
        local_addr=(listen_ip, listen_port)
    )
    logging.info(f"DNS UDP listener running on {listen_ip}:{listen_port}")

    # TCP listener
    server = await asyncio.start_server(
        lambda r, w: _tcp_handler(r, w, resolver),
        listen_ip, listen_port
    )
    logging.info(f"DNS TCP listener running on {listen_ip}:{listen_port}")

    try:
        await server.serve_forever()
    finally:
        udp_transport.close()
        server.close()
        await server.wait_closed()


def run_server_sync(listen_ip: str, listen_port: int, upstream_dns: str, protocol: str,
                    dns_resolver_server: str = None, verbose: bool = False,
                    blocklists: dict = None, disable_ipv6: bool = False,
                    **kwargs):
    # Wrapper that passes all extra keyword arguments to the async version
    asyncio.run(run_server(
        listen_ip, listen_port, upstream_dns, protocol,
        dns_resolver_server=dns_resolver_server,
        verbose=verbose,
        blocklists=blocklists,
        disable_ipv6=disable_ipv6,
        **kwargs
    ))