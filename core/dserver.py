import asyncio
import logging
import os
from typing import Dict, Set, Tuple, Optional, Any

from core.resolver import DNSResolver, RateLimiter
from utils.ListUpdater import fetch_blocklists, periodic_fetch

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.rcode
import dns.resolver


class ResolverHolder:
    """Mutable container that allows atomic resolver swaps.
    UDP and TCP handlers read from this instead of holding a direct reference.
    """
    def __init__(self, resolver: DNSResolver) -> None:
        self.resolver: DNSResolver = resolver


class UDPResolverProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol handler for DNS queries."""

    def __init__(self, holder: ResolverHolder) -> None:
        self.holder: ResolverHolder = holder
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        logging.debug("UDP listener started")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        logging.debug(f"Received UDP DNS query from {addr}")
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: Tuple[str, int]) -> None:
        resolver = self.holder.resolver  # always read the latest resolver
        client_ip = addr[0]

        # --- Rate limiting ---
        if resolver.rate_limiter is not None:
            if not await resolver.rate_limiter.is_allowed(client_ip):
                logging.debug("Rate‑limited UDP query from %s", client_ip)
                return

        try:
            qname: Optional[str] = None
            request_msg: Optional[dns.message.Message] = None
            qtype: Optional[int] = None
            try:
                request_msg = dns.message.from_wire(data)
                if request_msg.question:
                    qname = str(request_msg.question[0].name).rstrip('.')
                    qtype = request_msg.question[0].rdtype
            except Exception:
                qname = None

            # Block AAAA queries when IPv6 is disabled
            if resolver.disable_ipv6 and qtype == dns.rdatatype.AAAA:
                resp_wire = resolver.build_block_response(data, action='NXDOMAIN')
                if self.transport:
                    self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked AAAA query for {qname} due to disable_ipv6")
                try:
                    resolver.log_dns_event('Blocked (internal)', qname, f"{addr[0]}:{addr[1]}", 'Disabled IPv6')
                except Exception:
                    pass
                return

            # Blocklist check
            if qname and resolver.is_blocked(qname):
                action = resolver.get_block_action()
                resp_wire = resolver.build_block_response(data, action=action)
                if self.transport:
                    self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked UDP DNS query for {qname} -> action {action}")
                try:
                    resolver.log_dns_event('Blocked (internal)', qname, f"{addr[0]}:{addr[1]}", f"Action={action}")
                except Exception:
                    pass
                return

            # Forward query to upstream
            response = await resolver.forward_dns_query(data)

            # Strip AAAA records when IPv6 disabled
            if resolver.disable_ipv6:
                try:
                    resp_msg = dns.message.from_wire(response)
                    resp_msg.answer = [rr for rr in resp_msg.answer if rr.rdtype != dns.rdatatype.AAAA]
                    resp_msg.additional = [rr for rr in resp_msg.additional if rr.rdtype != dns.rdatatype.AAAA]
                    response = resp_msg.to_wire()
                except Exception:
                    pass

            if self.transport:
                self.transport.sendto(response, addr)
            logging.debug(f"Sent UDP DNS response to {addr}")
            try:
                resolver.log_dns_event('Processed', qname, f"{addr[0]}:{addr[1]}")
            except Exception:
                pass
        except Exception as e:
            logging.error(f"Error handling UDP DNS query from {addr}: {e}")


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       holder: ResolverHolder) -> None:
    """Handle a single TCP DNS query."""
    peer = writer.get_extra_info('peername')
    logging.debug(f"Accepted TCP connection from {peer}")
    resolver = holder.resolver  # always read the latest resolver
    client_ip = peer[0] if peer else "unknown"

    # --- Rate limiting ---
    if resolver.rate_limiter is not None:
        if not await resolver.rate_limiter.is_allowed(client_ip):
            logging.debug("Rate‑limited TCP query from %s", client_ip)
            writer.close()
            return

    try:
        length_bytes = await reader.readexactly(2)
        length = int.from_bytes(length_bytes, 'big')
        data = await reader.readexactly(length)
        qname: Optional[str] = None
        request_msg: Optional[dns.message.Message] = None
        qtype: Optional[int] = None
        try:
            request_msg = dns.message.from_wire(data)
            if request_msg.question:
                qname = str(request_msg.question[0].name).rstrip('.')
                qtype = request_msg.question[0].rdtype
        except Exception:
            qname = None

        # Block AAAA queries when IPv6 is disabled
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

        # Blocklist check
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

        # Forward query
        response = await resolver.forward_dns_query(data)

        # Strip AAAA records when IPv6 disabled
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


async def reload_resolver(holder: ResolverHolder,
                          config: Dict[str, Any],
                          current_resolver: DNSResolver,
                          blocklists: Optional[Dict[str, Any]] = None) -> None:
    """Hot‑reload the resolver's configuration without restarting the server."""
    current_resolver.update_config(
        upstream_dns=config.get("upstream_dns"),
        protocol=config.get("protocol"),
        verbose=config.get("verbose", False),
        disable_ipv6=config.get("disable_ipv6", False),
        udp_timeout=config.get("upstream_udp_timeout"),
        tcp_timeout=config.get("upstream_tcp_timeout"),
        doh_timeout=config.get("upstream_doh_timeout"),
        retries=config.get("upstream_retries"),
        pinned_certs=config.get("dns_pinned_certs"),
        dnssec_enabled=config.get("dnssec_enabled", False),
        trust_anchors=config.get("trust_anchors_file"),
        metrics_enabled=config.get("metrics_enabled", False),
        metrics_port=config.get("metrics_port", 8000),
        rate_limit_rps=config.get("rate_limit_rps"),
        rate_limit_burst=config.get("rate_limit_burst"),
    )

    if blocklists:
        action = blocklists.get('action', 'NXDOMAIN')
        current_resolver.set_block_action(action)
        urls = blocklists.get('urls', []) or []
        local_dir = blocklists.get('local_blocklist_dir', 'blocklists')
        if urls:
            try:
                await fetch_blocklists(urls, destination_dir=local_dir)
                logging.info("Blocklists re‑fetched during config reload")
            except Exception as e:
                logging.warning("Blocklist fetch during reload failed: %s", e)
        try:
            exact_set, suffix_set, hosts_map = current_resolver.load_blocklists_from_dir(local_dir)
            domains = list(exact_set) + ['.' + s for s in suffix_set]
            current_resolver.set_blocklist(domains)
            current_resolver.set_hosts_map(hosts_map)
            logging.info("Blocklists reloaded from %s", local_dir)
        except Exception as e:
            logging.warning("Blocklist reload during config update failed: %s", e)

    logging.info("Configuration reloaded successfully (upstream=%s, protocol=%s)",
                 current_resolver.upstream_dns, current_resolver.protocol)


async def run_server(listen_ip: str, listen_port: int, upstream_dns: str, protocol: str,
                     dns_resolver_server: Optional[str] = None,
                     verbose: bool = False,
                     blocklists: Optional[Dict[str, Any]] = None,
                     disable_ipv6: bool = False,
                     dns_cache_ttl: int = 300,
                     dns_cache_max_size: int = 1024,
                     dns_logging_enabled: bool = False,
                     dns_log_retention_days: int = 7,
                     dns_log_dir: str = '/var/log/phantomd',
                     dns_log_prefix: str = 'dns-log',
                     dns_pinned_certs: Optional[Dict[str, str]] = None,
                     dnssec_enabled: bool = False,
                     trust_anchors_file: Optional[str] = None,
                     metrics_enabled: bool = False,
                     metrics_port: int = 8000,
                     uvloop_enable: bool = False,
                     upstream_retries: int = 2,
                     upstream_initial_backoff: float = 0.1,
                     upstream_udp_timeout: float = 2.0,
                     upstream_tcp_timeout: float = 5.0,
                     upstream_doh_timeout: float = 5.0,
                     rate_limit_rps: float = 0.0,
                     rate_limit_burst: float = 0.0) -> None:
    """Start the DNS server (UDP + TCP) and blocklist background tasks."""
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
        rate_limit_rps=rate_limit_rps,
        rate_limit_burst=rate_limit_burst,
    )

    # Mutable holder for atomic resolver swaps
    holder = ResolverHolder(resolver)
    loop = asyncio.get_running_loop()

    # --- Blocklist loading and scheduling ---
    if blocklists:
        action = blocklists.get('action', 'NXDOMAIN')
        resolver.set_block_action(action)
        urls = blocklists.get('urls', []) or []
        local_dir = blocklists.get('local_blocklist_dir', 'blocklists')

        if urls:
            try:
                await fetch_blocklists(urls, destination_dir=local_dir)
                logging.info("Initial blocklist fetch complete")
            except Exception as e:
                logging.warning("Initial async blocklist fetch failed: %s", e)

        try:
            exact_set, suffix_set, hosts_map = resolver.load_blocklists_from_dir(local_dir)
            domains = list(exact_set) + ['.' + s for s in suffix_set]
            resolver.set_blocklist(domains)
            resolver.set_hosts_map(hosts_map)
        except Exception as e:
            logging.warning("Failed to load blocklists from %s: %s", local_dir, e)

        if blocklists.get('enabled') and urls:
            interval = blocklists.get('interval_seconds', 86400)
            async def periodic_reload() -> None:
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
        lambda: UDPResolverProtocol(holder),
        local_addr=(listen_ip, listen_port)
    )
    logging.info(f"DNS UDP listener running on {listen_ip}:{listen_port}")

    # TCP listener
    server = await asyncio.start_server(
        lambda r, w: _tcp_handler(r, w, holder),
        listen_ip, listen_port
    )
    logging.info(f"DNS TCP listener running on {listen_ip}:{listen_port}")

    # Store references so external code (e.g., main.py) can trigger reloads
    run_server.holder = holder
    run_server.resolver = resolver
    run_server.blocklists = blocklists

    try:
        await server.serve_forever()
    finally:
        udp_transport.close()
        server.close()
        await server.wait_closed()


def run_server_sync(listen_ip: str, listen_port: int, upstream_dns: str, protocol: str,
                    dns_resolver_server: Optional[str] = None,
                    verbose: bool = False,
                    blocklists: Optional[Dict[str, Any]] = None,
                    disable_ipv6: bool = False,
                    **kwargs: Any) -> None:
    """Synchronous wrapper for run_server."""
    asyncio.run(run_server(
        listen_ip, listen_port, upstream_dns, protocol,
        dns_resolver_server=dns_resolver_server,
        verbose=verbose,
        blocklists=blocklists,
        disable_ipv6=disable_ipv6,
        **kwargs
    ))