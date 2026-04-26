import sys
import os


# ------------------------------------------------------------
# 1. Add the project root to sys.path FIRST
# ------------------------------------------------------------
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


import asyncio
import socket
import pytest
import pytest_asyncio
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
from core.resolver import DNSResolver
from core.phantomd_dhcp import DHCPServer


@pytest.fixture
def resolver_no_network():
    """Return a DNSResolver with no real upstream; suitable for cache/parsing tests."""
    return DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="udp",
        dns_resolver_server=None,
        verbose=False,
        disable_ipv6=True,
        cache_ttl=5,
        cache_max_size=10,
    )


@pytest.fixture
def dhcp_server():
    """Create a DHCPServer with a small pool and no persistence for unit tests."""
    srv = DHCPServer(
        subnet="192.168.1.0",
        netmask="255.255.255.0",
        start_ip="192.168.1.100",
        end_ip="192.168.1.200",
        lease_ttl=600,
        server_ip="192.168.1.1",
        lease_db_path=None,
    )
    srv.lease_backend = "none"
    srv._save_leases = lambda: None
    srv._maybe_async_save = lambda: None
    return srv


# ---------------------------------------------------------------------------
# Integration test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def unused_port() -> int:
    """Return a random, available high port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class MockUpstream:
    """A minimal DNS server that responds with canned answers for integration tests."""
    def __init__(self, answers_by_qname=None, failures: int = 0):
        self.answers_by_qname = answers_by_qname or {}
        self.failures = failures
        self.transport = None
        self._queries = 0

    def handle(self, data, addr):
        self._queries += 1
        if self._queries <= self.failures:
            return
        try:
            query = dns.message.from_wire(data)
            if not query.question:
                return
            qname = str(query.question[0].name)
            if qname in self.answers_by_qname:
                ip = self.answers_by_qname[qname]
                if ip is None:
                    resp = dns.message.make_response(query)
                    resp.set_rcode(dns.rcode.SERVFAIL)
                else:
                    resp = dns.message.make_response(query)
                    resp.answer = [dns.rrset.from_text(qname, 60, dns.rdataclass.IN, dns.rdatatype.A, ip)]
            else:
                resp = dns.message.make_response(query)
                resp.set_rcode(dns.rcode.NXDOMAIN)
            self.transport.sendto(resp.to_wire(), addr)
        except Exception:
            pass

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: MockUpstreamProtocol(self),
            local_addr=('127.0.0.1', 0)
        )
        self.transport = transport
        return transport.get_extra_info('socket').getsockname()[1]

    def close(self) -> None:
        if self.transport:
            self.transport.close()


class MockUpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: MockUpstream):
        self.handler = handler

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.handler.handle(data, addr)


async def _wait_for_server(host: str, port: int, timeout: float = 5.0) -> None:
    """Wait until the TCP server is accepting connections."""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.1
            )
            writer.close()
            return
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            if asyncio.get_running_loop().time() > deadline:
                raise Exception("Server did not start within timeout")
            await asyncio.sleep(0.05)


def _probe_server(address: tuple) -> bool:
    """Send a single UDP probe query from a different source IP so that
    it does NOT affect rate‑limiter buckets.  Returns True if any response
    is received."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind to a different IP than the test queries will use
        s.bind(('127.0.0.2', 0))
        s.settimeout(0.5)
        q = dns.message.make_query('probe.invalid', 'A').to_wire()
        s.sendto(q, address)
        data, _ = s.recvfrom(512)
        return data is not None
    except (socket.timeout, OSError):
        return False
    finally:
        s.close()


@pytest_asyncio.fixture
async def phantomd_server_factory():
    """Create a phantomd server with custom configuration.

    Returns a callable ``start(config_overrides) -> port``.
    The callable starts a server, waits until both TCP and UDP are ready,
    and returns the listening port.
    """
    from core.dserver import run_server

    tasks = []
    mock_upstreams = []

    async def _start(overrides: dict) -> int:
        # Merge defaults
        cfg = {
            'listen_ip': '127.0.0.1',
            'listen_port': None,
            'upstream_dns': '127.0.0.1',
            'protocol': 'udp',
            'verbose': False,
            'disable_ipv6': True,
            'blocklists': {'enabled': False},
            'dhcp': {'enabled': False},
            'dns_cache_ttl': 5,
            'dns_cache_max_size': 10,
            'upstreams': [],
            'rate_limit_rps': 0.0,
            'rate_limit_burst': 0.0,
            'optimistic_cache_enabled': False,
            'rebind_protection_enabled': False,
            'rebind_action': 'strip',
            'dns_privilege_drop_user': '',
            'dns_privilege_drop_group': '',
            'dns_chroot_dir': '',
            'pool_max_size': 1,
            'pool_idle_timeout': 60.0,
        }
        cfg.update(overrides)

        if cfg['listen_port'] is None:
            cfg['listen_port'] = _new_port()

        # Build upstream(s)
        upstreams = cfg.get('upstreams', [])
        if not upstreams:
            # Single mock upstream if none given
            mu = MockUpstream(answers_by_qname={'example.com.': '1.2.3.4'})
            upstream_port = await mu.start()
            mock_upstreams.append(mu)
            upstreams = [{
                'address': '127.0.0.1',
                'port': upstream_port,
                'protocol': 'udp',
                'hostname': '127.0.0.1'
            }]
        else:
            for up in upstreams:
                mu = up.pop('mu', None)
                if mu:
                    port = await mu.start()
                    up['port'] = port
                    up['address'] = '127.0.0.1'
                    mock_upstreams.append(mu)

        config = cfg.copy()
        config['upstreams'] = upstreams

        task = asyncio.create_task(run_server(
            listen_ip=config['listen_ip'],
            listen_port=config['listen_port'],
            upstream_dns=config['upstream_dns'],
            protocol=config['protocol'],
            verbose=config['verbose'],
            disable_ipv6=config['disable_ipv6'],
            blocklists=config['blocklists'],
            dns_cache_ttl=config['dns_cache_ttl'],
            dns_cache_max_size=config['dns_cache_max_size'],
            upstreams=config['upstreams'],
            rate_limit_rps=config['rate_limit_rps'],
            rate_limit_burst=config['rate_limit_burst'],
            optimistic_cache_enabled=config['optimistic_cache_enabled'],
            optimistic_stale_max_age=config.get('optimistic_stale_max_age', 86400),
            optimistic_stale_response_ttl=config.get('optimistic_stale_response_ttl', 30),
            dns_rebind_protection=config['rebind_protection_enabled'],
            dns_rebind_action=config['rebind_action'],
            dns_privilege_drop_user=config.get('dns_privilege_drop_user', ''),
            dns_privilege_drop_group=config.get('dns_privilege_drop_group', ''),
            dns_chroot_dir=config.get('dns_chroot_dir', ''),
            pool_max_size=config.get('pool_max_size', 1),
            pool_idle_timeout=config.get('pool_idle_timeout', 60.0),
        ))

        tasks.append(task)
        await _wait_for_server(config['listen_ip'], config['listen_port'])

        # --- Non‑blocking UDP readiness probe (from 127.0.0.2) ---
        loop = asyncio.get_running_loop()
        addr = (config['listen_ip'], config['listen_port'])
        deadline = loop.time() + 5.0
        udp_ready = False
        while loop.time() < deadline:
            ok = await loop.run_in_executor(None, _probe_server, addr)
            if ok:
                udp_ready = True
                break
            await asyncio.sleep(0.2)
        if not udp_ready:
            raise Exception("UDP listener did not respond within timeout")

        # Reset mock upstream counters so the probe does not affect
        # failure‑count tests or rate‑limiting tests.
        for mu in mock_upstreams:
            mu._queries = 0

        return config['listen_port']

    yield _start

    # Cleanup all tasks and mock upstreams
    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    for mu in mock_upstreams:
        mu.close()


def _new_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]