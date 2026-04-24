# tests/conftest.py
import pytest
import asyncio
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
        lease_db_path=None,   # no disk write
    )
    srv.lease_backend = "none"
    srv._save_leases = lambda: None
    srv._maybe_async_save = lambda: None
    return srv