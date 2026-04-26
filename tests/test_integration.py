import pytest
import asyncio
import socket
import struct
import random
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
from tests.conftest import MockUpstream
from dns.name import from_text as name_from_text


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    tid = struct.pack('>H', random.randint(0, 65535))
    flags = b'\x01\x00'
    header = tid + flags + b'\x00\x01\x00\x00\x00\x00\x00\x00'

    qname = b''
    for label in domain.split('.'):
        if label:                  # skip empty labels (trailing dot)
            qname += struct.pack('B', len(label)) + label.encode('ascii')
    qname += b'\x00'

    return header + qname + struct.pack('>HH', qtype, 1)


async def send_dns_query(host: str, port: int, domain: str, qtype: int = 1,
                         timeout: float = 2.0) -> bytes:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    query = build_dns_query(domain, qtype)
    await loop.sock_sendto(sock, query, (host, port))
    try:
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=timeout)
        return data
    except asyncio.TimeoutError:
        return None
    finally:
        sock.close()


async def send_tcp_dns_query(host: str, port: int, domain: str, qtype: int = 1,
                             timeout: float = 2.0) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    try:
        wire = build_dns_query(domain, qtype)
        writer.write(len(wire).to_bytes(2, 'big') + wire)
        await writer.drain()
        length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        length = int.from_bytes(length_bytes, 'big')
        data = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        return data
    except asyncio.TimeoutError:
        return None
    finally:
        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_basic_forwarding_udp(phantomd_server_factory):
    port = await phantomd_server_factory({})
    data = await send_dns_query('127.0.0.1', port, 'example.com')
    assert data is not None
    resp = dns.message.from_wire(data)
    assert len(resp.answer) == 1
    assert str(resp.answer[0][0]) == '1.2.3.4'


@pytest.mark.asyncio
async def test_basic_forwarding_tcp(phantomd_server_factory):
    port = await phantomd_server_factory({})
    data = await send_tcp_dns_query('127.0.0.1', port, 'example.com')
    assert data is not None
    resp = dns.message.from_wire(data)
    assert str(resp.answer[0][0]) == '1.2.3.4'


@pytest.mark.asyncio
async def test_nxdomain(phantomd_server_factory):
    port = await phantomd_server_factory({})
    data = await send_dns_query('127.0.0.1', port, 'nonexistent.example')
    assert data is not None
    resp = dns.message.from_wire(data)
    assert resp.rcode() == dns.rcode.NXDOMAIN


@pytest.mark.asyncio
async def test_caching(phantomd_server_factory):
    port = await phantomd_server_factory({})
    data1 = await send_dns_query('127.0.0.1', port, 'example.com')
    assert data1 is not None
    resp1 = dns.message.from_wire(data1)
    assert str(resp1.answer[0][0]) == '1.2.3.4'

    data2 = await send_dns_query('127.0.0.1', port, 'example.com')
    assert data2 is not None
    resp2 = dns.message.from_wire(data2)
    assert str(resp2.answer[0][0]) == '1.2.3.4'


# ---- corrected: plain domain entry, not hosts entry ----
@pytest.mark.asyncio
async def test_blocklist_nxdomain(phantomd_server_factory, tmp_path):
    block_dir = tmp_path / 'blocklists'
    block_dir.mkdir()
    # A plain domain (no IP) is added to the exact blocklist
    (block_dir / 'block.txt').write_text('blocked.example\n')

    port = await phantomd_server_factory({
        'blocklists': {
            'enabled': True,
            'urls': [],
            'local_blocklist_dir': str(block_dir),
            'action': 'NXDOMAIN',
            'interval_seconds': 86400,
        },
        'upstreams': [{'mu': MockUpstream(answers_by_qname={'blocked.example.': '2.2.2.2'})}]
    })

    data = await send_dns_query('127.0.0.1', port, 'blocked.example')
    assert data is not None
    resp = dns.message.from_wire(data)
    assert resp.rcode() == dns.rcode.NXDOMAIN


# ---- corrected: plain domain entry ----
@pytest.mark.asyncio
async def test_blocklist_zeroip(phantomd_server_factory, tmp_path):
    block_dir = tmp_path / 'blocklists'
    block_dir.mkdir()
    (block_dir / 'block.txt').write_text('blocked.example\n')

    port = await phantomd_server_factory({
        'blocklists': {
            'enabled': True,
            'urls': [],
            'local_blocklist_dir': str(block_dir),
            'action': 'ZEROIP',
            'interval_seconds': 86400,
        },
        'upstreams': [{'mu': MockUpstream(answers_by_qname={'blocked.example.': '2.2.2.2'})}]
    })

    data = await send_dns_query('127.0.0.1', port, 'blocked.example')
    assert data is not None
    resp = dns.message.from_wire(data)
    assert str(resp.answer[0][0]) == '0.0.0.0'


@pytest.mark.asyncio
async def test_hosts_map(phantomd_server_factory, tmp_path):
    hosts_dir = tmp_path / 'hosts'
    hosts_dir.mkdir()
    (hosts_dir / 'hosts.txt').write_text('10.0.0.1 local.test\n')

    port = await phantomd_server_factory({
        'blocklists': {
            'enabled': True,
            'urls': [],
            'local_blocklist_dir': str(hosts_dir),
            'action': 'NXDOMAIN',
            'interval_seconds': 86400,
        },
    })

    # Use TRAILING DOT so the query contains an absolute domain name
    data = await send_dns_query('127.0.0.1', port, 'local.test.')
    assert data is not None
    resp = dns.message.from_wire(data)
    assert str(resp.answer[0][0]) == '10.0.0.1'


@pytest.mark.asyncio
async def test_disable_ipv6_aaaa_blocked(phantomd_server_factory):
    port = await phantomd_server_factory({'disable_ipv6': True})
    data = await send_dns_query('127.0.0.1', port, 'example.com', qtype=28)
    assert data is not None
    resp = dns.message.from_wire(data)
    assert resp.rcode() == dns.rcode.NXDOMAIN


@pytest.mark.asyncio
async def test_rebind_protection_strip(phantomd_server_factory):
    mu = MockUpstream(answers_by_qname={})

    resp_msg = dns.message.make_query('mixed.example.', 'A')
    resp_msg.answer = [dns.rrset.from_text("mixed.example.", 60, 'IN', 'A', "1.2.3.4", "10.0.0.1")]
    resp_wire = resp_msg.to_wire()

    original_handle = mu.handle
    def patched_handle(data, addr):
        query = dns.message.from_wire(data)
        if str(query.question[0].name) == 'mixed.example.':
            mu.transport.sendto(resp_wire, addr)
        else:
            original_handle(data, addr)
    mu.handle = patched_handle

    port = await phantomd_server_factory({
        'upstreams': [{'mu': mu}],
        'rebind_protection_enabled': True,
        'rebind_action': 'strip',
    })

    data = await send_dns_query('127.0.0.1', port, 'mixed.example')
    assert data is not None
    resp = dns.message.from_wire(data)
    ips = [str(rd) for rd in resp.answer[0]]
    assert '1.2.3.4' in ips
    assert '10.0.0.1' not in ips


@pytest.mark.asyncio
async def test_multi_upstream_failover(phantomd_server_factory):
    mu_a = MockUpstream(answers_by_qname={'example.com.': '1.2.3.4'}, failures=2)
    mu_b = MockUpstream(answers_by_qname={'example.com.': '2.2.2.2'})

    port = await phantomd_server_factory({
        'upstreams': [
            {'mu': mu_a, 'protocol': 'udp'},
            {'mu': mu_b, 'protocol': 'udp'},
        ]
    })

    data = await send_dns_query('127.0.0.1', port, 'example.com', timeout=6)
    assert data is not None
    resp = dns.message.from_wire(data)
    assert str(resp.answer[0][0]) == '2.2.2.2'


# ---- robust rate‑limiting test ----
@pytest.mark.asyncio
async def test_rate_limiting(phantomd_server_factory):
    port = await phantomd_server_factory({
        'rate_limit_rps': 100.0,
        'rate_limit_burst': 10,
    })
    # Send 11 rapid queries; first 10 should succeed, 11th timed out (dropped)
    for _ in range(10):
        d = await send_dns_query('127.0.0.1', port, 'example.com', timeout=2)
        assert d is not None

    # 11th should be dropped
    dropped = await send_dns_query('127.0.0.1', port, 'example.com', timeout=0.5)
    assert dropped is None