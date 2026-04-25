# tests/test_dserver.py
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

import dns.message
import dns.rdatatype

from core.dserver import (
    ResolverHolder,
    UDPResolverProtocol,
    _tcp_handler,
    reload_resolver,
    run_server,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_resolver():
    """Return a fully mocked DNSResolver with all relevant methods."""
    resolver = MagicMock()
    # Async methods need to return coroutines
    resolver.forward_dns_query = AsyncMock(return_value=b'\x00' * 20)  # dummy response
    resolver.is_blocked = MagicMock(return_value=False)
    resolver.get_block_action = MagicMock(return_value='NXDOMAIN')
    resolver.build_block_response = MagicMock(return_value=b'\x01\x02')
    resolver.log_dns_event = MagicMock()
    resolver.disable_ipv6 = False
    return resolver

@pytest.fixture
def holder(mock_resolver):
    return ResolverHolder(mock_resolver)

# ---------------------------------------------------------------------------
# UDPResolverProtocol._handle  tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_udp_normal_query(holder):
    """A normal query is forwarded and the response sent back."""
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()

    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('127.0.0.1', 12345)

    await proto._handle(data, addr)

    holder.resolver.forward_dns_query.assert_awaited_once_with(data)
    transport.sendto.assert_called_once()
    # The first argument to sendto should be the dummy response
    assert transport.sendto.call_args[0][0] == b'\x00' * 20
    # Should not have blocked
    holder.resolver.is_blocked.assert_not_called()  # is_blocked called after qname extraction

@pytest.mark.asyncio
async def test_udp_blocked_query(holder):
    """Blocked queries are intercepted and a block response sent."""
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03bad\x07example\x03com\x00\x00\x01\x00\x01'
    holder.resolver.is_blocked.return_value = True
    holder.resolver.build_block_response.return_value = b'\xFF' * 5

    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()
    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('10.0.0.1', 54321)

    await proto._handle(data, addr)

    holder.resolver.build_block_response.assert_called_once_with(data, action='NXDOMAIN')
    transport.sendto.assert_called_once_with(b'\xFF' * 5, addr)
    # forward_dns_query must not be called
    holder.resolver.forward_dns_query.assert_not_awaited()

@pytest.mark.asyncio
async def test_udp_disable_ipv6_aaaa_blocked(holder):
    """AAAA query with disable_ipv6=True returns NXDOMAIN and does not forward."""
    holder.resolver.disable_ipv6 = True
    # Build a minimal AAAA query
    data = (
        b'\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x04test\x04case\x03com\x00'
        b'\x00\x1c\x00\x01'  # type AAAA
    )
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()
    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('10.0.0.2', 1111)

    await proto._handle(data, addr)

    # must block without forwarding
    holder.resolver.forward_dns_query.assert_not_awaited()
    # should call build_block_response with action='NXDOMAIN'
    holder.resolver.build_block_response.assert_called_once()
    transport.sendto.assert_called_once()

@pytest.mark.asyncio
async def test_udp_strip_aaaa_when_ipv6_disabled(holder):
    """If disable_ipv6=True, AAAA records are stripped from upstream responses."""
    holder.resolver.disable_ipv6 = True
    # Build a response that contains both A and AAAA
    response_msg = dns.message.make_response(
        dns.message.from_wire(
            b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x04dual\x04host\x03com\x00\x00\xff\x00\x01'  # ANY or catch-all
        )
    )
    response_msg.answer = [
        dns.rrset.from_text('dual.host.com.', 60, dns.rdataclass.IN, dns.rdatatype.A, '1.1.1.1'),
        dns.rrset.from_text('dual.host.com.', 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '::1'),
    ]
    wire = response_msg.to_wire()
    holder.resolver.forward_dns_query.return_value = wire

    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04dual\x04host\x03com\x00\x00\xff\x00\x01'
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()
    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('192.168.1.1', 9999)

    await proto._handle(data, addr)

    sent_data = transport.sendto.call_args[0][0]
    # Parse the sent response
    parsed = dns.message.from_wire(sent_data)
    types_in_answer = {rr.rdtype for rr in parsed.answer}
    # AAAA should have been removed
    assert dns.rdatatype.AAAA not in types_in_answer
    # A must still be present
    assert dns.rdatatype.A in types_in_answer

# ---------------------------------------------------------------------------
# _tcp_handler tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tcp_normal_query(holder):
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('127.0.0.1', 54321)
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api\x07example\x03com\x00\x00\x01\x00\x01'
    reader.readexactly = AsyncMock(side_effect=[len(query).to_bytes(2, 'big'), query])

    await _tcp_handler(reader, writer, holder)

    holder.resolver.forward_dns_query.assert_awaited_once_with(query)
    writer.write.assert_called()
    writer.wait_closed.assert_awaited()

@pytest.mark.asyncio
async def test_tcp_blocked_query(holder):
    holder.resolver.is_blocked.return_value = True
    holder.resolver.build_block_response.return_value = b'BLOCKED'

    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('10.0.0.5', 33333)
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    query = b'\x99\x99\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04evil\x03com\x00\x00\x01\x00\x01'
    reader.readexactly = AsyncMock(side_effect=[len(query).to_bytes(2, 'big'), query])

    await _tcp_handler(reader, writer, holder)

    holder.resolver.build_block_response.assert_called_once_with(query, action='NXDOMAIN')
    # The written data should be length‑prefixed 'BLOCKED'
    calls = writer.write.call_args_list
    assert any(b'BLOCKED' in call[0][0] for call in calls)
    holder.resolver.forward_dns_query.assert_not_awaited()

@pytest.mark.asyncio
async def test_tcp_disable_ipv6_aaaa_blocked(holder):
    holder.resolver.disable_ipv6 = True

    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('10.0.0.6', 44444)
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    query = (
        b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x04ipv6\x04only\x03tld\x00'
        b'\x00\x1c\x00\x01'
    )
    reader.readexactly = AsyncMock(side_effect=[len(query).to_bytes(2, 'big'), query])

    await _tcp_handler(reader, writer, holder)

    holder.resolver.forward_dns_query.assert_not_awaited()
    holder.resolver.build_block_response.assert_called_once()
    writer.write.assert_called()

@pytest.mark.asyncio
async def test_tcp_strip_aaaa_when_ipv6_disabled(holder):
    holder.resolver.disable_ipv6 = True
    response_msg = dns.message.make_response(
        dns.message.from_wire(
            b'\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x04dual\x04host\x03com\x00\x00\xff\x00\x01'
        )
    )
    response_msg.answer = [
        dns.rrset.from_text('dual.host.com.', 60, dns.rdataclass.IN, dns.rdatatype.A, '2.2.2.2'),
        dns.rrset.from_text('dual.host.com.', 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '::2'),
    ]
    wire = response_msg.to_wire()
    holder.resolver.forward_dns_query.return_value = wire

    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('172.16.0.1', 55555)
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    query = b'\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04dual\x04host\x03com\x00\x00\xff\x00\x01'
    reader.readexactly = AsyncMock(side_effect=[len(query).to_bytes(2, 'big'), query])

    await _tcp_handler(reader, writer, holder)

    # Extract the written response
    written_data = writer.write.call_args_list[0][0][0]  # first write call, first arg
    # Skip the 2‑byte length prefix
    resp_wire = written_data[2:]
    parsed = dns.message.from_wire(resp_wire)
    types = {rr.rdtype for rr in parsed.answer}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA not in types