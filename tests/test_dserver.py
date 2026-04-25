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
from core.resolver import RateLimiter

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_resolver():
    """Return a fully mocked DNSResolver with all relevant methods."""
    resolver = MagicMock()
    resolver.forward_dns_query = AsyncMock(return_value=b'\x00' * 20)
    resolver.is_blocked = MagicMock(return_value=False)
    resolver.get_block_action = MagicMock(return_value='NXDOMAIN')
    resolver.build_block_response = MagicMock(return_value=b'\x01\x02')
    resolver.log_dns_event = MagicMock()
    resolver.disable_ipv6 = False
    # Rate limiter disabled by default
    resolver.rate_limiter = None
    return resolver

@pytest.fixture
def holder(mock_resolver):
    return ResolverHolder(mock_resolver)

# ---------------------------------------------------------------------------
# UDPResolverProtocol._handle  tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_udp_normal_query(holder):
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()

    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('127.0.0.1', 12345)

    await proto._handle(data, addr)

    holder.resolver.forward_dns_query.assert_awaited_once_with(data)
    transport.sendto.assert_called_once()
    assert transport.sendto.call_args[0][0] == b'\x00' * 20

@pytest.mark.asyncio
async def test_udp_blocked_query(holder):
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
    holder.resolver.forward_dns_query.assert_not_awaited()

@pytest.mark.asyncio
async def test_udp_disable_ipv6_aaaa_blocked(holder):
    holder.resolver.disable_ipv6 = True
    data = (
        b'\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x04test\x04case\x03com\x00'
        b'\x00\x1c\x00\x01'
    )
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()
    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('10.0.0.2', 1111)

    await proto._handle(data, addr)

    holder.resolver.forward_dns_query.assert_not_awaited()
    holder.resolver.build_block_response.assert_called_once()
    transport.sendto.assert_called_once()

@pytest.mark.asyncio
async def test_udp_strip_aaaa_when_ipv6_disabled(holder):
    holder.resolver.disable_ipv6 = True
    response_msg = dns.message.make_response(
        dns.message.from_wire(
            b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x04dual\x04host\x03com\x00\x00\xff\x00\x01'
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
    parsed = dns.message.from_wire(sent_data)
    types_in_answer = {rr.rdtype for rr in parsed.answer}
    assert dns.rdatatype.AAAA not in types_in_answer
    assert dns.rdatatype.A in types_in_answer

# --- NEW: UDP rate-limit tests ---

@pytest.mark.asyncio
async def test_udp_rate_limited_drop(holder):
    """When rate limiter denies the client, the query is silently dropped."""
    holder.resolver.rate_limiter = RateLimiter(10.0, 20.0)
    # make is_allowed return False
    holder.resolver.rate_limiter.is_allowed = AsyncMock(return_value=False)

    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()
    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('10.0.0.99', 12345)

    await proto._handle(data, addr)

    # Forward must not be called, and nothing sent
    holder.resolver.forward_dns_query.assert_not_awaited()
    transport.sendto.assert_not_called()

@pytest.mark.asyncio
async def test_udp_rate_limiter_disabled_passes(holder):
    """When rate_limiter is None, queries proceed normally."""
    holder.resolver.rate_limiter = None
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
    transport = MagicMock(spec=asyncio.DatagramTransport)
    transport.sendto = MagicMock()
    proto = UDPResolverProtocol(holder)
    proto.transport = transport
    addr = ('10.0.0.100', 12345)

    await proto._handle(data, addr)

    holder.resolver.forward_dns_query.assert_awaited_once_with(data)
    transport.sendto.assert_called_once()

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
    assert any(b'BLOCKED' in call[0][0] for call in writer.write.call_args_list)
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

    written_data = writer.write.call_args_list[0][0][0]
    resp_wire = written_data[2:]
    parsed = dns.message.from_wire(resp_wire)
    types = {rr.rdtype for rr in parsed.answer}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA not in types

# --- NEW: TCP rate-limit tests ---

@pytest.mark.asyncio
async def test_tcp_rate_limited_drop(holder):
    """TCP query dropped when rate limiter denies the client."""
    holder.resolver.rate_limiter = RateLimiter(10.0, 20.0)
    holder.resolver.rate_limiter.is_allowed = AsyncMock(return_value=False)

    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('10.0.0.200', 44444)
    writer.write = MagicMock()
    writer.close = MagicMock()

    await _tcp_handler(reader, writer, holder)

    # No attempt to read query, no write
    reader.readexactly.assert_not_called()
    writer.write.assert_not_called()
    # Connection should be closed
    writer.close.assert_called_once()

@pytest.mark.asyncio
async def test_tcp_rate_limiter_disabled_passes(holder):
    """When rate_limiter is None, TCP query proceeds normally."""
    holder.resolver.rate_limiter = None
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tcp\x07example\x03com\x00\x00\x01\x00\x01'
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ('10.0.0.201', 55555)
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    reader.readexactly = AsyncMock(side_effect=[len(query).to_bytes(2, 'big'), query])

    await _tcp_handler(reader, writer, holder)

    holder.resolver.forward_dns_query.assert_awaited_once_with(query)
    writer.write.assert_called()