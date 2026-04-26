# tests/test_resolver.py
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
import struct
import time
import socket

from core.resolver import DNSResolver, _HAS_CACHETOOLS, _HAS_AIOQUIC, RateLimiter, ConnectionPool


class TestParsing:
    def test_parse_simple_name(self):
        data = (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x03www\x07example\x03com\x00'
            b'\x00\x01\x00\x01'
        )
        name, offset = DNSResolver._parse_dns_name(data, 12)
        assert name == "www.example.com"
        assert offset == len(data) - 4

    def test_parse_pointer_name(self):
        data = (
            b'\x00' * 12 +
            b'\x07example\x03com\x00' +
            b'\x00\x01\x00\x01' +
            b'\xc0\x0c'
        )
        name, offset = DNSResolver._parse_dns_name(data, 29)
        assert name == "example.com"
        assert offset == 31

    def test_parse_pointer_loop(self):
        data = bytearray(b'\x00' * 20)
        data[12] = 0xC0
        data[13] = 12
        with pytest.raises(ValueError):
            DNSResolver._parse_dns_name(data, 12)

    def test_parse_name_out_of_bounds_label(self):
        data = b'\x00' * 12 + b'\x10abc'
        with pytest.raises(ValueError):
            DNSResolver._parse_dns_name(data, 12)

    def test_parse_name_truncated_pointer(self):
        data = b'\x00' * 12 + b'\xc0'
        with pytest.raises(ValueError):
            DNSResolver._parse_dns_name(data, 12)

    def test_extract_qname(self, resolver_no_network):
        data = b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        data += b'\x03ftp\x07example\x03com\x00\x00\x01\x00\x01'
        qname = resolver_no_network._extract_qname_from_wire(data)
        assert qname == "ftp.example.com"

    def test_extract_qname_short_packet(self, resolver_no_network):
        assert resolver_no_network._extract_qname_from_wire(b'\x00' * 11) is None

    def test_extract_qtype(self, resolver_no_network):
        data = b'\x00' * 12 + b'\x03abc\x00\x00\x1c\x00\x01'
        qtype = resolver_no_network._extract_qtype_from_wire(data)
        assert qtype == 28

    def test_extract_qtype_truncated(self, resolver_no_network):
        data = b'\x00' * 12 + b'\x03abc\x00'
        assert resolver_no_network._extract_qtype_from_wire(data) is None


class TestBlocklistAndHosts:
    def test_exact_block(self, resolver_no_network):
        resolver_no_network.set_blocklist(["evil.com", "bad.org"])
        assert resolver_no_network.is_blocked("evil.com")
        assert resolver_no_network.is_blocked("bad.org")
        assert not resolver_no_network.is_blocked("good.com")

    def test_suffix_block(self, resolver_no_network):
        resolver_no_network.set_blocklist([".tracker.net"])
        assert resolver_no_network.is_blocked("www.tracker.net")
        assert resolver_no_network.is_blocked("tracker.net")
        assert not resolver_no_network.is_blocked("tracker.netx")

    def test_hosts_map(self, resolver_no_network):
        resolver_no_network.set_hosts_map({"local.test": ("192.168.1.1",)})
        assert resolver_no_network.get_host_for("local.test") == ("192.168.1.1",)
        assert resolver_no_network.get_host_for("unknown.test") is None


@pytest.mark.asyncio
class TestCache:
    async def test_async_cache_basic(self, resolver_no_network):
        key = ("test", 1, "udp")
        await resolver_no_network._cache_set(key, "192.168.1.10")
        val = await resolver_no_network._cache_get(key)
        assert val == "192.168.1.10"

    async def test_wire_cache_expiry(self, resolver_no_network):
        key = ("expired.test", 1, "udp")
        await resolver_no_network._wire_cache_set(key, b'\x00' * 20, ttl_seconds=0, query_data=b'\x00')
        val = await resolver_no_network._wire_cache_get_valid(key)
        assert val is None

    async def test_wire_cache_normal(self, resolver_no_network):
        key = ("fresh.test", 1, "udp")
        data = b'\x01\x02'
        await resolver_no_network._wire_cache_set(key, data, ttl_seconds=300, query_data=b'\x00')
        cached = await resolver_no_network._wire_cache_get_valid(key)
        assert cached == data


class TestNXDOMAIN:
    def test_nxdomain_preserves_tid(self, resolver_no_network):
        query = b'\xAA\xBB\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        query += b'\x03bad\x07example\x03com\x00\x00\x01\x00\x01'
        resp = resolver_no_network._make_nxdomain_response(query)
        assert resp[0:2] == b'\xAA\xBB'
        flags = int.from_bytes(resp[2:4], 'big')
        assert (flags & 0x000F) == 3


class TestHostPortSplitting:
    def test_split(self, resolver_no_network):
        assert resolver_no_network._split_hostport("1.2.3.4:853", default_port=53) == ("1.2.3.4", 853)
        assert resolver_no_network._split_hostport("1.2.3.4") == ("1.2.3.4", 53)
        assert resolver_no_network._split_hostport("[::1]:853") == ("::1", 853)
        assert resolver_no_network._split_hostport("[::1]") == ("::1", 53)


class TestLocalAResponse:
    def test_build_local_A(self, resolver_no_network):
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        query += b'\x03www\x07example\x03com\x00\x00\x01\x00\x01'
        resp = resolver_no_network._build_local_A_response(query, "10.0.0.1")
        assert len(resp) > 12
        assert socket.inet_aton("10.0.0.1") in resp

    def test_build_local_A_short_query(self, resolver_no_network):
        resp = resolver_no_network._build_local_A_response(b'\x00' * 10, "1.2.3.4")
        assert resp == b''


# ---------------------------------------------------------------------------
# Mocked forwarding tests (single upstream)
# ---------------------------------------------------------------------------

@pytest.fixture
def resolver_mocked_forward():
    resolver = DNSResolver(
        upstream_dns="1.2.3.4",
        protocol="udp",
        disable_ipv6=True,
        cache_ttl=5,
        cache_max_size=10,
        udp_timeout=1,
        retries=1
    )
    resolver._forward_udp = AsyncMock(return_value=b'\x55\x55')
    resolver._forward_tcp = AsyncMock(return_value=b'\x66\x66')
    resolver._forward_tls = AsyncMock(return_value=b'\x77\x77')
    resolver._forward_https = AsyncMock(return_value=b'\x88\x88')
    if _HAS_AIOQUIC:
        resolver._forward_quic = AsyncMock(return_value=b'\x99\x99')
    return resolver


@pytest.mark.asyncio
async def test_forward_udp_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "udp"
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_udp.assert_awaited_once_with(
        data, {'address': '1.2.3.4', 'protocol': 'udp', 'hostname': '1.2.3.4'}
    )
    assert resp == b'\x55\x55'


@pytest.mark.asyncio
async def test_forward_tcp_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "tcp"
    data = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tcp\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_tcp.assert_awaited_once_with(
        data, {'address': '1.2.3.4', 'protocol': 'tcp', 'hostname': '1.2.3.4'}
    )
    assert resp == b'\x66\x66'


@pytest.mark.asyncio
async def test_forward_tls_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "tls"
    data = b'\xef\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tls\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_tls.assert_awaited_once_with(
        data, {'address': '1.2.3.4', 'protocol': 'tls', 'hostname': '1.2.3.4'}
    )
    assert resp == b'\x77\x77'


@pytest.mark.asyncio
async def test_forward_https_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "https"
    data = b'\xca\xfe\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03doh\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_https.assert_awaited_once_with(
        data, {'address': '1.2.3.4', 'protocol': 'https', 'hostname': '1.2.3.4'}
    )
    assert resp == b'\x88\x88'


@pytest.mark.asyncio
async def test_forward_quic_called(resolver_mocked_forward):
    if not _HAS_AIOQUIC:
        pytest.skip("aioquic not available")
    resolver_mocked_forward.protocol = "quic"
    data = b'\xde\xad\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03quic\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_quic.assert_awaited_once_with(
        data, {'address': '1.2.3.4', 'protocol': 'quic', 'hostname': '1.2.3.4'}
    )
    assert resp == b'\x99\x99'


@pytest.mark.asyncio
async def test_retries_on_failure(resolver_mocked_forward):
    resolver_mocked_forward._forward_udp.side_effect = [
        asyncio.TimeoutError(),
        b'\xaa\xaa'
    ]
    resolver_mocked_forward.retries = 2
    data = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03ret\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    assert resp == b'\xaa\xaa'
    assert resolver_mocked_forward._forward_udp.call_count == 2


@pytest.mark.asyncio
async def test_all_retries_fail(resolver_mocked_forward):
    resolver_mocked_forward._forward_udp.side_effect = asyncio.TimeoutError()
    resolver_mocked_forward.retries = 2
    data = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03fail\x00\x00\x01\x00\x01'
    with pytest.raises(asyncio.TimeoutError):
        await resolver_mocked_forward.forward_dns_query(data)
    assert resolver_mocked_forward._forward_udp.call_count == 2


@pytest.mark.asyncio
async def test_blocked_query_not_forwarded(resolver_mocked_forward):
    resolver_mocked_forward.set_blocklist(["blocked.com"])
    data = (
        b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x07blocked\x03com\x00'
        b'\x00\x01\x00\x01'
    )
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_udp.assert_not_called()
    assert resp != b'\x55\x55'
    assert len(resp) > 0


@pytest.mark.asyncio
async def test_hosts_map_avoids_forwarding(resolver_mocked_forward):
    resolver_mocked_forward.set_hosts_map({"custom.local": ("10.10.10.10",)})
    data = (
        b'\x01\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x06custom\x05local\x00'
        b'\x00\x01\x00\x01'
    )
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_udp.assert_not_called()
    assert b'\x0a\x0a\x0a\x0a' in resp


@pytest.mark.asyncio
async def test_wire_cache_prevents_forwarding(resolver_mocked_forward):
    data = b'\x55\x66\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03cached\x00\x00\x01\x00\x01'
    cached_response = b'\xcc\xcc'
    resolver_mocked_forward._wire_cache_get_valid = AsyncMock(return_value=cached_response)
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_udp.assert_not_called()
    assert resp == cached_response


# ---------------------------------------------------------------------------
# Multi-upstream failover tests
# ---------------------------------------------------------------------------

@pytest.fixture
def resolver_multi_upstream():
    resolver = DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="udp",
        disable_ipv6=True,
        cache_ttl=300,
        cache_max_size=10,
        upstreams=[
            {'address': '10.0.0.1', 'protocol': 'udp', 'port': 53, 'hostname': 'ns1.example.com'},
            {'address': '10.0.0.2', 'protocol': 'tls', 'port': 853, 'hostname': 'ns2.example.com'},
            {'address': '10.0.0.3', 'protocol': 'https', 'port': 443, 'hostname': 'ns3.example.com'},
        ],
    )
    resolver._try_upstream = AsyncMock()
    return resolver


@pytest.mark.asyncio
async def test_multi_upstream_first_succeeds(resolver_multi_upstream):
    resolver_multi_upstream._try_upstream.return_value = b'\x01\x02'
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x00\x00\x01\x00\x01'
    resp = await resolver_multi_upstream.forward_dns_query(data)
    assert resp == b'\x01\x02'
    assert resolver_multi_upstream._try_upstream.call_count == 1
    called_upstream = resolver_multi_upstream._try_upstream.call_args[0][0]
    assert called_upstream['address'] == '10.0.0.1'


@pytest.mark.asyncio
async def test_multi_upstream_second_succeeds(resolver_multi_upstream):
    resolver_multi_upstream._try_upstream.side_effect = [
        Exception("first failure"),
        b'\x02\x03'
    ]
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03def\x00\x00\x01\x00\x01'
    resp = await resolver_multi_upstream.forward_dns_query(data)
    assert resp == b'\x02\x03'
    assert resolver_multi_upstream._try_upstream.call_count == 2
    calls = resolver_multi_upstream._try_upstream.call_args_list
    assert calls[0][0][0]['address'] == '10.0.0.1'
    assert calls[1][0][0]['address'] == '10.0.0.2'


@pytest.mark.asyncio
async def test_multi_upstream_all_fail(resolver_multi_upstream):
    resolver_multi_upstream._try_upstream.side_effect = [
        Exception("fail1"),
        Exception("fail2"),
        Exception("fail3"),
    ]
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03xyz\x00\x00\x01\x00\x01'
    with pytest.raises(Exception) as exc_info:
        await resolver_multi_upstream.forward_dns_query(data)
    assert "fail3" in str(exc_info.value)
    assert resolver_multi_upstream._try_upstream.call_count == 3


@pytest.mark.asyncio
async def test_multi_upstream_cache_hit_skips_all(resolver_multi_upstream):
    key = ("abc.def", 1, resolver_multi_upstream.protocol)
    await resolver_multi_upstream._wire_cache_set(key, b'\xcc\xcc', ttl_seconds=60, query_data=b'\x00')
    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x03def\x00\x00\x01\x00\x01'
    resp = await resolver_multi_upstream.forward_dns_query(data)
    assert resp == b'\xcc\xcc'
    resolver_multi_upstream._try_upstream.assert_not_called()


# ---------------------------------------------------------------------------
# RateLimiter unit tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allow_within_burst(self):
        limiter = RateLimiter(10.0, 5.0)
        for _ in range(5):
            assert await limiter.is_allowed("client1")

    @pytest.mark.asyncio
    async def test_deny_after_burst(self):
        limiter = RateLimiter(10.0, 3.0)
        for _ in range(3):
            assert await limiter.is_allowed("client1")
        assert not await limiter.is_allowed("client1")

    @pytest.mark.asyncio
    async def test_tokens_regenerate_over_time(self):
        limiter = RateLimiter(100.0, 3.0)
        key = "client2"
        for _ in range(3):
            assert await limiter.is_allowed(key)
        assert not await limiter.is_allowed(key)
        await asyncio.sleep(0.05)
        assert await limiter.is_allowed(key)

    @pytest.mark.asyncio
    async def test_different_keys_independent(self):
        limiter = RateLimiter(10.0, 1.0)
        assert await limiter.is_allowed("clientA")
        assert not await limiter.is_allowed("clientA")
        assert await limiter.is_allowed("clientB")

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        limiter = RateLimiter(1000.0, 100.0)
        key = "client3"
        async def consume():
            return await limiter.is_allowed(key)
        tasks = [consume() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        assert all(results)


# ---------------------------------------------------------------------------
# Rate limiter config hot-reload test
# ---------------------------------------------------------------------------

class TestRateLimitConfig:
    def test_update_config_disables_limiter(self, resolver_no_network):
        resolver_no_network.rate_limiter = RateLimiter(10.0, 20.0)
        resolver_no_network.rate_limit_rps = 10.0
        resolver_no_network.rate_limit_burst = 20.0
        resolver_no_network.update_config(rate_limit_rps=0.0, rate_limit_burst=0.0)
        assert resolver_no_network.rate_limiter is None
        assert resolver_no_network.rate_limit_rps == 0.0
        assert resolver_no_network.rate_limit_burst == 0.0

    def test_update_config_enables_limiter(self, resolver_no_network):
        resolver_no_network.rate_limiter = None
        resolver_no_network.update_config(rate_limit_rps=50.0, rate_limit_burst=100.0)
        assert resolver_no_network.rate_limiter is not None
        assert resolver_no_network.rate_limiter.rate == 50.0
        assert resolver_no_network.rate_limiter.burst == 100.0

    def test_update_config_updates_existing_limiter(self, resolver_no_network):
        limiter = RateLimiter(10.0, 20.0)
        resolver_no_network.rate_limiter = limiter
        resolver_no_network.update_config(rate_limit_rps=30.0, rate_limit_burst=40.0)
        assert resolver_no_network.rate_limiter is limiter
        assert limiter.rate == 30.0
        assert limiter.burst == 40.0


# ===========================================================================
# DNS rebinding protection tests (existing)
# ===========================================================================

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset


class TestIsPrivateIP:
    """Unit tests for the static helper _is_private_ip."""

    def test_public_ipv4(self):
        assert not DNSResolver._is_private_ip("1.1.1.1")
        assert not DNSResolver._is_private_ip("8.8.8.8")

    def test_private_ipv4(self):
        assert DNSResolver._is_private_ip("192.168.1.1")
        assert DNSResolver._is_private_ip("10.0.0.1")
        assert DNSResolver._is_private_ip("172.16.0.1")

    def test_loopback_ipv4(self):
        assert DNSResolver._is_private_ip("127.0.0.1")

    def test_link_local_ipv4(self):
        assert DNSResolver._is_private_ip("169.254.1.1")

    def test_multicast_ipv4(self):
        assert DNSResolver._is_private_ip("224.0.0.1")

    def test_public_ipv6(self):
        assert not DNSResolver._is_private_ip("2001:4860:4860::8888")

    def test_loopback_ipv6(self):
        assert DNSResolver._is_private_ip("::1")

    def test_link_local_ipv6(self):
        assert DNSResolver._is_private_ip("fe80::1")

    def test_invalid_ip(self):
        assert not DNSResolver._is_private_ip("not an ip")


@pytest.fixture
def resolver_rebind_strip():
    resolver = DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="udp",
        disable_ipv6=True,
        rebind_protection_enabled=True,
        rebind_action="strip",
    )
    resolver._try_upstream = AsyncMock(return_value=b'\x00'*100)
    return resolver


@pytest.fixture
def resolver_rebind_block():
    resolver = DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="udp",
        disable_ipv6=True,
        rebind_protection_enabled=True,
        rebind_action="block",
    )
    resolver._try_upstream = AsyncMock(return_value=b'\x00'*100)
    return resolver


class TestApplyRebindProtection:
    def test_strip_private_ipv4(self, resolver_rebind_strip):
        msg = dns.message.Message()
        msg.answer = [
            dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "1.1.1.1", "192.168.1.1"),
        ]
        wire = msg.to_wire()
        result = resolver_rebind_strip._apply_rebind_protection(wire)
        parsed = dns.message.from_wire(result)
        ips = [rd.to_text() for rrset in parsed.answer for rd in rrset]
        assert "1.1.1.1" in ips
        assert "192.168.1.1" not in ips

    def test_strip_all_private_leaves_rrset_empty(self, resolver_rebind_strip):
        msg = dns.message.Message()
        msg.answer = [
            dns.rrset.from_text("internal.example.", 60, dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1", "192.168.1.1"),
        ]
        wire = msg.to_wire()
        result = resolver_rebind_strip._apply_rebind_protection(wire)
        parsed = dns.message.from_wire(result)
        assert len(parsed.answer) == 0

    def test_block_all_private_returns_nxdomain(self, resolver_rebind_block):
        msg = dns.message.Message()
        msg.answer = [
            dns.rrset.from_text("internal.example.", 60, dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1"),
        ]
        wire = msg.to_wire()
        result = resolver_rebind_block._apply_rebind_protection(wire)
        parsed = dns.message.Message()
        parsed.flags = struct.unpack("!H", result[2:4])[0]
        assert (parsed.flags & 0x000F) == 3  # NXDOMAIN

    def test_block_public_ips_preserved(self, resolver_rebind_block):
        msg = dns.message.Message()
        msg.answer = [
            dns.rrset.from_text("safe.example.", 60, dns.rdataclass.IN, dns.rdatatype.A, "1.1.1.1", "8.8.8.8"),
        ]
        wire = msg.to_wire()
        result = resolver_rebind_block._apply_rebind_protection(wire)
        parsed = dns.message.from_wire(result)
        ips = [rd.to_text() for rrset in parsed.answer for rd in rrset]
        assert "1.1.1.1" in ips
        assert "8.8.8.8" in ips

    def test_disabled_does_nothing(self):
        resolver = DNSResolver(
            upstream_dns="1.1.1.1",
            protocol="udp",
            disable_ipv6=True,
            rebind_protection_enabled=False,
        )
        msg = dns.message.Message()
        msg.answer = [
            dns.rrset.from_text("mixed.example.", 60, dns.rdataclass.IN, dns.rdatatype.A, "1.1.1.1", "10.0.0.1"),
        ]
        wire = msg.to_wire()
        result = resolver._apply_rebind_protection(wire)
        parsed = dns.message.from_wire(result)
        ips = [rd.to_text() for rrset in parsed.answer for rd in rrset]
        assert "1.1.1.1" in ips
        assert "10.0.0.1" in ips

    def test_mixed_aaaa_and_a(self, resolver_rebind_strip):
        msg = dns.message.Message()
        msg.answer = [
            dns.rrset.from_text("dual.example.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:4860:4860::8888"),
            dns.rrset.from_text("dual.example.", 60, dns.rdataclass.IN, dns.rdatatype.A, "1.1.1.1"),
            dns.rrset.from_text("dual.example.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1"),
        ]
        wire = msg.to_wire()
        result = resolver_rebind_strip._apply_rebind_protection(wire)
        parsed = dns.message.from_wire(result)
        aaaa_ips = [rd.to_text() for rrset in parsed.answer if rrset.rdtype == dns.rdatatype.AAAA for rd in rrset]
        a_ips = [rd.to_text() for rrset in parsed.answer if rrset.rdtype == dns.rdatatype.A for rd in rrset]
        assert "2001:4860:4860::8888" in aaaa_ips
        assert "1.1.1.1" in a_ips
        assert "::1" not in aaaa_ips


@pytest.mark.asyncio
async def test_forward_query_applies_rebind(resolver_rebind_strip):
    msg = dns.message.make_response(
        dns.message.from_wire(
            b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x04test\x04case\x03com\x00'
            b'\x00\x01\x00\x01'
        )
    )
    msg.answer = [
        dns.rrset.from_text("test.case.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "1.1.1.1", "192.168.1.1"),
    ]
    upstream_wire = msg.to_wire()
    resolver_rebind_strip._try_upstream.return_value = upstream_wire

    data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x04case\x03com\x00\x00\x01\x00\x01'
    resp = await resolver_rebind_strip.forward_dns_query(data)
    parsed = dns.message.from_wire(resp)
    ips = [rd.to_text() for rrset in parsed.answer for rd in rrset]
    assert "1.1.1.1" in ips
    assert "192.168.1.1" not in ips


# ===========================================================================
# Connection pool tests
# ===========================================================================

@pytest.mark.asyncio
class TestConnectionPool:
    async def test_get_empty(self):
        pool = ConnectionPool(max_size=2)
        assert await pool.get(("host", 53)) is None

    async def test_put_and_get(self):
        pool = ConnectionPool(max_size=2)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.is_closing.return_value = False
        await pool.put(("host", 53), reader, writer)
        result = await pool.get(("host", 53))
        assert result == (reader, writer)

    async def test_closed_connection_not_returned(self):
        pool = ConnectionPool(max_size=2)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.is_closing.return_value = True
        await pool.put(("host", 53), reader, writer)
        assert await pool.get(("host", 53)) is None

    async def test_max_size_exceeded_closes_extra(self):
        pool = ConnectionPool(max_size=2)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer1 = MagicMock(spec=asyncio.StreamWriter)
        writer1.is_closing.return_value = False
        writer2 = MagicMock(spec=asyncio.StreamWriter)
        writer2.is_closing.return_value = False
        writer3 = MagicMock(spec=asyncio.StreamWriter)
        writer3.is_closing.return_value = False
        await pool.put(("host", 53), reader, writer1)
        await pool.put(("host", 53), reader, writer2)
        await pool.put(("host", 53), reader, writer3)
        # pool should have size 2; writer3 should have been closed
        writer3.close.assert_called_once()
        # pool is LIFO — last inserted is returned first
        assert await pool.get(("host", 53)) == (reader, writer2)
        assert await pool.get(("host", 53)) == (reader, writer1)
        assert await pool.get(("host", 53)) is None

    async def test_different_keys(self):
        pool = ConnectionPool(max_size=2)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer_a = MagicMock(spec=asyncio.StreamWriter)
        writer_a.is_closing.return_value = False
        writer_b = MagicMock(spec=asyncio.StreamWriter)
        writer_b.is_closing.return_value = False
        await pool.put(("host_a", 53), reader, writer_a)
        await pool.put(("host_b", 853, "tls.example"), reader, writer_b)
        assert await pool.get(("host_a", 53)) == (reader, writer_a)
        assert await pool.get(("host_b", 853, "tls.example")) == (reader, writer_b)
        assert await pool.get(("host_a", 53)) is None


# ---------------------------------------------------------------------------
# Resolver pooling integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolver_tcp_pooling():
    resolver = DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="tcp",
        disable_ipv6=True,
        pool_max_size=2,
    )
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False
    # side_effect must provide 4 values: length + response × 2 queries
    reader.readexactly = AsyncMock(side_effect=[
        b'\x00\x04',           # 1st query: length prefix
        b'\xAA\xBB\xCC\xDD',   # 1st query: response
        b'\x00\x04',           # 2nd query: length prefix
        b'\x11\x22\x33\x44',   # 2nd query: response
    ])
    resolver._resolve_upstream_ip = AsyncMock(return_value="1.1.1.1")
    with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_open:
        mock_open.return_value = (reader, writer)
        data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x00\x00\x01\x00\x01'
        # first call should open a connection
        resp1 = await resolver._forward_tcp(data, {'address': '1.1.1.1', 'protocol': 'tcp', 'port': 53})
        assert resp1 == b'\xAA\xBB\xCC\xDD'
        mock_open.assert_called_once_with("1.1.1.1", 53)
        writer.drain.assert_called()
        # second call should reuse the same connection (no new open)
        mock_open.reset_mock()
        resp2 = await resolver._forward_tcp(data, {'address': '1.1.1.1', 'protocol': 'tcp', 'port': 53})
        assert resp2 == b'\x11\x22\x33\x44'
        mock_open.assert_not_called()

@pytest.mark.asyncio
async def test_resolver_tcp_pooling_on_error_closes():
    resolver = DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="tcp",
        disable_ipv6=True,
        pool_max_size=2,
    )
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False
    # first call fails
    reader.readexactly = AsyncMock(side_effect=OSError("connection broken"))
    resolver._resolve_upstream_ip = AsyncMock(return_value="1.1.1.1")
    with patch('asyncio.open_connection', new_callable=AsyncMock) as mock_open:
        mock_open.return_value = (reader, writer)
        data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x00\x00\x01\x00\x01'
        with pytest.raises(OSError):
            await resolver._forward_tcp(data, {'address': '1.1.1.1', 'protocol': 'tcp', 'port': 53})
        # the connection should be closed and NOT returned to pool
        writer.close.assert_called()
        # subsequent call should open a new connection
        mock_open.reset_mock()
        reader2 = MagicMock(spec=asyncio.StreamReader)
        writer2 = MagicMock(spec=asyncio.StreamWriter)
        writer2.is_closing.return_value = False
        reader2.readexactly = AsyncMock(side_effect=[b'\x00\x04', b'\x55\x55\x55\x55'])
        mock_open.return_value = (reader2, writer2)
        resp = await resolver._forward_tcp(data, {'address': '1.1.1.1', 'protocol': 'tcp', 'port': 53})
        assert resp == b'\x55\x55\x55\x55'
        mock_open.assert_called_once_with("1.1.1.1", 53)  # new connection