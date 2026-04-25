# tests/test_resolver.py
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
import struct
import time
import socket

from core.resolver import DNSResolver, _HAS_CACHETOOLS, _HAS_AIOQUIC, RateLimiter


class TestParsing:
    def test_parse_simple_name(self):
        data = (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # header
            b'\x03www\x07example\x03com\x00'                      # question
            b'\x00\x01\x00\x01'                                    # qtype + qclass
        )
        name, offset = DNSResolver._parse_dns_name(data, 12)
        assert name == "www.example.com"
        assert offset == len(data) - 4

    def test_parse_pointer_name(self):
        data = (
            b'\x00' * 12 +
            b'\x07example\x03com\x00' +
            b'\x00\x01\x00\x01' +
            b'\xc0\x0c'   # pointer to offset 12 (0x0c)
        )
        # The pointer is at offset 29 (12+13+4). Parsing from there should yield "example.com"
        name, offset = DNSResolver._parse_dns_name(data, 29)
        assert name == "example.com"
        assert offset == 31   # 29 + 2 bytes for pointer

    def test_parse_pointer_loop(self):
        data = bytearray(b'\x00' * 20)
        data[12] = 0xC0
        data[13] = 12  # points to itself
        with pytest.raises(ValueError):
            DNSResolver._parse_dns_name(data, 12)

    def test_parse_name_out_of_bounds_label(self):
        data = b'\x00' * 12 + b'\x10abc'  # label length 16 but only 3 bytes follow
        with pytest.raises(ValueError):
            DNSResolver._parse_dns_name(data, 12)

    def test_parse_name_truncated_pointer(self):
        data = b'\x00' * 12 + b'\xc0'  # only one byte of pointer
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
        data = b'\x00' * 12 + b'\x03abc\x00'  # missing qtype/class
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
        await resolver_no_network._wire_cache_set(key, b'\x00' * 20, ttl_seconds=0)
        val = await resolver_no_network._wire_cache_get_valid(key)
        assert val is None

    async def test_wire_cache_normal(self, resolver_no_network):
        key = ("fresh.test", 1, "udp")
        data = b'\x01\x02'
        await resolver_no_network._wire_cache_set(key, data, ttl_seconds=300)
        cached = await resolver_no_network._wire_cache_get_valid(key)
        assert cached == data


class TestNXDOMAIN:
    def test_nxdomain_preserves_tid(self, resolver_no_network):
        query = b'\xAA\xBB\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        query += b'\x03bad\x07example\x03com\x00\x00\x01\x00\x01'
        resp = resolver_no_network._make_nxdomain_response(query)
        assert resp[0:2] == b'\xAA\xBB'
        flags = int.from_bytes(resp[2:4], 'big')
        assert (flags & 0x000F) == 3  # NXDOMAIN rcode


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
        # Basic checks: header, question, answer
        assert len(resp) > 12
        # Check that IP appears in response
        assert socket.inet_aton("10.0.0.1") in resp

    def test_build_local_A_short_query(self, resolver_no_network):
        # Should return empty bytes for too-short data
        resp = resolver_no_network._build_local_A_response(b'\x00' * 10, "1.2.3.4")
        assert resp == b''


# ---------------------------------------------------------------------------
# NEW: Mocked forwarding tests
# ---------------------------------------------------------------------------

@pytest.fixture
def resolver_mocked_forward():
    """Resolver with mocked network forwarding functions."""
    resolver = DNSResolver(
        upstream_dns="1.2.3.4",
        protocol="udp",
        disable_ipv6=True,
        cache_ttl=5,
        cache_max_size=10,
        udp_timeout=1,
        retries=1
    )
    # Mock all forwarding methods to return canned responses
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
    # Should call _forward_udp and return its response
    resolver_mocked_forward._forward_udp.assert_awaited_once_with(data)
    assert resp == b'\x55\x55'


@pytest.mark.asyncio
async def test_forward_tcp_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "tcp"
    data = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tcp\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_tcp.assert_awaited_once_with(data)
    assert resp == b'\x66\x66'


@pytest.mark.asyncio
async def test_forward_tls_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "tls"
    data = b'\xef\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tls\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_tls.assert_awaited_once_with(data)
    assert resp == b'\x77\x77'


@pytest.mark.asyncio
async def test_forward_https_called(resolver_mocked_forward):
    resolver_mocked_forward.protocol = "https"
    data = b'\xca\xfe\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03doh\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_https.assert_awaited_once_with(data)
    assert resp == b'\x88\x88'


@pytest.mark.asyncio
async def test_forward_quic_called(resolver_mocked_forward):
    if not _HAS_AIOQUIC:
        pytest.skip("aioquic not available")
    resolver_mocked_forward.protocol = "quic"
    data = b'\xde\xad\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03quic\x00\x00\x01\x00\x01'
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_quic.assert_awaited_once_with(data)
    assert resp == b'\x99\x99'


@pytest.mark.asyncio
async def test_retries_on_failure(resolver_mocked_forward):
    """Ensure retries happen when forwarding fails."""
    resolver_mocked_forward._forward_udp.side_effect = [
        asyncio.TimeoutError(),
        b'\xaa\xaa'  # second attempt succeeds
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
    # Must not have called any forward method
    resolver_mocked_forward._forward_udp.assert_not_called()
    # Response should be a block response, not our mock values
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
    # Should not have called any upstream forwarding
    resolver_mocked_forward._forward_udp.assert_not_called()
    # Response should contain the IP from hosts_map
    assert b'\x0a\x0a\x0a\x0a' in resp  # 10.10.10.10 in hex


@pytest.mark.asyncio
async def test_wire_cache_prevents_forwarding(resolver_mocked_forward):
    data = b'\x55\x66\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03cached\x00\x00\x01\x00\x01'
    cached_response = b'\xcc\xcc'
    resolver_mocked_forward._wire_cache_get_valid = AsyncMock(return_value=cached_response)
    resp = await resolver_mocked_forward.forward_dns_query(data)
    resolver_mocked_forward._forward_udp.assert_not_called()
    assert resp == cached_response
    
# ---------------------------------------------------------------------------
# NEW: RateLimiter unit tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allow_within_burst(self):
        limiter = RateLimiter(10.0, 5.0)
        # first burst of 5 should all pass
        for _ in range(5):
            assert await limiter.is_allowed("client1")

    @pytest.mark.asyncio
    async def test_deny_after_burst(self):
        limiter = RateLimiter(10.0, 3.0)
        for _ in range(3):
            assert await limiter.is_allowed("client1")
        # 4th should fail
        assert not await limiter.is_allowed("client1")

    @pytest.mark.asyncio
    async def test_tokens_regenerate_over_time(self):
        limiter = RateLimiter(100.0, 3.0)  # high rate to refill quickly
        key = "client2"
        for _ in range(3):
            assert await limiter.is_allowed(key)
        assert not await limiter.is_allowed(key)
        # wait a bit for tokens to regenerate (rate=100, so 0.05s gives ~5 tokens)
        await asyncio.sleep(0.05)
        assert await limiter.is_allowed(key)

    @pytest.mark.asyncio
    async def test_different_keys_independent(self):
        limiter = RateLimiter(10.0, 1.0)
        assert await limiter.is_allowed("clientA")
        assert not await limiter.is_allowed("clientA")
        # clientB should still be allowed
        assert await limiter.is_allowed("clientB")

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        limiter = RateLimiter(1000.0, 100.0)
        key = "client3"
        # simulate concurrent requests
        async def consume():
            return await limiter.is_allowed(key)
        tasks = [consume() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        # All should pass because burst is 100
        assert all(results)

# ---------------------------------------------------------------------------
# NEW: Rate limiter config hot-reload test
# ---------------------------------------------------------------------------

class TestRateLimitConfig:
    def test_update_config_disables_limiter(self, resolver_no_network):
        # start with limiter enabled
        resolver_no_network.rate_limiter = RateLimiter(10.0, 20.0)
        resolver_no_network.rate_limit_rps = 10.0
        resolver_no_network.rate_limit_burst = 20.0

        # disable via update
        resolver_no_network.update_config(rate_limit_rps=0.0, rate_limit_burst=0.0)
        assert resolver_no_network.rate_limiter is None
        assert resolver_no_network.rate_limit_rps == 0.0
        assert resolver_no_network.rate_limit_burst == 0.0

    def test_update_config_enables_limiter(self, resolver_no_network):
        # start disabled
        resolver_no_network.rate_limiter = None
        resolver_no_network.update_config(rate_limit_rps=50.0, rate_limit_burst=100.0)
        assert resolver_no_network.rate_limiter is not None
        assert resolver_no_network.rate_limiter.rate == 50.0
        assert resolver_no_network.rate_limiter.burst == 100.0

    def test_update_config_updates_existing_limiter(self, resolver_no_network):
        limiter = RateLimiter(10.0, 20.0)
        resolver_no_network.rate_limiter = limiter
        resolver_no_network.update_config(rate_limit_rps=30.0, rate_limit_burst=40.0)
        # should be the same object, just updated
        assert resolver_no_network.rate_limiter is limiter
        assert limiter.rate == 30.0
        assert limiter.burst == 40.0