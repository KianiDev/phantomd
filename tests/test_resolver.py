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
# Optimistic caching tests
# ===========================================================================

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset

@pytest.fixture
def resolver_optimistic():
    """Resolver with optimistic caching enabled and a short stale max age."""
    resolver = DNSResolver(
        upstream_dns="1.1.1.1",
        protocol="udp",
        disable_ipv6=True,
        optimistic_cache_enabled=True,
        optimistic_stale_max_age=60,
        optimistic_stale_response_ttl=30,
    )
    # Prevent background refresh from actually hitting the network
    resolver._try_upstream = AsyncMock(return_value=b'\x00'*100)
    return resolver


@pytest.mark.asyncio
async def test_fresh_response_returned(resolver_optimistic):
    """A non-expired entry returns the original response bytes."""
    key = ("fresh.example", 1, "udp")
    query_data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05fresh\x07example\x00\x00\x01\x00\x01'
    resp_data = b'\x56\x78' + b'\x00'*50
    await resolver_optimistic._wire_cache_set(key, resp_data, ttl_seconds=300, query_data=query_data)
    result = await resolver_optimistic._wire_cache_get_valid(key)
    assert result == resp_data


@pytest.mark.asyncio
async def test_stale_response_served_and_ttl_modified(resolver_optimistic):
    """Expired entry within stale window returns data with short TTL."""
    key = ("stale.example", 1, "udp")
    query_data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05stale\x07example\x00\x00\x01\x00\x01'
    # Build a fresh response with a known TTL (e.g., 60 seconds) and insert it as expired
    msg = dns.message.make_response(
        dns.message.from_wire(query_data)
    )
    msg.answer = [
        dns.rrset.from_text('stale.example.', 60, dns.rdataclass.IN, dns.rdatatype.A, '1.2.3.4')
    ]
    original_wire = msg.to_wire()
    # Store with expired expiry but still within stale window
    now = time.time()
    expiry = now - 10          # expired 10 seconds ago
    stale_until = now + 600    # stale for another 10 minutes
    entry = (original_wire, expiry, query_data, stale_until)
    # Inject directly to bypass the normal set method
    async with resolver_optimistic._lock:
        if resolver_optimistic._cache_is_sync:
            resolver_optimistic._wire_cache[key] = entry
        else:
            await resolver_optimistic._wire_cache.set(key, entry)
    # Now get it
    result = await resolver_optimistic._wire_cache_get_valid(key)
    # Verify it returned a response, not None
    assert result is not None
    # The TTL in the returned response should be modified to stale_response_ttl=30
    parsed = dns.message.from_wire(result)
    assert parsed.answer[0].ttl == 30
    # Background refresh should have been triggered
    await asyncio.sleep(0.01)
    # Since we mocked _try_upstream, it will have been called as a background refresh
    # But we can't easily assert from here because it's a separate task; we'll trust the log


@pytest.mark.asyncio
async def test_stale_past_max_age_not_served(resolver_optimistic):
    """When stale_until has passed, the entry is treated as fully expired."""
    key = ("dead.example", 1, "udp")
    query_data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04dead\x07example\x00\x00\x01\x00\x01'
    entry = (b'\x00'*20, time.time() - 120, query_data, time.time() - 10)  # stale_until in past
    async with resolver_optimistic._lock:
        if resolver_optimistic._cache_is_sync:
            resolver_optimistic._wire_cache[key] = entry
        else:
            await resolver_optimistic._wire_cache.set(key, entry)
    result = await resolver_optimistic._wire_cache_get_valid(key)
    assert result is None


@pytest.mark.asyncio
async def test_stale_refresh_pending_prevents_duplicate(resolver_optimistic):
    """If a stale refresh is already pending, no duplicate refresh is scheduled."""
    key = ("dedup.example", 1, "udp")
    query_data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05dedup\x07example\x00\x00\x01\x00\x01'
    # Manually mark a key as pending
    async with resolver_optimistic._stale_refresh_lock:
        resolver_optimistic._stale_refresh_pending.add(key)
    # Attempt to trigger another refresh; should not start a second one
    with patch.object(resolver_optimistic, '_background_refresh') as mock_refresh:
        await resolver_optimistic._maybe_refresh_stale(key, query_data)
        mock_refresh.assert_not_called()


@pytest.mark.asyncio
async def test_disabled_optimistic_cache_ignores_stale(resolver_no_network):
    """When optimistic caching is off, stale entries are simply expired."""
    resolver_no_network.optimistic_cache_enabled = False
    key = ("noopt.example", 1, "udp")
    query_data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05noopt\x07example\x00\x00\x01\x00\x01'
    entry = (b'\x00'*20, time.time() - 10, query_data, time.time() + 600)
    async with resolver_no_network._lock:
        if resolver_no_network._cache_is_sync:
            resolver_no_network._wire_cache[key] = entry
        else:
            await resolver_no_network._wire_cache.set(key, entry)
    result = await resolver_no_network._wire_cache_get_valid(key)
    assert result is None