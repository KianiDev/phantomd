# tests/test_resolver.py
import pytest
from core.resolver import DNSResolver, _HAS_CACHETOOLS


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
            b'\xc0\x0c'   # pointer to offset 12
        )
        name, offset = DNSResolver._parse_dns_name(data, 20)
        assert name == "example.com"
        assert offset == 22

    def test_parse_pointer_loop(self):
        data = bytearray(b'\x00' * 20)
        data[12] = 0xC0
        data[13] = 12  # points to itself
        with pytest.raises(ValueError):
            DNSResolver._parse_dns_name(data, 12)

    def test_extract_qname(self, resolver_no_network):
        data = b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        data += b'\x03ftp\x07example\x03com\x00\x00\x01\x00\x01'
        qname = resolver_no_network._extract_qname_from_wire(data)
        assert qname == "ftp.example.com"

    def test_extract_qtype(self, resolver_no_network):
        data = b'\x00' * 12 + b'\x03abc\x00\x00\x1c\x00\x01'
        qtype = resolver_no_network._extract_qtype_from_wire(data)
        assert qtype == 28  # AAAA


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
        # Set with TTL=0 → immediate expiry
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