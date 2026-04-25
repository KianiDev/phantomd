# tests/test_phantomd_dhcp.py
import pytest
import asyncio
import time
import struct
import socket
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from core.phantomd_dhcp import (
    ip_to_int, int_to_ip, calc_broadcast,
    DHCPServer, DHCPProtocol,
    BOOTREPLY, DHCPOFFER, DHCPACK, DHCPNAK,
    OPTION_MESSAGE_TYPE, OPTION_LEASE_TIME, OPTION_T1, OPTION_SERVER_ID,
    OPTION_REQUESTED_IP, OPTION_PARAM_REQUEST_LIST, OPTION_END,
    MAGIC_COOKIE, BOOTREQUEST, DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE
)


# ---------------------------------------------------------------------------
# Existing unit tests (kept exactly as before)
# ---------------------------------------------------------------------------

class TestIPConversion:
    def test_ip_to_int(self):
        assert ip_to_int('192.168.1.100') == 0xC0A80164

    def test_int_to_ip(self):
        assert int_to_ip(0xC0A80164) == '192.168.1.100'

    def test_calc_broadcast(self):
        bcast = calc_broadcast('192.168.1.15', '255.255.255.0')
        assert bcast == '192.168.1.255'


class TestMacNormalization:
    def test_bytes_mac(self, dhcp_server):
        mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        assert dhcp_server._normalize_mac(mac) == 'aa:bb:cc:dd:ee:ff'

    def test_colon_format(self, dhcp_server):
        assert dhcp_server._normalize_mac('AA:BB:CC:DD:EE:FF') == 'aa:bb:cc:dd:ee:ff'

    def test_dash_and_plain(self, dhcp_server):
        assert dhcp_server._normalize_mac('aa-bb-cc-dd-ee-ff') == 'aa:bb:cc:dd:ee:ff'
        assert dhcp_server._normalize_mac('AABBCCDDEEFF') == 'aa:bb:cc:dd:ee:ff'

    def test_invalid(self, dhcp_server):
        assert dhcp_server._normalize_mac('bad:mac:is:here') is None
        assert dhcp_server._normalize_mac('') is None


class TestOptions:
    def test_build_and_parse(self, dhcp_server):
        opts = {1: b'\xff\xff\xff\x00', 3: b'\xc0\xa8\x01\x01'}
        blob = dhcp_server.build_options(opts)
        parsed = dhcp_server.parse_options(blob)
        assert parsed[1] == opts[1]
        assert parsed[3] == opts[3]

    def test_padding(self, dhcp_server):
        blob = dhcp_server.build_options({})
        assert len(blob) % 4 == 0


class TestPacketBuilding:
    def test_build_offer(self, dhcp_server):
        chaddr = b'\x11\x22\x33\x44\x55\x66'
        pkt = dhcp_server.build_reply(BOOTREPLY, 0xABCD, chaddr, '192.168.1.110', DHCPOFFER, include_t1t2=True)
        assert len(pkt) >= 240 + 4
        opts = dhcp_server.parse_options(pkt[240:])
        assert opts[OPTION_MESSAGE_TYPE] == bytes([DHCPOFFER])
        assert OPTION_LEASE_TIME in opts
        assert OPTION_T1 in opts

    def test_build_nak(self, dhcp_server):
        nak = dhcp_server.build_nak(0x1234, b'\xaa\xbb\xcc\xdd\xee\xff')
        opts = dhcp_server.parse_options(nak[240:])
        assert opts[OPTION_MESSAGE_TYPE] == bytes([DHCPNAK])
        assert opts[OPTION_SERVER_ID] == socket.inet_aton('192.168.1.1')  # 192.168.1.1


class TestLeaseAllocation:
    def test_new_client_gets_next_free(self, dhcp_server):
        ip = dhcp_server.allocate_for_mac('aa:bb:cc:dd:ee:01')
        assert ip == '192.168.1.100'
        assert dhcp_server.ip_map[ip] == 'aa:bb:cc:dd:ee:01'

    def test_same_mac_renews(self, dhcp_server):
        first = dhcp_server.allocate_for_mac('aa:bb:cc:dd:ee:01')
        second = dhcp_server.allocate_for_mac('aa:bb:cc:dd:ee:01')
        assert first == second

    def test_static_lease_preferred(self):
        srv = DHCPServer(
            subnet="192.168.1.0",
            netmask="255.255.255.0",
            start_ip="192.168.1.100",
            end_ip="192.168.1.200",
            lease_ttl=600,
            server_ip="192.168.1.1",
            static_leases={'aa:bb:cc:dd:ee:02': '192.168.1.200'},
            lease_db_path=None
        )
        srv.lease_backend = 'none'
        ip = srv.allocate_for_mac('aa:bb:cc:dd:ee:02')
        assert ip == '192.168.1.200'

    def test_pool_exhausted(self, dhcp_server):
        dhcp_server.start_ip = '192.168.1.100'
        dhcp_server.end_ip = '192.168.1.100'
        ip1 = dhcp_server.allocate_for_mac('11:22:33:44:55:66')
        assert ip1 == '192.168.1.100'
        ip2 = dhcp_server.allocate_for_mac('aa:bb:cc:dd:ee:ff')
        assert ip2 is None

    def test_expired_lease_reused(self, dhcp_server):
        mac_old = '11:22:33:44:55:66'
        dhcp_server.leases[mac_old] = {'ip': '192.168.1.100', 'expiry': int(time.time()) - 10}
        dhcp_server.ip_map['192.168.1.100'] = mac_old
        ip = dhcp_server.allocate_for_mac('aa:bb:cc:dd:ee:ff')
        assert ip == '192.168.1.100'
        assert mac_old not in dhcp_server.leases


class TestRateLimiting:
    def test_allow_request_consumes_tokens(self, dhcp_server):
        dhcp_server.rate_limit_rps = 100.0
        dhcp_server.rate_limit_burst = 2.0
        mac = 'aa:bb:cc:dd:ee:01'
        ip = '10.0.0.1'
        assert dhcp_server._allow_request(mac, ip)
        assert dhcp_server._allow_request(mac, ip)
        assert not dhcp_server._allow_request(mac, ip)


@pytest.mark.asyncio
async def test_maintenance_cleanup_expired(dhcp_server):
    mac = '11:22:33:44:55:66'
    dhcp_server.leases[mac] = {'ip': '192.168.1.105', 'expiry': int(time.time()) - 5}
    dhcp_server.ip_map['192.168.1.105'] = mac
    async with dhcp_server._lock:
        dhcp_server._cleanup_expired()
    assert mac not in dhcp_server.leases
    assert '192.168.1.105' not in dhcp_server.ip_map


# ---------------------------------------------------------------------------
# DHCPProtocol handler tests – FIXED FIXTURE
# ---------------------------------------------------------------------------

# Helper to build minimal DHCP packets for testing
def _make_dhcp_packet(msg_type: int, xid: int = 0x12345678,
                      chaddr: bytes = b'\xaa\xbb\xcc\xdd\xee\xff',
                      requested_ip: str = None,
                      server_id: str = None,
                      ciaddr: str = '0.0.0.0',
                      flags: int = 0,
                      opts_extra: dict = None) -> bytes:
    op = BOOTREQUEST
    htype = 1
    hlen = 6
    hops = 0
    secs = 0
    ciaddr_b = socket.inet_aton(ciaddr)
    yiaddr_b = b'\x00' * 4
    siaddr_b = b'\x00' * 4
    giaddr_b = b'\x00' * 4
    ch = chaddr.ljust(16, b'\x00')[:16]
    sname = b'\x00' * 64
    filearea = b'\x00' * 128
    header = struct.pack('>BBBBIHH4s4s4s4s16s64s128s',
                         op, htype, hlen, hops, xid, secs, flags,
                         ciaddr_b, yiaddr_b, siaddr_b, giaddr_b, ch, sname, filearea)
    pkt = header + MAGIC_COOKIE
    opts = {}
    opts[OPTION_MESSAGE_TYPE] = bytes([msg_type])
    if requested_ip:
        opts[OPTION_REQUESTED_IP] = socket.inet_aton(requested_ip)
    if server_id:
        opts[OPTION_SERVER_ID] = socket.inet_aton(server_id)
    if opts_extra:
        opts.update(opts_extra)
    parts = bytearray()
    for code, val in opts.items():
        parts.append(code)
        parts.append(len(val))
        parts.extend(val)
    parts.append(OPTION_END)
    return pkt + bytes(parts)


@pytest.fixture
def dhcp_protocol():
    """Return a DHCPProtocol with a real DHCPServer, only critical methods mocked."""
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
    srv._save_leases = MagicMock()
    srv._maybe_async_save = MagicMock()
    srv._cleanup_expired = MagicMock()  # not used in handler tests
    srv.arp_probe_enable = False

    # Mock only the methods we need to control/assert on
    srv._allow_request = MagicMock(return_value=True)
    srv.async_allocate_for_mac = AsyncMock(return_value='192.168.1.100')
    srv.build_reply = MagicMock(return_value=b'\x02\x02' + b'\x00' * 300)
    srv.build_nak = MagicMock(return_value=b'\x03\x03' + b'\x00' * 300)
    srv.async_handle_request = AsyncMock(return_value=b'\x05\x05' + b'\x00' * 300)
    srv.get_primary_ip = MagicMock(return_value='192.168.1.1')
    srv._save_leases = MagicMock()

    # Provide a real lock for async operations
    srv._lock = asyncio.Lock()

    proto = DHCPProtocol(srv)
    return proto


@pytest.mark.asyncio
async def test_discover_sends_offer(dhcp_protocol):
    pkt = _make_dhcp_packet(DHCPDISCOVER, xid=0xAABB)
    transport = MagicMock()
    transport.get_extra_info = MagicMock(return_value=None)
    transport.sendto = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.5', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    dhcp_protocol.server.build_reply.assert_called_once()
    transport.sendto.assert_called()
    sent_data = transport.sendto.call_args[0][0]
    assert sent_data[:2] == b'\x02\x02'

@pytest.mark.asyncio
async def test_request_sends_ack(dhcp_protocol):
    pkt = _make_dhcp_packet(DHCPREQUEST, xid=0xBEEF,
                            requested_ip='192.168.1.110',
                            server_id='192.168.1.1')
    transport = MagicMock()
    transport.get_extra_info = MagicMock(return_value=None)
    transport.sendto = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.6', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    dhcp_protocol.server.async_handle_request.assert_called_once()
    # The handler sends the response from async_handle_request; check that it was sent
    transport.sendto.assert_called()
    sent_data = transport.sendto.call_args[0][0]
    # Our mock async_handle_request returns b'\x05\x05...'
    assert sent_data[:2] == b'\x05\x05'

@pytest.mark.asyncio
async def test_request_wrong_server_id_ignored(dhcp_protocol):
    pkt = _make_dhcp_packet(DHCPREQUEST, xid=0xBEEF,
                            requested_ip='192.168.1.110',
                            server_id='1.2.3.4')
    transport = MagicMock()
    transport.get_extra_info = MagicMock(return_value=None)
    transport.sendto = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.7', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    dhcp_protocol.server.async_handle_request.assert_not_called()
    transport.sendto.assert_not_called()

@pytest.mark.asyncio
async def test_release_removes_lease(dhcp_protocol):
    dhcp_protocol.server.leases['aa:bb:cc:dd:ee:ff'] = {'ip': '192.168.1.150', 'expiry': time.time() + 600}
    dhcp_protocol.server.ip_map = {'192.168.1.150': 'aa:bb:cc:dd:ee:ff'}
    pkt = _make_dhcp_packet(DHCPRELEASE, xid=0xDEAD, ciaddr='192.168.1.150')
    transport = MagicMock()
    transport.get_extra_info = MagicMock(return_value=None)
    transport.sendto = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.8', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    assert 'aa:bb:cc:dd:ee:ff' not in dhcp_protocol.server.leases

@pytest.mark.asyncio
async def test_rate_limited_packet_dropped(dhcp_protocol):
    dhcp_protocol.server._allow_request.return_value = False
    pkt = _make_dhcp_packet(DHCPDISCOVER)
    transport = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.9', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    transport.sendto.assert_not_called()

@pytest.mark.asyncio
async def test_invalid_mac_dropped(dhcp_protocol):
    original = dhcp_protocol.server._normalize_mac
    dhcp_protocol.server._normalize_mac = MagicMock(return_value=None)
    pkt = _make_dhcp_packet(DHCPDISCOVER, chaddr=b'\x00' * 6)
    transport = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.10', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    transport.sendto.assert_not_called()

@pytest.mark.asyncio
async def test_short_packet_ignored(dhcp_protocol):
    transport = MagicMock()
    dhcp_protocol.connection_made(transport)
    dhcp_protocol.datagram_received(b'\x00' * 100, ('10.0.0.11', 68))
    await asyncio.sleep(0.01)
    transport.sendto.assert_not_called()

@pytest.mark.asyncio
async def test_discover_no_ip_available(dhcp_protocol):
    dhcp_protocol.server.async_allocate_for_mac.return_value = None
    pkt = _make_dhcp_packet(DHCPDISCOVER)
    transport = MagicMock()
    dhcp_protocol.connection_made(transport)
    addr = ('10.0.0.12', 68)

    dhcp_protocol.datagram_received(pkt, addr)
    await asyncio.sleep(0.01)

    transport.sendto.assert_not_called()