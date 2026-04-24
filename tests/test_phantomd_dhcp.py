# tests/test_phantomd_dhcp.py
import pytest
import time
from core.phantomd_dhcp import (
    ip_to_int, int_to_ip, calc_broadcast,
    DHCPServer, DHCPProtocol,
    BOOTREPLY, DHCPOFFER, DHCPNAK, DHCPACK,
    OPTION_MESSAGE_TYPE, OPTION_LEASE_TIME, OPTION_T1, OPTION_SERVER_ID
)


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
        assert opts[OPTION_SERVER_ID] == b'\xc0\xa8\x01\x01'  # 192.168.1.1


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
        # single IP pool
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
        # old mac should be cleaned
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