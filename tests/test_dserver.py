# tests/test_dserver.py
import pytest
from core.dserver import BLOCK_ACTION_NX
from core.resolver import DNSResolver


class TestBlockAction:
    def test_block_action_override(self):
        resolver = DNSResolver(
            upstream_dns="1.1.1.1",
            protocol="udp",
            disable_ipv6=True
        )
        resolver.set_block_action('ZEROIP')
        assert resolver.get_block_action() == 'ZEROIP'

        # build_block_response should reflect that
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        query += b'\x03bad\x07example\x03com\x00\x00\x01\x00\x01'
        resp = resolver.build_block_response(query)
        # When action is ZEROIP, an A record with 0.0.0.0 should be present
        assert b'\x00\x00\x00\x00' in resp  # zero IP in answer