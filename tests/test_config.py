# tests/test_config.py
import os
import tempfile
from utils.config import load_config


def test_default_config_when_missing():
    config = load_config(path='/non/existent/phantomd.conf')
    assert config['upstream_dns'] == '1.1.1.1'
    assert config['protocol'] == 'udp'
    assert config['blocklists']['enabled'] is False
    assert config['dhcp']['enabled'] is False


def test_parses_config_file():
    content = """[upstream]
dns_server = 8.8.8.8
dns_protocol = tls
disable_ipv6 = true
dns_cache_ttl = 600

[blocklists]
enabled = true
urls = http://example.com/block.txt, http://example.org/list.txt
action = ZEROIP

[dhcp]
enabled = true
subnet = 192.168.0.0
netmask = 255.255.255.0
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(content)
        temp_path = f.name

    try:
        config = load_config(path=temp_path)
        assert config['upstream_dns'] == '8.8.8.8'
        assert config['protocol'] == 'tls'
        assert config['disable_ipv6'] is True
        assert config['dns_cache_ttl'] == 600
        assert config['blocklists']['enabled'] is True
        assert len(config['blocklists']['urls']) == 2
        assert config['blocklists']['action'] == 'ZEROIP'
        assert config['dhcp']['enabled'] is True
        assert config['dhcp']['subnet'] == '192.168.0.0'
    finally:
        os.unlink(temp_path)