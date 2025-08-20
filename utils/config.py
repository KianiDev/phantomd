import configparser
import os

def load_config(path='config/phantomd.conf'):
    config = configparser.ConfigParser()
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")
    config.read(path)
    # read blocklists section
    block_enabled = config.getboolean('blocklists', 'enabled', fallback=False)
    block_urls = config.get('blocklists', 'urls', fallback='')
    block_interval = config.getint('blocklists', 'interval_seconds', fallback=86400)
    block_action = config.get('blocklists', 'action', fallback='NXDOMAIN').upper()
    # normalize urls into list
    urls_list = [u.strip() for u in block_urls.split(',') if u.strip()]
    # read disable ipv6 option under upstream
    disable_ipv6 = config.getboolean('upstream', 'disable_ipv6', fallback=False)

    # DHCP settings
    dhcp_enabled = config.getboolean('dhcp', 'enabled', fallback=False)
    dhcp_subnet = config.get('dhcp', 'subnet', fallback='192.168.1.0')
    dhcp_netmask = config.get('dhcp', 'netmask', fallback='255.255.255.0')
    dhcp_start = config.get('dhcp', 'start_ip', fallback='192.168.1.100')
    dhcp_end = config.get('dhcp', 'end_ip', fallback='192.168.1.200')
    dhcp_lease_ttl = config.getint('dhcp', 'lease_ttl', fallback=86400)
    dhcp_static = config.get('dhcp', 'static_leases', fallback='')
    # parse static leases in format mac=ip,mac=ip
    static_leases = {}
    for item in [s.strip() for s in dhcp_static.split(',') if s.strip()]:
        if '=' in item:
            mac, ip = item.split('=', 1)
            static_leases[mac.strip().lower()] = ip.strip()
    # lease DB path
    dhcp_lease_db = config.get('dhcp', 'lease_db_path', fallback='/var/lib/phantomd/dhcp_leases.json')

    return {
        "upstream_dns": config.get("upstream", "dns_server", fallback="1.1.1.1"),
        "protocol": config.get("upstream", "dns_protocol", fallback="udp"),
        "listen_ip": config.get("interface", "listen_ip", fallback="0.0.0.0"),
        "listen_port": config.getint("interface", "listen_port", fallback=53),
        "verbose": config.getboolean("logging", "verbose", fallback=False),
        "dns_resolver_server": config.get("logging", "dns_resolver_server", fallback="1.1.1.1:53"),
        "disable_ipv6": disable_ipv6,
        "dhcp": {
            "enabled": dhcp_enabled,
            "subnet": dhcp_subnet,
            "netmask": dhcp_netmask,
            "start_ip": dhcp_start,
            "end_ip": dhcp_end,
            "lease_ttl": dhcp_lease_ttl,
            "static_leases": static_leases,
            "lease_db_path": dhcp_lease_db
        },
        "blocklists": {
            "enabled": block_enabled,
            "urls": urls_list,
            "interval_seconds": block_interval,
            "action": block_action
        }
    }
