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
    return {
        "upstream_dns": config.get("upstream", "dns_server", fallback="1.1.1.1"),
        "protocol": config.get("upstream", "dns_protocol", fallback="udp"),
        "listen_ip": config.get("interface", "listen_ip", fallback="0.0.0.0"),
        "listen_port": config.getint("interface", "listen_port", fallback=53),
        "verbose": config.getboolean("logging", "verbose", fallback=False),
        "dns_resolver_server": config.get("logging", "dns_resolver_server", fallback="1.1.1.1:53"),
        "disable_ipv6": disable_ipv6,
        "blocklists": {
            "enabled": block_enabled,
            "urls": urls_list,
            "interval_seconds": block_interval,
            "action": block_action
        }
    }
