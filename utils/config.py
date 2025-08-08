import configparser
import os

def load_config(path='config/phantomd.conf'):
    config = configparser.ConfigParser()
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")
    config.read(path)
    return {
        "upstream_dns": config.get("upstream", "dns_server", fallback="1.1.1.1"),
        "protocol": config.get("upstream", "dns_protocol", fallback="udp"),
        "listen_ip": config.get("interface", "listen_ip", fallback="0.0.0.0"),
        "listen_port": config.getint("interface", "listen_port", fallback=53),
        "verbose": config.getboolean("logging", "verbose", fallback=False),
        "dns_resolver_server": config.get("logging", "dns_resolver_server", fallback="1.1.1.1:53")
    }
