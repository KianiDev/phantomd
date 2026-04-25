import os
import configparser
from typing import Dict, Any, List, Optional


def load_config(path: str = 'config/phantomd.conf') -> Dict[str, Any]:
    """Load and parse the phantomd configuration file.

    If the file does not exist, a complete set of safe defaults is returned.
    All sections and options are accessed via fallback values, so the
    resulting dictionary always contains every expected key.

    Returns:
        A dictionary containing all configuration values.
    """
    config: configparser.ConfigParser = configparser.ConfigParser()
    if not os.path.exists(path):
        # Return a full set of defaults when no config file is present.
        # This ensures all expected keys are available with safe values.
        return {
            'verbose': False,
            'listen_ip': '0.0.0.0',
            'listen_port': 53,
            'listen_loopback_only': False,
            'upstream_dns': '1.1.1.1',
            'protocol': 'udp',
            'dns_resolver_server': '1.1.1.1:53',
            'disable_ipv6': False,
            'blocklists': {
                'enabled': False,
                'urls': [],
                'interval_seconds': 86400,
                'action': 'NXDOMAIN',
                'local_blocklist_dir': 'blocklists',
                'reload_on_change': True
            },
            'dhcp': {
                'enabled': False,
                'subnet': '192.168.1.0',
                'netmask': '255.255.255.0',
                'start_ip': '192.168.1.100',
                'end_ip': '192.168.1.200',
                'lease_ttl': 86400,
                'static_leases': {},
                'lease_db_path': '/var/lib/phantomd/dhcp_leases.json',
                'rate_limit_rps': 5.0,
                'rate_limit_burst': 20
            },
            'dns_cache_ttl': 300,
            'dns_cache_max_size': 1024,
            'dns_logging_enabled': False,
            'dns_log_retention_days': 7,
            'dns_log_dir': '/var/log/phantomd',
            'dns_log_prefix': 'dns-log',
            'dns_pinned_certs': {},
            'dnssec_enabled': False,
            'trust_anchors_file': '',
            'metrics_enabled': False,
            'metrics_port': 8000,
            'uvloop_enable': False,
            'require_privileged_bind': False,
            'log_dir_owner': 'root:root',
            'lease_db_owner': 'root:root',
            'lease_sqlite_enabled': True,
            'lease_sqlite_path': '/var/lib/phantomd/dhcp_leases.sqlite',
            'dhcp_arp_probe_enable': True,
            'dhcp_arp_probe_timeout': 1,
            'dhcp_privilege_drop_user': 'nobody',
            'dhcp_privilege_drop_group': '',
            'dhcp_chroot_dir': '',
            'dhcp_test_bind_port': 67,
            'upstream_retries': 2,
            'upstream_initial_backoff': 0.1,
            'upstream_udp_timeout': 2.0,
            'upstream_tcp_timeout': 5.0,
            'upstream_doh_timeout': 5.0,
            'rate_limit_rps': 0.0,
            'rate_limit_burst': 0.0,
            'upstreams': [],     # new: list of upstream server configs
        }
    config.read(path)

    # read blocklists section
    block_enabled: bool = config.getboolean('blocklists', 'enabled', fallback=False)
    block_urls: str = config.get('blocklists', 'urls', fallback='')
    block_interval: int = config.getint('blocklists', 'interval_seconds', fallback=86400)
    block_action: str = config.get('blocklists', 'action', fallback='NXDOMAIN').upper()
    urls_list: List[str] = [u.strip() for u in block_urls.split(',') if u.strip()]
    block_local_dir: str = config.get('blocklists', 'local_blocklist_dir', fallback='blocklists')
    block_reload_on_change: bool = config.getboolean('blocklists', 'reload_on_change', fallback=True)

    # read disable ipv6 option under upstream
    disable_ipv6: bool = config.getboolean('upstream', 'disable_ipv6', fallback=False)

    # DNS cache settings
    dns_cache_ttl: int = config.getint('upstream', 'dns_cache_ttl', fallback=300)
    dns_cache_max_size: int = config.getint('upstream', 'dns_cache_max_size', fallback=1024)

    # allow performance section to override cache settings
    try:
        perf_ttl: Optional[int] = config.getint('performance', 'dns_cache_ttl', fallback=None)
        if perf_ttl is not None:
            dns_cache_ttl = perf_ttl
    except Exception:
        pass
    try:
        perf_max: Optional[int] = config.getint('performance', 'dns_cache_max_size', fallback=None)
        if perf_max is not None:
            dns_cache_max_size = perf_max
    except Exception:
        pass

    # DNS request logging settings (under [logging])
    dns_logging_enabled: bool = config.getboolean('logging', 'dns_logging_enabled', fallback=False)
    dns_log_retention_days: int = config.getint('logging', 'dns_log_retention_days', fallback=7)
    dns_log_dir: str = config.get('logging', 'dns_log_dir', fallback='/var/log/phantomd')
    dns_log_prefix: str = config.get('logging', 'dns_log_prefix', fallback='dns-log')
    verbose_flag: bool = config.getboolean('logging', 'verbose', fallback=False)

    # DHCP settings
    dhcp_enabled: bool = config.getboolean('dhcp', 'enabled', fallback=False)
    dhcp_subnet: str = config.get('dhcp', 'subnet', fallback='192.168.1.0')
    dhcp_netmask: str = config.get('dhcp', 'netmask', fallback='255.255.255.0')
    dhcp_start: str = config.get('dhcp', 'start_ip', fallback='192.168.1.100')
    dhcp_end: str = config.get('dhcp', 'end_ip', fallback='192.168.1.200')
    dhcp_lease_ttl: int = config.getint('dhcp', 'lease_ttl', fallback=86400)
    dhcp_static: str = config.get('dhcp', 'static_leases', fallback='')
    dhcp_rate_limit_rps: float = config.getfloat('dhcp', 'dhcp_rate_limit_rps', fallback=5.0)
    dhcp_rate_limit_burst: int = config.getint('dhcp', 'dhcp_rate_limit_burst', fallback=20)
    dhcp_arp_probe_enable: bool = config.getboolean('dhcp', 'arp_probe_enable', fallback=True)
    dhcp_arp_probe_timeout: int = config.getint('dhcp', 'arp_probe_timeout', fallback=1)
    dhcp_privilege_drop_user: str = config.get('dhcp', 'privilege_drop_user', fallback='nobody')
    dhcp_privilege_drop_group: str = config.get('dhcp', 'privilege_drop_group', fallback='')
    dhcp_chroot_dir: str = config.get('dhcp', 'chroot_dir', fallback='')
    dhcp_test_bind_port: int = config.getint('dhcp', 'bind_port', fallback=67)
    lease_sqlite_enabled: bool = config.getboolean('dhcp', 'lease_sqlite_enabled', fallback=True)
    lease_sqlite_path: str = config.get('dhcp', 'lease_sqlite_path', fallback='/var/lib/phantomd/dhcp_leases.sqlite')
    static_leases: Dict[str, str] = {}
    for item in [s.strip() for s in dhcp_static.split(',') if s.strip()]:
        try:
            mac, ip = item.split('=', 1)
            static_leases[mac.strip().lower()] = ip.strip()
        except Exception:
            continue
    dhcp_lease_db: str = config.get('dhcp', 'dhcp_lease_db', fallback='/var/lib/phantomd/dhcp_leases.json')

    # Security and advanced options
    dns_resolver_server: str = config.get('upstream', 'dns_resolver_server', fallback='1.1.1.1:53')
    dnssec_enabled: bool = config.getboolean('upstream', 'dnssec_enabled', fallback=False)
    trust_anchors_file: str = config.get('upstream', 'trust_anchors_file', fallback='')
    pinned_raw: str = config.get('upstream', 'pinned_certs', fallback='')
    pinned_dict: Dict[str, str] = {}
    for item in [s.strip() for s in pinned_raw.split(',') if s.strip()]:
        try:
            host, fp = item.split('=', 1)
            pinned_dict[host.strip()] = fp.strip()
        except Exception:
            continue

    # monitoring & perf
    metrics_enabled: bool = config.getboolean('monitoring', 'metrics_enabled', fallback=False)
    uvloop_enable: bool = config.getboolean('performance', 'uvloop_enable', fallback=False)
    metrics_port: int = config.getint('monitoring', 'metrics_port', fallback=8000)

    # interface and security helpers
    listen_loopback_only: bool = config.getboolean('interface', 'listen_loopback_only', fallback=False)
    require_privileged_bind: bool = config.getboolean('security', 'require_privileged_bind', fallback=False)
    log_dir_owner: str = config.get('security', 'log_dir_owner', fallback='root:root')
    lease_db_owner: str = config.get('security', 'lease_db_owner', fallback='root:root')

    # advanced tuning
    upstream_retries: int = config.getint('advanced', 'upstream_retries', fallback=2)
    upstream_initial_backoff: float = config.getfloat('advanced', 'upstream_initial_backoff', fallback=0.1)
    upstream_udp_timeout: float = config.getfloat('advanced', 'upstream_udp_timeout', fallback=2.0)
    upstream_tcp_timeout: float = config.getfloat('advanced', 'upstream_tcp_timeout', fallback=5.0)
    upstream_doh_timeout: float = config.getfloat('advanced', 'upstream_doh_timeout', fallback=5.0)
    rate_limit_rps: float = config.getfloat('advanced', 'rate_limit_rps', fallback=0.0)
    rate_limit_burst: float = config.getfloat('advanced', 'rate_limit_burst', fallback=0.0)

    # --- NEW: Multi-upstream parsing ---
    upstreams: List[Dict[str, Any]] = []
    if config.has_section('upstreams') and config.has_option('upstreams', 'servers'):
        server_names = [s.strip() for s in config.get('upstreams', 'servers').split(',') if s.strip()]
        for name in server_names:
            section = f'upstreams.{name}'
            if not config.has_section(section):
                continue
            address = config.get(section, 'address', fallback='')
            if not address:
                continue
            proto = config.get(section, 'protocol', fallback='udp').lower()
            port_str = config.get(section, 'port', fallback=None)
            if port_str:
                try:
                    port = int(port_str)
                except ValueError:
                    port = None
            else:
                # default ports per protocol
                if proto == 'tls':
                    port = 853
                elif proto == 'https':
                    port = 443
                elif proto == 'quic':
                    port = 784
                else:
                    port = 53
            hostname = config.get(section, 'hostname', fallback='') or address
            upstreams.append({
                'address': address,
                'protocol': proto,
                'port': port,
                'hostname': hostname,
            })

    return {
        'verbose': verbose_flag,
        'listen_ip': config.get('interface', 'listen_ip', fallback='0.0.0.0'),
        'listen_port': config.getint('interface', 'listen_port', fallback=53),
        'listen_loopback_only': listen_loopback_only,
        'upstream_dns': config.get('upstream', 'dns_server', fallback='1.1.1.1'),
        'protocol': config.get('upstream', 'dns_protocol', fallback='udp'),
        'dns_resolver_server': dns_resolver_server,
        'disable_ipv6': disable_ipv6,
        'blocklists': {
            'enabled': block_enabled,
            'urls': urls_list,
            'interval_seconds': block_interval,
            'action': block_action,
            'local_blocklist_dir': block_local_dir,
            'reload_on_change': block_reload_on_change
        },
        'dhcp': {
            'enabled': dhcp_enabled,
            'subnet': dhcp_subnet,
            'netmask': dhcp_netmask,
            'start_ip': dhcp_start,
            'end_ip': dhcp_end,
            'lease_ttl': dhcp_lease_ttl,
            'static_leases': static_leases,
            'lease_db_path': dhcp_lease_db,
            'rate_limit_rps': dhcp_rate_limit_rps,
            'rate_limit_burst': dhcp_rate_limit_burst
        },
        'dns_cache_ttl': dns_cache_ttl,
        'dns_cache_max_size': dns_cache_max_size,
        'dns_logging_enabled': dns_logging_enabled,
        'dns_log_retention_days': dns_log_retention_days,
        'dns_log_dir': dns_log_dir,
        'dns_log_prefix': dns_log_prefix,
        'dns_pinned_certs': pinned_dict,
        'dnssec_enabled': dnssec_enabled,
        'trust_anchors_file': trust_anchors_file,
        'metrics_enabled': metrics_enabled,
        'metrics_port': metrics_port,
        'uvloop_enable': uvloop_enable,
        'require_privileged_bind': require_privileged_bind,
        'log_dir_owner': log_dir_owner,
        'lease_db_owner': lease_db_owner,
        'lease_sqlite_enabled': lease_sqlite_enabled,
        'lease_sqlite_path': lease_sqlite_path,
        'dhcp_arp_probe_enable': dhcp_arp_probe_enable,
        'dhcp_arp_probe_timeout': dhcp_arp_probe_timeout,
        'dhcp_privilege_drop_user': dhcp_privilege_drop_user,
        'dhcp_privilege_drop_group': dhcp_privilege_drop_group,
        'dhcp_chroot_dir': dhcp_chroot_dir,
        'dhcp_test_bind_port': dhcp_test_bind_port,
        'upstream_retries': upstream_retries,
        'upstream_initial_backoff': upstream_initial_backoff,
        'upstream_udp_timeout': upstream_udp_timeout,
        'upstream_tcp_timeout': upstream_tcp_timeout,
        'upstream_doh_timeout': upstream_doh_timeout,
        'rate_limit_rps': rate_limit_rps,
        'rate_limit_burst': rate_limit_burst,
        'upstreams': upstreams,  # new: list of upstream dicts
    }