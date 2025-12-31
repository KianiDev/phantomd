import os
import configparser


def load_config(path='config/phantomd.conf'):
    config = configparser.ConfigParser()
    if not os.path.exists(path):
        # return defaults if config missing
        return {
            'verbose': False,
            'listen_ip': '0.0.0.0',
            'listen_port': 53,
            'upstream_dns': '1.1.1.1',
            'protocol': 'udp',
            'dns_resolver_server': '1.1.1.1:53',
            'disable_ipv6': False,
            'blocklists': {'enabled': False, 'urls': [], 'interval_seconds': 86400, 'action': 'NXDOMAIN'},
            'dhcp': {'enabled': False},
            'dns_cache_ttl': 300,
            'dns_cache_max_size': 1024,
            'dns_logging_enabled': False,
            'dns_log_retention_days': 7,
            'dns_log_dir': '/var/log/phantomd',
            'dns_log_prefix': 'dns-log',
            'dns_pinned_certs': None,
            'dnssec_enabled': False,
            'trust_anchors_file': None,
            'metrics_enabled': False,
            'uvloop_enable': False,
        }
    config.read(path)
    # read blocklists section
    block_enabled = config.getboolean('blocklists', 'enabled', fallback=False)
    block_urls = config.get('blocklists', 'urls', fallback='')
    block_interval = config.getint('blocklists', 'interval_seconds', fallback=86400)
    block_action = config.get('blocklists', 'action', fallback='NXDOMAIN').upper()
    # normalize urls into list
    urls_list = [u.strip() for u in block_urls.split(',') if u.strip()]
    # local blocklist dir & reload behavior
    block_local_dir = config.get('blocklists', 'local_blocklist_dir', fallback='blocklists')
    block_reload_on_change = config.getboolean('blocklists', 'reload_on_change', fallback=True)
    # read disable ipv6 option under upstream
    disable_ipv6 = config.getboolean('upstream', 'disable_ipv6', fallback=False)
    # DNS cache settings
    dns_cache_ttl = config.getint('upstream', 'dns_cache_ttl', fallback=300)
    dns_cache_max_size = config.getint('upstream', 'dns_cache_max_size', fallback=1024)

    # allow performance section to override cache settings
    try:
        perf_ttl = config.getint('performance', 'dns_cache_ttl', fallback=None)
        if perf_ttl is not None:
            dns_cache_ttl = perf_ttl
    except Exception:
        pass
    try:
        perf_max = config.getint('performance', 'dns_cache_max_size', fallback=None)
        if perf_max is not None:
            dns_cache_max_size = perf_max
    except Exception:
        pass

    # DNS request logging settings (under [logging])
    dns_logging_enabled = config.getboolean('logging', 'dns_logging_enabled', fallback=False)
    dns_log_retention_days = config.getint('logging', 'dns_log_retention_days', fallback=7)
    dns_log_dir = config.get('logging', 'dns_log_dir', fallback='/var/log/phantomd')
    dns_log_prefix = config.get('logging', 'dns_log_prefix', fallback='dns-log')
    # convenience: verbose also under logging
    verbose_flag = config.getboolean('logging', 'verbose', fallback=False)

    # DHCP settings
    dhcp_enabled = config.getboolean('dhcp', 'enabled', fallback=False)
    dhcp_subnet = config.get('dhcp', 'subnet', fallback='192.168.1.0')
    dhcp_netmask = config.get('dhcp', 'netmask', fallback='255.255.255.0')
    dhcp_start = config.get('dhcp', 'start_ip', fallback='192.168.1.100')
    dhcp_end = config.get('dhcp', 'end_ip', fallback='192.168.1.200')
    dhcp_lease_ttl = config.getint('dhcp', 'lease_ttl', fallback=86400)
    dhcp_static = config.get('dhcp', 'static_leases', fallback='')
    # rate limiting
    dhcp_rate_limit_rps = config.getfloat('dhcp', 'dhcp_rate_limit_rps', fallback=5.0)
    dhcp_rate_limit_burst = config.getint('dhcp', 'dhcp_rate_limit_burst', fallback=20)
    # DHCP advanced options
    dhcp_arp_probe_enable = config.getboolean('dhcp', 'arp_probe_enable', fallback=True)
    dhcp_arp_probe_timeout = config.getint('dhcp', 'arp_probe_timeout', fallback=1)
    dhcp_privilege_drop_user = config.get('dhcp', 'privilege_drop_user', fallback='nobody')
    dhcp_privilege_drop_group = config.get('dhcp', 'privilege_drop_group', fallback='')
    dhcp_chroot_dir = config.get('dhcp', 'chroot_dir', fallback='')
    dhcp_test_bind_port = config.getint('dhcp', 'test_bind_port', fallback=67)
    lease_sqlite_enabled = config.getboolean('dhcp', 'lease_sqlite_enabled', fallback=True)
    lease_sqlite_path = config.get('dhcp', 'lease_sqlite_path', fallback='/var/lib/phantomd/dhcp_leases.sqlite')
    # parse static leases in format mac=ip,mac=ip
    static_leases = {}
    for item in [s.strip() for s in dhcp_static.split(',') if s.strip()]:
        try:
            mac, ip = item.split('=', 1)
            static_leases[mac.strip().lower()] = ip.strip()
        except Exception:
            continue
    # lease DB path - normalize key used across codebase
    dhcp_lease_db = config.get('dhcp', 'dhcp_lease_db', fallback='/var/lib/phantomd/dhcp_leases.json')

    # Security and advanced options
    dns_resolver_server = config.get('upstream', 'dns_resolver_server', fallback='1.1.1.1:53')
    dnssec_enabled = config.getboolean('upstream', 'dnssec_enabled', fallback=False)
    trust_anchors_file = config.get('upstream', 'trust_anchors_file', fallback='')
    # pinned certs: comma separated host=fingerprint (sha256 hex)
    pinned_raw = config.get('upstream', 'pinned_certs', fallback='')
    pinned_dict = {}
    for item in [s.strip() for s in pinned_raw.split(',') if s.strip()]:
        try:
            host, fp = item.split('=', 1)
            pinned_dict[host.strip()] = fp.strip()
        except Exception:
            continue

    # monitoring & perf
    metrics_enabled = config.getboolean('monitoring', 'metrics_enabled', fallback=False)
    uvloop_enable = config.getboolean('performance', 'uvloop_enable', fallback=False)
    metrics_port = config.getint('monitoring', 'metrics_port', fallback=8000)

    # interface and security helpers
    listen_loopback_only = config.getboolean('interface', 'listen_loopback_only', fallback=False)
    require_privileged_bind = config.getboolean('security', 'require_privileged_bind', fallback=False)
    log_dir_owner = config.get('security', 'log_dir_owner', fallback='root:root')
    lease_db_owner = config.get('security', 'lease_db_owner', fallback='root:root')

    # advanced tuning
    upstream_retries = config.getint('advanced', 'upstream_retries', fallback=2)
    upstream_initial_backoff = config.getfloat('advanced', 'upstream_initial_backoff', fallback=0.1)
    upstream_udp_timeout = config.getfloat('advanced', 'upstream_udp_timeout', fallback=2.0)
    upstream_tcp_timeout = config.getfloat('advanced', 'upstream_tcp_timeout', fallback=5.0)
    upstream_doh_timeout = config.getfloat('advanced', 'upstream_doh_timeout', fallback=5.0)

    return {
        'verbose': verbose_flag,
        'listen_ip': config.get('interface', 'listen_ip', fallback='0.0.0.0'),
        'listen_port': config.getint('interface', 'listen_port', fallback=53),
        'listen_loopback_only': listen_loopback_only,
        'upstream_dns': config.get('upstream', 'dns_server', fallback='1.1.1.1'),
        'protocol': config.get('upstream', 'dns_protocol', fallback='udp'),
        'dns_resolver_server': dns_resolver_server,
        'disable_ipv6': disable_ipv6,
        'blocklists': {'enabled': block_enabled, 'urls': urls_list, 'interval_seconds': block_interval, 'action': block_action, 'local_blocklist_dir': block_local_dir, 'reload_on_change': block_reload_on_change},
        'dhcp': {'enabled': dhcp_enabled, 'subnet': dhcp_subnet, 'netmask': dhcp_netmask, 'start_ip': dhcp_start, 'end_ip': dhcp_end, 'lease_ttl': dhcp_lease_ttl, 'static_leases': static_leases, 'lease_db_path': dhcp_lease_db, 'rate_limit_rps': dhcp_rate_limit_rps, 'rate_limit_burst': dhcp_rate_limit_burst},
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
    }
