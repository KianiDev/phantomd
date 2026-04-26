from utils.config import load_config
import os
import sys
import argparse
import logging
import asyncio
import signal
import concurrent.futures
from typing import Any, Dict, Optional, List, Tuple, Callable, Awaitable

from core.dserver import run_server, reload_resolver, ResolverHolder
from core.resolver import DNSResolver
from utils.ListUpdater import fetch_blocklists_sync


def main() -> None:
    parser = argparse.ArgumentParser(description="phantomd DNS server")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    config: Dict[str, Any] = load_config()
    verbose: bool = args.verbose or config.get("verbose", False)

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='[%(levelname)s] %(message)s'
    )

    upstream_dns: Optional[str] = config.get("upstream_dns")
    protocol: str = config.get("protocol", "udp")
    if not upstream_dns:
        logging.critical("Missing required configuration key: 'upstream_dns'")
        sys.exit(1)

    listen_loopback: bool = bool(config.get('listen_loopback_only', False))
    listen_ip_cfg: Optional[str] = config.get('listen_ip')
    if listen_loopback:
        listen_ip_cfg = '127.0.0.1'

    require_priv: bool = bool(config.get('require_privileged_bind', False))
    listen_port_cfg: int = int(config.get('listen_port', 53))
    if require_priv and listen_port_cfg < 1024:
        try:
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                logging.critical('Config requires privileged bind but process is not running as root. Exiting.')
                sys.exit(1)
        except Exception:
            logging.warning('Unable to verify privileges on this platform; ensure process has permission to bind privileged ports.')

    logging.info("Configuration loaded successfully:")
    for key, value in config.items():
        logging.info(f"{key}: {value}")

    if config.get("uvloop_enable", False):
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            logging.info("uvloop enabled")
        except Exception as e:
            logging.warning("Failed to enable uvloop: %s", e)

    # Extract typed configuration values
    dns_resolver_server: str = str(config.get("dns_resolver_server") or "")
    disable_ipv6_flag: bool = bool(config.get("disable_ipv6", False))
    dns_cache_ttl_val: int = int(config.get("dns_cache_ttl", 300))
    dns_cache_max_size_val: int = int(config.get("dns_cache_max_size", 1024))
    dns_logging_enabled_flag: bool = bool(config.get("dns_logging_enabled", False))
    dns_log_retention_days_val: int = int(config.get("dns_log_retention_days", 7))
    dns_log_dir_str: str = str(config.get("dns_log_dir", "/var/log/phantomd"))
    dns_log_prefix_str: str = str(config.get("dns_log_prefix", "dns-log"))
    dns_pinned_certs_dict: Dict[str, str] = config.get("dns_pinned_certs") or {}
    dnssec_enabled_flag: bool = bool(config.get("dnssec_enabled", False))
    trust_anchors_file_str: str = str(config.get("trust_anchors_file") or "")
    metrics_enabled_flag: bool = bool(config.get("metrics_enabled", False))
    metrics_port_val: int = int(config.get("metrics_port", 8000))
    upstream_retries_val: int = int(config.get("upstream_retries", 2))
    upstream_initial_backoff_val: float = float(config.get("upstream_initial_backoff", 0.1))
    upstream_udp_timeout_val: float = float(config.get("upstream_udp_timeout", 2.0))
    upstream_tcp_timeout_val: float = float(config.get("upstream_tcp_timeout", 5.0))
    upstream_doh_timeout_val: float = float(config.get("upstream_doh_timeout", 5.0))
    rate_limit_rps_val: float = float(config.get("rate_limit_rps", 0.0))
    rate_limit_burst_val: float = float(config.get("rate_limit_burst", 0.0))
    upstreams_val: List[Dict[str, Any]] = config.get("upstreams", [])
    optimistic_cache_enabled_val: bool = bool(config.get("optimistic_cache_enabled", False))
    optimistic_stale_max_age_val: int = int(config.get("optimistic_stale_max_age", 86400))
    optimistic_stale_response_ttl_val: int = int(config.get("optimistic_stale_response_ttl", 30))
    dns_privilege_drop_user_val: str = str(config.get("dns_privilege_drop_user", ""))
    dns_privilege_drop_group_val: str = str(config.get("dns_privilege_drop_group", ""))
    dns_chroot_dir_val: str = str(config.get("dns_chroot_dir", ""))
    dns_rebind_protection_val: bool = bool(config.get("dns_rebind_protection", False))
    dns_rebind_action_val: str = str(config.get("dns_rebind_action", "strip"))

    # NEW: connection pooling config
    pool_max_size_val: int = int(config.get("pool_max_size", 5))
    pool_idle_timeout_val: float = float(config.get("pool_idle_timeout", 60.0))

    # DHCP configuration
    dhcp_cfg: Dict[str, Any] = config.get('dhcp', {})
    dhcp_start_fn: Optional[Callable[[], Awaitable[None]]] = None
    if dhcp_cfg.get('enabled'):
        try:
            from core.phantomd_dhcp import DHCPServer as _DHCPImpl
        except Exception as e:
            logging.warning("DHCP enabled in config but DHCP module failed to import; skipping DHCP startup: %s", e)
            _dh = None
        else:
            _dh = _DHCPImpl

        if _dh is None:
            logging.warning("DHCP enabled in config but no DHCPServer implementation available; skipping DHCP startup")
        else:
            try:
                dhcp = _dh(
                    subnet=dhcp_cfg.get('subnet'),
                    netmask=dhcp_cfg.get('netmask'),
                    start_ip=dhcp_cfg.get('start_ip'),
                    end_ip=dhcp_cfg.get('end_ip'),
                    lease_ttl=dhcp_cfg.get('lease_ttl'),
                    static_leases=dhcp_cfg.get('static_leases') or {},
                    server_ip=None,
                    lease_db_path=dhcp_cfg.get('lease_db_path')
                )
                try:
                    dhcp.arp_probe_enable = bool(config.get('dhcp_arp_probe_enable', True))
                    dhcp.arp_probe_timeout = int(config.get('dhcp_arp_probe_timeout', 1))
                    dhcp.privilege_drop_user = config.get('dhcp_privilege_drop_user', 'nobody')
                    dhcp.privilege_drop_group = config.get('dhcp_privilege_drop_group', '')
                    dhcp.chroot_dir = config.get('dhcp_chroot_dir', '')
                    dhcp.test_bind_port = int(config.get('dhcp_test_bind_port', 67))
                    dhcp.lease_sqlite_enabled = bool(config.get('lease_sqlite_enabled', True))
                    dhcp.lease_sqlite_path = config.get('lease_sqlite_path', '/var/lib/phantomd/dhcp_leases.sqlite')
                    try:
                        dhcp.rate_limit_rps = float(dhcp_cfg.get('rate_limit_rps',
                            config.get('dhcp_rate_limit_rps', 5.0)))
                    except Exception:
                        dhcp.rate_limit_rps = float(config.get('dhcp_rate_limit_rps', 5.0))
                    try:
                        dhcp.rate_limit_burst = float(dhcp_cfg.get('rate_limit_burst',
                            config.get('dhcp_rate_limit_burst', 20)))
                    except Exception:
                        dhcp.rate_limit_burst = float(config.get('dhcp_rate_limit_burst', 20))
                except Exception:
                    logging.debug('Failed to set DHCP runtime attributes from config', exc_info=True)

                start_method = getattr(dhcp, 'start', None) or getattr(dhcp, 'serve', None) or getattr(dhcp, 'run', None)
                if not callable(start_method):
                    logging.warning('DHCP server has no known start method; skipping DHCP startup')
                else:
                    bind_ip: Optional[str] = listen_ip_cfg
                    bind_port: int = int(config.get('dhcp_test_bind_port', 67))

                    def make_dhcp_starter(method: Callable[..., Any], host: str, port: int) -> Callable[[], Awaitable[None]]:
                        async def starter() -> None:
                            try:
                                import inspect
                                sig = inspect.signature(method)
                                params = list(sig.parameters.keys())
                                if len(params) >= 2:
                                    result = method(host, port)
                                elif len(params) == 1:
                                    result = method(host)
                                else:
                                    result = method()
                                if asyncio.iscoroutine(result):
                                    await result
                                elif inspect.isawaitable(result):
                                    await result
                            except TypeError:
                                try:
                                    result = method(host)
                                    if asyncio.iscoroutine(result):
                                        await result
                                    elif inspect.isawaitable(result):
                                        await result
                                except TypeError:
                                    result = method()
                                    if asyncio.iscoroutine(result):
                                        await result
                                    elif inspect.isawaitable(result):
                                        await result
                            except Exception as e:
                                logging.exception("DHCP server encountered an error during startup: %s", e)
                        return starter

                    dhcp_start_fn = make_dhcp_starter(start_method, bind_ip, bind_port)
            except Exception as e:
                logging.exception("Failed to initialize DHCP server: %s", e)

    async def _run_all() -> None:
        block_cfg: Dict[str, Any] = config.get('blocklists', {})
        if block_cfg and block_cfg.get('enabled'):
            urls: List[str] = block_cfg.get('urls', [])
            if urls:
                dest_dir: str = block_cfg.get('local_blocklist_dir', 'blocklists')
                try:
                    loop = asyncio.get_running_loop()
                    results = await asyncio.wait_for(
                        loop.run_in_executor(None, fetch_blocklists_sync, urls, dest_dir),
                        timeout=30.0
                    )
                    failed = [src for src, ok in results if not ok]
                    if failed:
                        logging.warning(f"Some blocklist sources failed to fetch: {failed}")
                except asyncio.TimeoutError:
                    logging.warning("Initial blocklist fetch timed out after 30 seconds; continuing without updated lists")
                except Exception as e:
                    logging.warning(f"Initial blocklist fetch failed: {e}")

        dns_task: asyncio.Task[Any] = asyncio.create_task(run_server(
            listen_ip_cfg,
            listen_port_cfg,
            upstream_dns,
            protocol,
            dns_resolver_server=dns_resolver_server,
            verbose=verbose,
            blocklists=block_cfg or {},
            disable_ipv6=disable_ipv6_flag,
            dns_cache_ttl=dns_cache_ttl_val,
            dns_cache_max_size=dns_cache_max_size_val,
            dns_logging_enabled=dns_logging_enabled_flag,
            dns_log_retention_days=dns_log_retention_days_val,
            dns_log_dir=dns_log_dir_str,
            dns_log_prefix=dns_log_prefix_str,
            dns_pinned_certs=dns_pinned_certs_dict,
            dnssec_enabled=dnssec_enabled_flag,
            trust_anchors_file=trust_anchors_file_str,
            metrics_enabled=metrics_enabled_flag,
            metrics_port=metrics_port_val,
            uvloop_enable=False,   # already handled above
            upstream_retries=upstream_retries_val,
            upstream_initial_backoff=upstream_initial_backoff_val,
            upstream_udp_timeout=upstream_udp_timeout_val,
            upstream_tcp_timeout=upstream_tcp_timeout_val,
            upstream_doh_timeout=upstream_doh_timeout_val,
            rate_limit_rps=rate_limit_rps_val,
            rate_limit_burst=rate_limit_burst_val,
            upstreams=upstreams_val,
            optimistic_cache_enabled=optimistic_cache_enabled_val,
            optimistic_stale_max_age=optimistic_stale_max_age_val,
            optimistic_stale_response_ttl=optimistic_stale_response_ttl_val,
            dns_privilege_drop_user=dns_privilege_drop_user_val,
            dns_privilege_drop_group=dns_privilege_drop_group_val,
            dns_chroot_dir=dns_chroot_dir_val,
            dns_rebind_protection=dns_rebind_protection_val,
            dns_rebind_action=dns_rebind_action_val,
            pool_max_size=pool_max_size_val,
            pool_idle_timeout=pool_idle_timeout_val,
        ))

        dhcp_task: Optional[asyncio.Task[Any]] = None
        if dhcp_start_fn:
            dhcp_task = asyncio.create_task(dhcp_start_fn())

        loop = asyncio.get_running_loop()

        def _reload_handler() -> None:
            logging.info("SIGHUP received – reloading configuration...")
            try:
                new_config = load_config()
                holder: ResolverHolder = run_server.holder
                resolver: DNSResolver = run_server.resolver
                blocklists_cfg: Dict[str, Any] = new_config.get('blocklists', {})
                asyncio.create_task(reload_resolver(holder, new_config, resolver, blocklists_cfg))
            except Exception as e:
                logging.error("Configuration reload failed: %s", e)

        try:
            loop.add_signal_handler(signal.SIGHUP, _reload_handler)
            logging.info("SIGHUP signal handler installed – send 'kill -HUP %d' to reload config", os.getpid())
        except (NotImplementedError, RuntimeError):
            logging.debug("Signal handlers not supported on this platform (Windows); config reload via signal is disabled")

        tasks: List[asyncio.Task[Any]] = [dns_task]
        if dhcp_task:
            tasks.append(dhcp_task)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for t, r in zip(tasks, results):
            if isinstance(r, Exception):
                logging.error("A service task exited with error: %s", r)

    asyncio.run(_run_all())


if __name__ == "__main__":
    main()