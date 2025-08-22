from utils.config import load_config
import argparse
import logging
import asyncio
from core.dserver import run_server
from core.DHCP import DHCPServer
from utils.ListUpdater import fetch_blocklists_sync

def main():
    parser = argparse.ArgumentParser(description="phantomd DNS server")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    config = load_config()
    verbose = args.verbose or config.get("verbose", False)

    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format='[%(levelname)s] %(message)s')
    logging.info("Configuration loaded successfully:")
    for key, value in config.items():
        logging.info(f"{key}: {value}")

    # Blocklist settings
    block_cfg = config.get('blocklists', {})
    if block_cfg and block_cfg.get('enabled'):
        urls = block_cfg.get('urls', [])
        # perform initial synchronous fetch (wait), warn on failure
        try:
            results = fetch_blocklists_sync(urls)
            failed = [src for src, ok in results if not ok]
            if failed:
                logging.warning(f"Some blocklist sources failed to fetch: {failed}")
        except Exception as e:
            logging.warning(f"Initial blocklist fetch failed: {e}")

    # Prepare coroutines
    dns_coro = run_server(
        config["listen_ip"],
        config["listen_port"],
        config["upstream_dns"],
        config["protocol"],
        dns_resolver_server=config.get("dns_resolver_server"),
        verbose=verbose,
        blocklists=block_cfg,
        disable_ipv6=config.get("disable_ipv6", False),
        dns_cache_ttl=config.get("dns_cache_ttl", 300),
        dns_cache_max_size=config.get("dns_cache_max_size", 1024),
        dns_logging_enabled=config.get("dns_logging_enabled", False),
        dns_log_retention_days=config.get("dns_log_retention_days", 7),
        dns_log_dir=config.get("dns_log_dir", "/var/log/phantomd"),
        dns_log_prefix=config.get("dns_log_prefix", "dns-log")
    )

    dhcp_cfg = config.get('dhcp', {})
    dhcp_coro = None
    if dhcp_cfg.get('enabled'):
        dhcp = DHCPServer(
            subnet=dhcp_cfg.get('subnet'),
            netmask=dhcp_cfg.get('netmask'),
            start_ip=dhcp_cfg.get('start_ip'),
            end_ip=dhcp_cfg.get('end_ip'),
            lease_ttl=dhcp_cfg.get('lease_ttl'),
            static_leases=dhcp_cfg.get('static_leases') or {},
            server_ip=None,
            lease_db_path=dhcp_cfg.get('lease_db_path')
        )
        dhcp_coro = dhcp.start()

    async def _run_all():
        if dhcp_coro:
            await asyncio.gather(dns_coro, dhcp_coro)
        else:
            await dns_coro

    asyncio.run(_run_all())


if __name__ == "__main__":
    main()