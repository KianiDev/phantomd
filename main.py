from utils.config import load_config
import argparse
import logging
from core.dserver import run_server_sync
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

    run_server_sync(
        config["listen_ip"],
        config["listen_port"],
        config["upstream_dns"],
        config["protocol"],
        dns_resolver_server=config.get("dns_resolver_server"),
        verbose=verbose,
        blocklists=block_cfg,
        disable_ipv6=config.get("disable_ipv6", False)
    )

if __name__ == "__main__":
    main()