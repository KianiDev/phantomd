from utils.config import load_config
import argparse
import logging
from core.resolver import run_resolver

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

    run_resolver(
        config["listen_ip"],
        config["listen_port"],
        config["upstream_dns"],
        config["protocol"],
        dns_resolver_server=config.get("dns_resolver_server"),
        verbose=verbose
    )

if __name__ == "__main__":
    main()