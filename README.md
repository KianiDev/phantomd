phantomd
========

A small, configurable local DNS server and forwarder with optional blocklist enforcement.

Features
- Listens on UDP/TCP (port configurable).
- Forwards upstream using UDP/TCP/TLS/HTTPS/QUIC (configurable).
- Optional blocklist fetching and enforcement (hosts-format supported).
- Configurable blocking actions: ZEROIP, NXDOMAIN, REFUSED.
- Optional ability to disable IPv6 lookups for better IPv4-only blocklists.

Quick install (recommended)
1. Run the bundled installer (headless interactive):
   sudo sh install_phantomd.sh

Prerequisites
- Linux systemd-based distribution
- curl, tar, python3 (>=3.8), python3-venv

Installer
- The installer automates fetching the repository tarball, creating a virtualenv, installing Python dependencies, creating a systemd service, and generating a configuration file.
- The installer is headless (CLI prompts only) and guides you through config options.

Configuration
The main configuration file is config/phantomd.conf. Important options:
- [upstream]
  - dns_server: Upstream DNS server (IP or host). Examples: 1.1.1.1, 9.9.9.9:853, https://dns.example/dns-query
  - dns_protocol: upstream protocol to use (udp, tcp, tls, https, quic)
  - disable_ipv6: true/false. When true the resolver will avoid IPv6 resolution and connections.

- [interface]
  - listen_ip: IP address to bind locally (default 0.0.0.0)
  - listen_port: port to bind locally (default 53)

- [logging]
  - verbose: true/false (enable debug logging)
  - dns_resolver_server: optional local resolver (ip:port) used to resolve upstream hostnames for DoH/DoT/DoQ

- [blocklists]
  - enabled: true/false
  - urls: comma-separated remote URLs or local file paths to fetch into ./blocklists
  - interval_seconds: how often to refresh the lists
  - action: ZEROIP | NXDOMAIN | REFUSED

Service
- Systemd service installed as /etc/systemd/system/phantomd.service (user provided during install).
- Control with:
  - sudo systemctl (Operation) phantomd
- Check program logs:
  - sudo journalctl -u phantomd -f

Security note
- When using DoH/DoT/DoQ ensure you trust the upstream. QUIC/HTTP/3 support depends on installed libraries and upstream compatibility.

Development
- If modifying code you can run it directly with the virtualenv Python created by the installer.

License
- Check repository LICENSE before redistribution.

Contact
- Repository: https://github.com/KianiDev/phantomd
- Email: mohammadamin.k1390@gmail.com
- Discord: kianivanced
