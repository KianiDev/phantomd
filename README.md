# phantomd 🕶️
A lightweight, modular DNS proxy with filtering and secure upstream support.

## ✨ Features
- Supports multiple DNS protocols:
  - UDP
  - TCP
  - DNS-over-HTTPS (DoH)
  - DNS-over-TLS (DoT)
  - DNS-over-QUIC (DoQ, currently experimental)
- Configurable via plain `.conf` files (no heavy configs).
- Filtering system:
  - Blocklists
- Minimal dependencies — runs on low-resource servers  *(tested on an Intel Core Duo with 3 GB RAM)*


## 🔒 Security Notes
- By default, phantomd only forwards DNS traffic.
- You can integrate it with `hostapd` by enabling the DHCP server in the config,  allowing Phantomd to act as a network-level DNS filter. (recommended)


## 🛠️ Development
- Python 3.10+ recommended.
- Built with `asyncio` for concurrency.

## 🗺️ Roadmap
- [ ] Full DoQ support
- [ ] Config reloading without restart
- [ ] Optional web dashboard
- [ ] Preventing DNS leaking at network level

## 🤝 Contributing
Pull requests are welcome! For major changes, open an issue first to discuss what you would like to change.

## 📜 License
MIT License — free to use, modify, and share.