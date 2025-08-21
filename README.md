# phantomd 🕶️
A lightweight, modular DNS proxy with filtering and secure upstream support.

## ✨ Features
- Supports multiple DNS protocols:
  - UDP
  - TCP
  - DNS-over-HTTPS (DoH)
  - DNS-over-TLS (DoT)
  - DNS-over-QUIC (DoQ, currently in beta)
- Configurable via plain `.conf` files (no heavy configs).
- Filtering system:
  - Blocklists
- Minimal dependencies — runs on low-resource servers (This project gets tested on a Intel Core Duo series with 3GBs of ram). 

## 🔒 Security Notes
- By default, phantomd only forwards DNS traffic.
- You can use integrate it with hostapd by enabling DHCP server inside the config file.

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