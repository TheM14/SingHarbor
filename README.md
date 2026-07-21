**English** | [中文](./README-ZH.md)

# SingHarbor

A cross-platform sing-box management WebUI for personal use.

**Target sing-box**: v1.13.14 &nbsp;|&nbsp; **Version**: v1.0.0

SingHarbor does **not** install system services or modify firewalls. It manages a
sing-box binary and its JSON configuration, and can optionally synchronize
explicit Cloudflare A/AAAA DNS records.

## Requirements

- Python 3.11 or newer
- `pip`

Using a virtual environment is recommended, but SingHarbor does not require
Conda or any particular environment manager.

## Quick Start

```bash
# Install dependencies into your active Python environment and start
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:51080` and follow the setup wizard.

For example, you can optionally create an isolated environment first:

```bash
# Standard Python venv (Linux/macOS)
python -m venv .venv
source .venv/bin/activate

# Or Conda
conda create -n singharbor python=3.11 -y
conda activate singharbor
```

## Supported Protocols

| Protocol | Type | TLS | Share Link |
|---|---|---|---|
| Shadowsocks | `shadowsocks` | No | ss:// |
| VMess | `vmess` | Optional | vmess:// |
| Trojan | `trojan` | Required | trojan:// |
| VLESS | `vless` | Optional | vless:// |
| Hysteria2 | `hysteria2` | Required | hysteria2:// |
| TUIC | `tuic` | Required | tuic:// |
| ShadowTLS | `shadowtls` | No | — |
| Naive | `naive` | Optional | naive+https:// |
| Hysteria | `hysteria` | Required | hysteria:// |
| AnyTLS | `anytls` | Required | — |

## Public endpoints and Cloudflare

- Generate separate client configurations for direct IPv4, direct IPv6, and a domain.
- VMess, VLESS, and Trojan can use WebSocket + TLS through Cloudflare's standard proxy.
- Hysteria, Hysteria2, and TUIC use UDP/QUIC and cannot use standard orange-cloud WebSocket proxying.
- Cloudflare API tokens are one-shot or read from `CLOUDFLARE_API_TOKEN`; they are never saved.
- DNS changes are previewed and require explicit confirmation.

## One-click deployment

The One-click Deploy page accepts a domain, a server-side certificate
directory, and optional IPv4/IPv6 addresses. It automatically allocates ports
and credentials, deploys every compatible protocol in one validated config
update, restarts sing-box once, and returns all available links/client JSON.
Empty input sections skip only their dependent routes. Cloudflare DNS is not
changed by this action and must already point the hostname to the server.

## Where Data Lives

Everything is inside the project directory. Delete the project folder and everything is gone.

| Data | Location |
|---|---|
| DB, settings, backups, logs | `<project>/data/` |
| sing-box config JSON | `<project>/data/singbox-config.json` |
| Downloaded kernels | `<project>/kernels/` |

## Uninstall

```bash
rm -rf path/to/SingHarbor
```

If you installed dependencies into a dedicated virtual environment outside the
project directory, remove that environment separately. SingHarbor itself does
not install a system service or modify the firewall.

## License

Personal use. Not affiliated with the sing-box project ([GPLv3](https://github.com/SagerNet/sing-box)).
