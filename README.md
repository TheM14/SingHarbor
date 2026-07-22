**English** | [中文](./README-ZH.md)

# SingHarbor

A cross-platform sing-box management WebUI for personal use.

**Target sing-box**: v1.13.14 &nbsp;|&nbsp; **Version**: v1.1.0

SingHarbor manages a sing-box binary and its JSON configuration. It does not
install a system service or modify the firewall. Cloudflare A/AAAA records are
changed only through the explicit preview-and-synchronize workflow.

## Requirements

- Python 3.12 or newer
- `pip`
- A sing-box v1.13-compatible binary for configuration validation and runtime

## Get the source

Download or clone the repository, then enter its directory before running any
of the installation examples below:

```bash
git clone https://github.com/TheM14/SingHarbor.git
cd SingHarbor
```

## Conda deployment

Create a dedicated Python 3.12 environment, install the project dependencies,
and start SingHarbor:

```bash
conda create -n singharbor python=3.12 pip -y
conda activate singharbor
python -m pip install -r requirements.txt
python run.py
```

The included `environment.yml` provides the same dependency set:

```bash
conda env create -f environment.yml
conda activate singharbor
python run.py
```

## Standard venv deployment

### Linux / macOS

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

After startup, open `http://127.0.0.1:51080`. The first visit creates the
single administrator account. Configure or download a sing-box kernel from the
Kernel page before deploying protocols.

To listen on a different local port:

```bash
python run.py --host 127.0.0.1 --port 51081
```

Binding to a public interface is not recommended without an HTTPS reverse
proxy and appropriate network access controls.

## Main features

- Manage sing-box kernels, configuration validation, backups and process state.
- Deploy protocols through a typed wizard or the atomic one-click planner.
- Publish independent IPv4, IPv6 and domain client variants.
- Use Cloudflare WebSocket + TLS routes and optional preferred Cloudflare IPs.
- Issue a publicly trusted Let's Encrypt certificate through Cloudflare DNS-01
  and atomically attach it to new or existing direct-TLS inbounds.
- Deploy direct VLESS Reality and generate compatible VLESS share links.
- Generate QR codes, copy all client variants, and download full JSON/text exports.
- Edit an existing inbound in place while preserving unknown sing-box fields.
- Preview and explicitly synchronize Cloudflare A/AAAA records.

## Supported protocols

| Protocol | Type | TLS | Share link |
|---|---|---|---|
| Shadowsocks | `shadowsocks` | No | `ss://` |
| VMess | `vmess` | Optional | `vmess://` |
| Trojan | `trojan` | Required | `trojan://` |
| VLESS / Reality | `vless` | Optional / Reality | `vless://` |
| Hysteria2 | `hysteria2` | Required | `hysteria2://` |
| TUIC | `tuic` | Required | `tuic://` |
| ShadowTLS | `shadowtls` | No | Client JSON |
| Naive | `naive` | Optional | `naive+https://` |
| Hysteria | `hysteria` | Required | `hysteria://` |
| AnyTLS | `anytls` | Required | `anytls://` |

Reality is always a direct endpoint and is never mixed with a Cloudflare
orange-cloud route. Generate its key pair with
`sing-box generate reality-keypair`, then enter the server private key, client
public key, handshake destination/SNI, short ID and client fingerprint in the
VLESS wizard.

## Public endpoints and Cloudflare

- Client addresses are metadata and do not replace the sing-box listen address.
- VMess, VLESS and Trojan can use WebSocket + TLS through Cloudflare.
- A preferred Cloudflare IPv4 or IPv6 changes only the client connection
  address; TLS SNI and WebSocket Host continue to use the domain.
- Hysteria, Hysteria2 and TUIC use UDP/QUIC and cannot use the standard
  Cloudflare orange-cloud WebSocket proxy.
- API tokens are one-shot or read from `CLOUDFLARE_API_TOKEN`; they are never saved.
- Cloudflare Origin CA certificates are suitable for CDN origin traffic only.
  Direct TLS uses the optional Let's Encrypt certificate or another publicly
  trusted full chain.

## One-click deployment

The One-click Deploy page accepts three independent input groups:

1. A domain, plus an optional preferred Cloudflare IPv4 or IPv6.
2. An optional CDN certificate directory, plus optional automatic Let's Encrypt
   issuance for TLS Direct using a one-shot Cloudflare DNS API token and email.
3. Optional direct public IPv4 and IPv6 addresses.

Empty groups skip only the routes that depend on them. Invalid non-empty values
stop deployment. Ports and credentials are allocated automatically, all
inbounds are validated and saved in one update, and sing-box is restarted once.
One-click deployment never changes A/AAAA records. Let's Encrypt DNS-01
temporarily creates and removes `_acme-challenge` TXT records through Certbot.
Because SingHarbor does not retain the Cloudflare token, run the action again
before certificate expiry. `CLOUDFLARE_API_TOKEN` avoids re-entering the token
but does not create a background renewal schedule.
After a successful issuance, the result page shows the issuer, expiry,
SHA-256 fingerprint, certificate path, and the TLS Direct inbounds that were
actually updated. The same token-free evidence is stored in
`data/letsencrypt/last-issuance.json`.

## Data locations

| Data | Location |
|---|---|
| Database, settings, backups and logs | `<project>/data/` |
| sing-box configuration | `<project>/data/sing-box-config.json` |
| Certbot account and issued certificate material | `<project>/data/letsencrypt/` |
| Downloaded kernels | `<project>/kernels/` |

## Tests

```bash
pytest tests/ -v
```

## Uninstall

Stop SingHarbor and remove its project directory. If you created a dedicated
Conda environment, remove it separately:

```bash
conda env remove -n singharbor
```

## License

Personal use. Not affiliated with the sing-box project
([GPLv3](https://github.com/SagerNet/sing-box)).
