# SingHarbor Requirements

## sing-box Version Target

- **Stable version**: v1.13.14
- **Latest alpha**: v1.14.0-alpha.48
- **Repository**: https://github.com/SagerNet/sing-box
- **Documentation**: https://sing-box.sagernet.org/

## Supported Protocols (Phase 1)

| Protocol | Inbound Type | TLS Required | Share Format | Status |
|---|---|---|---|---|
| Shadowsocks | shadowsocks | No | ss:// | Implemented |
| VMess | vmess | Optional | vmess:// | Implemented |
| Trojan | trojan | Yes | trojan:// | Implemented |
| VLESS | vless | Optional | vless:// | Implemented |
| Hysteria2 | hysteria2 | Yes | hysteria2:// | Implemented |
| TUIC | tuic | Yes | tuic:// | Implemented |
| ShadowTLS | shadowtls | No | - | Implemented |
| Naive | naive | Optional | naive+https:// | Implemented |
| Hysteria | hysteria | Yes | hysteria:// | Implemented |
| AnyTLS | anytls | Yes | - | Implemented |

## Planned Protocols (Phase 2+)

| Protocol | Inbound Type | Share Format | Status |
|---|---|---|---|
| Snell | snell | - | Planned |

## sing-box CLI Commands Used

- `sing-box version` - Version query
- `sing-box check -c config.json` - Configuration validation
- `sing-box format -w -c config.json` - Configuration formatting
- `sing-box run -c config.json` - Run service
- `sing-box generate rand --base64 <length>` - Random key generation
- `sing-box generate uuid` - UUID generation

## Release Asset Naming Convention

```
sing-box-{version}-{os}-{arch}.{ext}
```

- **OS**: windows, linux, darwin
- **Arch**: amd64, arm64, 386, armv5, armv6, armv7
- **Ext**: zip (Windows), tar.gz (Linux/macOS)
