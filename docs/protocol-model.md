# SingHarbor Protocol Model

## Design

Protocols are not hardcoded in pages. They are defined via a protocol definition layer.

### ProtocolDefinition Base Class

```python
class ProtocolDefinition:
    name: str              # Display name
    inbound_type: str      # sing-box inbound type
    min_version: str       # Minimum sing-box version
    max_version: str|None  # Maximum version (None = no upper bound)
    fields: list[ProtocolField]  # Parameter definitions
    supports_tls: bool
    supports_transport: bool
    supports_multiplex: bool
    share_link_prefix: str  # URL scheme prefix

    def validate_params(params) -> list[str]  # Validation errors
    def generate_config(params) -> dict       # Inbound config
    def generate_client_info(config, addr) -> dict  # One client endpoint
```

### ProtocolField

```python
class ProtocolField:
    name: str
    field_type: str  # string, int, bool, list, dict, uuid, password
    required: bool
    default: Any
    description: str
    min_value: int|None
    max_value: int|None
    choices: list|None
```

## Current Protocol Definitions

### Shadowsocks

- **Methods**: 2022-blake3 (128/256-bit), AES-GCM, ChaCha20
- **Share**: ss://{base64(method:password)}@{server}:{port}
- **Key generation**: sing-box generate rand --base64 N

### VMess

- **Users**: UUID-based authentication
- **Share**: vmess://{base64(json)}
- **TLS/Transport**: Supported

### Trojan

- **Users**: Password-based authentication
- **Share**: trojan://{password}@{server}:{port}?...
- **TLS**: Required in practice
- **Transport**: Supported (ws, grpc, etc.)

### VLESS

- **Users**: UUID-based, optional flow control
- **Share**: vless://{uuid}@{server}:{port}?...
- **Flow**: xtls-rprx-vision
- **TLS/Transport**: Supported
- **Reality**: Direct TCP only; server private key remains in sing-box JSON,
  while the public key and client fingerprint remain in endpoint metadata

### Hysteria2
- **Auth**: Password-based
- **Share**: hysteria2://{password}@{server}:{port}?sni=...
- **Obfs**: salamander, gecko
- **Bandwidth**: up_mbps / down_mbps configurable

### TUIC
- **Auth**: UUID + password
- **Share**: tuic://{uuid}:{password}@{server}:{port}?...
- **CC**: cubic, new_reno, bbr
- **TLS/Transport**: Required TLS

### ShadowTLS
- **Versions**: 1, 2, 3
- **Auth**: Password (V1/V2), User list (V3)
- **Share**: No standard format
- **Handshake**: Forwards to fallback on non-ShadowTLS traffic

### Naive
- **Auth**: Username + password (HTTP Basic Auth)
- **Share**: naive+https://{username}:{password}@{server}:{port}
- **Network**: TCP/UDP via Chromium network stack

### Hysteria (v1)
- **Auth**: Password (auth_str)
- **Share**: hysteria://{password}@{server}:{port}?protocol=udp&...
- **Note**: Deprecated in favor of Hysteria2, still supported

### AnyTLS
- **Auth**: Password-based
- **Share**: anytls://{password}@{server}:{port}/?sni=...
- **Min version**: sing-box 1.12.0
- **Padding**: Configurable TLS padding scheme

## Extending

1. Create a new class inheriting ProtocolDefinition
2. Define fields and methods
3. Use @register decorator
4. Import in protocols/__init__.py

## Limitations

- Multi-user configurations partially supported
- Some transport combinations may not be validatable without real kernel
- Complex TLS certificate configurations require manual JSON editing

## Public Client Endpoints

SingHarbor keeps public client addresses separate from the inbound listen
address. IPv6 literals are bracketed only in URI authority components and
remain unbracketed in sing-box `server` fields.

VMess, VLESS, and Trojan support the WebSocket + TLS deployment UI and can use
Cloudflare's standard HTTP proxy on supported HTTPS ports. UDP/QUIC protocols
such as Hysteria2 and TUIC require DNS-only records or a compatible Layer 4
service such as Cloudflare Spectrum.

When orange-cloud mode is combined with public IPv4/IPv6 addresses, VMess and
VLESS use a split deployment with shared user credentials:

- `<tag>-direct` listens on the direct port and publishes only IPv4/IPv6
  clients. It uses native TCP without TLS or WebSocket.
- `<tag>-cdn` listens on a separate Cloudflare HTTPS port and publishes only
  the domain client. It uses WebSocket + TLS with the configured SNI and
  certificate paths.

Both inbounds are validated and written in one configuration update, followed
by a single process restart. Trojan is not offered in plaintext split mode
because its direct listener requires TLS.

The certificate-directory certificate belongs to the CDN inbound. A
Cloudflare Origin CA certificate is appropriate when the hostname always
remains behind the orange cloud. Direct TLS inbounds use a separate publicly
trusted Let's Encrypt certificate issued through Cloudflare DNS-01, or another
publicly trusted full chain. Enabling issuance atomically replaces the
certificate paths on matching existing direct TLS inbounds. Plaintext IP
inbounds do not use either certificate.

## One-click Protocol Matrix

One-click deployment builds a capability-based plan from three input blocks.
IP addresses enable native Shadowsocks/VMess/VLESS. A domain plus either a
validated certificate directory or an issued Let's Encrypt certificate enables
VMess/VLESS/Trojan Cloudflare WebSocket routes. A public certificate and IP
addresses enable direct TLS routes for Trojan, Hysteria2, TUIC, Hysteria v1,
and AnyTLS. The complete plan contains 11 inbounds for 8 protocols, with unique
automatically allocated ports.

Let's Encrypt issuance uses Certbot's Cloudflare DNS plugin. The API token is
passed through a mode-0600 temporary credentials file which is overwritten and
removed after Certbot exits. It is not stored in settings, the database, API
responses, or the sing-box configuration. The administrator re-runs issuance
before expiry; `CLOUDFLARE_API_TOKEN` avoids re-entering the token but does not
create a background renewal schedule.
Port 443 is reserved for an Nginx-hosted WebUI; quick-deploy CDN listeners use
2053, 2083, 2087, 2096, and 8443. The manual wizard still permits port 443.

ShadowTLS remains manual because it needs an explicit handshake server. Naive
remains manual because its safe deployment needs a dedicated directly
reachable TLS hostname/routing decision. Empty input blocks are treated as
intentional omissions; malformed non-empty values are validation errors.
