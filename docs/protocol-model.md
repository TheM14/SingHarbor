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
- **Share**: No standard format
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

The certificate belongs only to the CDN inbound. A Cloudflare Origin CA
certificate is appropriate when the hostname always remains behind the orange
cloud. Use a publicly trusted certificate if clients may connect to that TLS
origin directly. The plaintext IP inbound does not use either certificate.

## One-click Protocol Matrix

One-click deployment builds a capability-based plan from three optional input
blocks. IP addresses enable native Shadowsocks/VMess/VLESS. A domain plus a
validated certificate directory enables VMess/VLESS/Trojan Cloudflare
WebSocket routes. Combining all inputs also enables direct TLS routes for
Trojan, Hysteria2, TUIC, Hysteria v1, and AnyTLS. The complete plan contains 11
inbounds for 8 protocols, with unique automatically allocated ports.
Port 443 is reserved for an Nginx-hosted WebUI; quick-deploy CDN listeners use
2053, 2083, 2087, 2096, and 8443. The manual wizard still permits port 443.

ShadowTLS remains manual because it needs an explicit handshake server. Naive
remains manual because its safe deployment needs a dedicated directly
reachable TLS hostname/routing decision. Empty input blocks are treated as
intentional omissions; malformed non-empty values are validation errors.
