"""Public endpoint and CDN helpers.

The sing-box inbound listen address is intentionally kept separate from the
addresses published to clients.  A single inbound can therefore expose direct
IPv4, direct IPv6, and domain/CDN client variants without duplicating secrets.
Split deployments attach each variant only to its matching inbound.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any
from urllib.parse import quote


CLOUDFLARE_WS_PROTOCOLS = frozenset({"vmess", "vless", "trojan"})
PLAIN_DIRECT_SPLIT_PROTOCOLS = frozenset({"vmess", "vless"})
CLOUDFLARE_HTTP_PORTS = frozenset({80, 8080, 8880, 2052, 2082, 2086, 2095})
CLOUDFLARE_HTTPS_PORTS = frozenset({443, 2053, 2083, 2087, 2096, 8443})

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def as_bool(value: Any) -> bool:
    """Convert JSON/form boolean values without treating ``"false"`` as true."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_domain(value: str) -> str:
    """Return a lower-case ASCII hostname or raise ``ValueError``."""
    domain = str(value or "").strip().rstrip(".")
    if not domain:
        return ""
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("domain is not a valid IDN hostname") from exc
    if len(ascii_domain) > 253:
        raise ValueError("domain is too long")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("domain must be a fully-qualified hostname")
    return ascii_domain


def normalize_ip(value: str, version: int) -> str:
    """Validate and canonicalize an IPv4 or IPv6 literal."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError(f"IPv{version} address is invalid") from exc
    if address.version != version:
        raise ValueError(f"expected an IPv{version} address")
    return address.compressed


def uri_host(address: str) -> str:
    """Format an address for the authority component of a URI."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    return f"[{parsed.compressed}]" if parsed.version == 6 else parsed.compressed


def uri_fragment(value: str) -> str:
    """Percent-encode a user-facing share-link name."""
    return quote(str(value or ""), safe="")


def build_endpoint_profile(values: dict | None) -> tuple[dict, list[str]]:
    """Validate public endpoint values and return a normalized profile."""
    values = values or {}
    errors: list[str] = []

    try:
        ipv4 = normalize_ip(values.get("public_ipv4", ""), 4)
    except ValueError as exc:
        ipv4 = ""
        errors.append(f"public_ipv4: {exc}")
    try:
        ipv6 = normalize_ip(values.get("public_ipv6", ""), 6)
    except ValueError as exc:
        ipv6 = ""
        errors.append(f"public_ipv6: {exc}")
    try:
        domain = normalize_domain(values.get("public_domain", ""))
    except ValueError as exc:
        domain = ""
        errors.append(f"public_domain: {exc}")

    cloudflare_proxied = as_bool(values.get("cloudflare_proxied", False))
    if cloudflare_proxied and not domain:
        errors.append("public_domain: required for Cloudflare proxying")

    preferred = str(values.get("preferred_endpoint", "domain")).strip().lower()
    available = {
        kind for kind, address in (("ipv4", ipv4), ("ipv6", ipv6), ("domain", domain))
        if address
    }
    if preferred not in available:
        preferred = "domain" if domain else "ipv4" if ipv4 else "ipv6" if ipv6 else ""

    return {
        "public_ipv4": ipv4,
        "public_ipv6": ipv6,
        "public_domain": domain,
        "preferred_endpoint": preferred,
        "cloudflare_proxied": cloudflare_proxied,
    }, errors


def validate_cdn_options(protocol_type: str, params: dict) -> list[str]:
    """Validate the independent WebSocket/TLS Cloudflare listener."""
    errors: list[str] = []
    websocket = as_bool(params.get("ws_enabled", False))
    tls_enabled = as_bool(params.get("tls_enabled", False))
    cloudflare = as_bool(params.get("cloudflare_proxied", False))
    port_raw = params.get("cdn_listen_port", 443)
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 0

    if websocket and protocol_type not in CLOUDFLARE_WS_PROTOCOLS:
        errors.append(f"WebSocket transport is not supported by {protocol_type}")
    if websocket:
        path = str(params.get("ws_path", "/")).strip()
        if not path.startswith("/"):
            errors.append("ws_path: must start with '/'")

    if tls_enabled:
        cert_path = str(params.get("tls_certificate_path", "")).strip()
        key_path = str(params.get("tls_key_path", "")).strip()
        if not cert_path:
            errors.append("tls_certificate_path: required when TLS is enabled")
        if not key_path:
            errors.append("tls_key_path: required when TLS is enabled")

    if cloudflare:
        if protocol_type not in CLOUDFLARE_WS_PROTOCOLS:
            errors.append("Cloudflare orange-cloud mode requires VMess, VLESS, or Trojan")
        if not websocket:
            errors.append("Cloudflare orange-cloud mode requires WebSocket transport")
        if not tls_enabled:
            errors.append("Cloudflare orange-cloud mode requires TLS in SingHarbor")
        if not params.get("public_domain"):
            errors.append("public_domain: required for Cloudflare orange-cloud mode")
        if port not in CLOUDFLARE_HTTPS_PORTS:
            errors.append(
                "cdn_listen_port: use a Cloudflare HTTPS port (443, 2053, 2083, "
                "2087, 2096, or 8443)"
            )
        has_direct_address = bool(
            params.get("public_ipv4") or params.get("public_ipv6")
        )
        if has_direct_address and protocol_type not in PLAIN_DIRECT_SPLIT_PROTOCOLS:
            errors.append(
                f"{protocol_type}: a plaintext IPv4/IPv6 listener cannot be "
                "paired with the Cloudflare TLS listener"
            )

    if protocol_type == "vless" and websocket and params.get("flow"):
        errors.append("flow: VLESS WebSocket mode requires an empty flow value")

    return errors


def apply_server_connection_options(config: dict, params: dict) -> dict:
    """Apply typed WebSocket and inbound TLS options to an inbound config."""
    if as_bool(params.get("ws_enabled", False)):
        config["transport"] = {
            "type": "ws",
            "path": str(params.get("ws_path", "/")).strip() or "/",
        }
    elif isinstance(params.get("transport"), dict) and params["transport"]:
        config["transport"] = copy.deepcopy(params["transport"])

    if as_bool(params.get("tls_enabled", False)):
        server_name = str(
            params.get("tls_server_name") or params.get("public_domain") or ""
        ).strip()
        tls = {
            "enabled": True,
            "certificate_path": str(params.get("tls_certificate_path", "")).strip(),
            "key_path": str(params.get("tls_key_path", "")).strip(),
        }
        if server_name:
            tls["server_name"] = server_name
        config["tls"] = tls
    elif isinstance(params.get("tls"), dict) and params["tls"]:
        config["tls"] = copy.deepcopy(params["tls"])

    return config


def client_transport(config: dict, fallback_host: str = "") -> dict | None:
    """Translate an inbound V2Ray transport into an outbound transport."""
    transport = config.get("transport")
    if not isinstance(transport, dict) or not transport:
        return None
    result = copy.deepcopy(transport)
    if result.get("type") == "ws":
        host = config.get("tls", {}).get("server_name") or fallback_host
        if host:
            headers = dict(result.get("headers") or {})
            headers["Host"] = host
            result["headers"] = headers
    return result


def client_tls(config: dict, fallback_server_name: str = "") -> dict | None:
    """Build safe outbound TLS options without copying server key material."""
    tls = config.get("tls")
    if not isinstance(tls, dict) or not tls or tls.get("enabled") is False:
        return None
    server_name = tls.get("server_name") or fallback_server_name
    result = {"enabled": True}
    if server_name:
        result["server_name"] = server_name
    return result


def build_client_bundle(proto, inbound: dict, profile: dict | None) -> dict:
    """Generate all configured direct and domain client variants."""
    normalized, errors = build_endpoint_profile(profile)
    variants = []
    entries = (
        ("ipv4", "IPv4 direct", normalized["public_ipv4"], False),
        ("ipv6", "IPv6 direct", normalized["public_ipv6"], False),
        (
            "domain",
            "Cloudflare domain" if normalized["cloudflare_proxied"] else "Domain",
            normalized["public_domain"],
            normalized["cloudflare_proxied"],
        ),
    )
    for kind, label, address, proxied in entries:
        if not address:
            continue
        info = proto.generate_client_info(inbound, address)
        variants.append({
            "kind": kind,
            "label": label,
            "address": address,
            "cloudflare_proxied": proxied,
            **info,
        })

    preferred = normalized.get("preferred_endpoint", "")
    primary = next((item for item in variants if item["kind"] == preferred), None)
    if primary is None and variants:
        primary = variants[0]

    result = {
        "preferred": primary["kind"] if primary else "",
        "variants": variants,
        "validation_errors": errors,
    }
    if primary:
        for key in ("share_link", "config_snippet", "credentials", "notes"):
            result[key] = primary.get(key, [] if key == "notes" else {})
    else:
        result.update({
            "share_link": "",
            "config_snippet": {},
            "credentials": {},
            "notes": ["Configure a public IPv4, IPv6, or domain endpoint."],
        })
    return result
