"""Inbound analyzer - identifies and extracts info from existing sing-box inbounds.

Parses the current sing-box configuration and identifies server-side inbound
protocols. For recognized protocols, extracts:
- Protocol type, tag, listen address/port
- Status (running/enabled)
- TLS and transport summary
- User/credential count
- Client connection info (share links, etc.)

Unknown configurations are preserved as-is.
"""

import logging
from pathlib import Path
from .protocols import get_by_type, get_server_protocols
from .utils import mask_dict_sensitive

logger = logging.getLogger(__name__)

SERVER_INBOUND_TYPES = {
    "shadowsocks", "vmess", "trojan", "vless",
    "hysteria2", "tuic", "shadowtls", "anytls",
    "naive", "hysteria", "snell",
}


def analyze_inbounds(config: dict, running: bool = False,
                     server_address: str = "",
                     endpoint_profile: dict | None = None,
                     endpoint_profiles: dict | None = None) -> list[dict]:
    """Analyze all inbounds in a configuration and extract metadata.

    Args:
        config: The full sing-box configuration dict.
        running: Whether sing-box is currently running.
        server_address: Server address for generating client info.

    Returns:
        List of analyzed inbound info dicts.
    """
    inbounds = config.get("inbounds", [])
    if not inbounds:
        return []

    results = []
    for inbound in inbounds:
        tag = inbound.get("tag", "")
        selected_profile = (endpoint_profiles or {}).get(tag, endpoint_profile)
        info = analyze_single_inbound(
            inbound, running, server_address, selected_profile
        )
        if info:
            results.append(info)

    return results


def analyze_single_inbound(inbound: dict, running: bool = False,
                           server_address: str = "",
                           endpoint_profile: dict | None = None) -> dict | None:
    """Analyze a single inbound configuration entry.

    Returns None if it's a non-server inbound type (tun, redirect, etc.).
    """
    inbound_type = inbound.get("type", "")

    if inbound_type in ("tun", "redirect", "tproxy", "cloudflared", "direct"):
        return None

    tag = inbound.get("tag", f"{inbound_type}-unknown")
    listen = inbound.get("listen", "0.0.0.0")
    port = inbound.get("listen_port", 0)

    tls_info = _extract_tls_info(inbound)
    transport_info = _extract_transport_info(inbound)
    user_count = _count_users(inbound)
    credential_count = user_count

    is_server_protocol = inbound_type in SERVER_INBOUND_TYPES
    recognized = is_server_protocol and inbound_type in get_server_protocols()

    result = {
        "tag": tag,
        "type": inbound_type,
        "listen": listen,
        "listen_port": port,
        "running": running,
        "tls": tls_info,
        "transport": transport_info,
        "user_count": user_count,
        "credential_count": credential_count,
        "recognized": recognized,
        "config": inbound if not recognized else None,
    }

    if recognized:
        proto = get_by_type(inbound_type)
        if proto:
            try:
                from .endpoints import build_client_bundle
                profile = endpoint_profile or {}
                if server_address and not any(profile.values()):
                    key = "public_ipv6" if ":" in server_address else "public_ipv4"
                    profile = {key: server_address}
                client_info = build_client_bundle(proto, inbound, profile)
                result["share_link"] = client_info.get("share_link", "")
                result["credentials"] = client_info.get("credentials", {})
                result["client_options"] = client_info.get("variants", [])
            except Exception:
                logger.warning("Failed to generate client info for %s", tag)
                result["share_link"] = ""
                result["credentials"] = {}
                result["client_options"] = []
        else:
            result["share_link"] = ""
            result["credentials"] = {}
            result["client_options"] = []

    if not recognized:
        result["share_link"] = ""
        result["credentials"] = {}
        result["client_options"] = []
        result["config"] = mask_dict_sensitive(inbound)  # mask sensitive fields

    return result


def _extract_tls_info(inbound: dict) -> dict:
    """Extract TLS configuration summary."""
    tls = inbound.get("tls", {})
    if not tls or not isinstance(tls, dict):
        return {"enabled": False}

    return {
        "enabled": tls.get("enabled", True) if "enabled" in tls else bool(tls),
        "server_name": tls.get("server_name", tls.get("server", "")),
        "certificate": bool(tls.get("certificate") or tls.get("certificate_path")),
        "alpn": tls.get("alpn", []),
    }


def _extract_transport_info(inbound: dict) -> dict:
    """Extract transport configuration summary."""
    transport = inbound.get("transport", {})
    if not transport or not isinstance(transport, dict):
        return {"type": "tcp"}

    return {
        "type": transport.get("type", "tcp"),
        "has_ws": transport.get("type") == "ws",
        "has_grpc": transport.get("type") == "grpc",
        "has_httpupgrade": transport.get("type") == "httpupgrade",
    }


def _count_users(inbound: dict) -> int:
    """Count the number of users/credentials in an inbound."""
    users = inbound.get("users", [])
    if users:
        return len(users)
    if inbound.get("password"):
        return 1
    if inbound.get("destinations"):
        return len(inbound["destinations"])
    return 0


def mask_sensitive_inbound_info(inbound_info: dict) -> dict:
    """Mask sensitive fields in inbound analysis result."""
    result = dict(inbound_info)
    if "credentials" in result and result["credentials"]:
        result["credentials"] = mask_dict_sensitive(result["credentials"])
    return result
