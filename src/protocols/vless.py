"""VLESS protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/vless/

Share link format: vless://{uuid}@{server}:{port}?...
"""

import ipaddress
import re
import uuid
from urllib.parse import quote, urlencode
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import (
    apply_server_connection_options,
    as_bool,
    client_tls,
    client_transport,
    uri_fragment,
    uri_host,
)


@register
class VLESSDefinition(ProtocolDefinition):
    name = "VLESS"
    inbound_type = "vless"
    description = "VLESS proxy protocol"
    min_version = "1.0.0"
    supports_tls = True
    supports_transport = True
    supports_multiplex = True
    share_link_prefix = "vless://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("uuid", "uuid", required=True,
                      description="VLESS user UUID"),
        ProtocolField("flow", "string", default="",
                      description="Flow control"),
        ProtocolField("user_name", "string", default="user",
                      description="User name"),
        ProtocolField("reality_enabled", "bool", default=False,
                      description="Enable direct VLESS Reality"),
        ProtocolField("reality_handshake_server", "string", default="",
                      description="Reality handshake destination hostname or IP"),
        ProtocolField("reality_handshake_server_port", "int", default=443,
                      min_value=1, max_value=65535,
                      description="Reality handshake destination port"),
        ProtocolField("reality_server_name", "string", default="",
                      description="Reality client SNI"),
        ProtocolField("reality_private_key", "secret", default="",
                      description="Server X25519 private key"),
        ProtocolField("reality_public_key", "string", default="",
                      description="Matching client X25519 public key"),
        ProtocolField("reality_short_id", "string", default="",
                      description="Even-length hexadecimal Reality short ID"),
        ProtocolField(
            "reality_fingerprint", "string", default="chrome",
            choices=["chrome", "firefox", "edge", "safari", "ios", "android", "random"],
            description="Client TLS fingerprint",
        ),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        flow = params.get("flow", "")
        if flow and flow not in ("xtls-rprx-vision", ""):
            errors.append("flow: must be empty or 'xtls-rprx-vision'")
        if as_bool(params.get("reality_enabled", False)):
            required = (
                "reality_handshake_server", "reality_server_name",
                "reality_private_key", "reality_public_key", "reality_short_id",
            )
            for name in required:
                if not str(params.get(name, "") or "").strip():
                    errors.append(f"{name}: required when Reality is enabled")

            handshake = str(params.get("reality_handshake_server", "") or "").strip()
            if handshake:
                try:
                    ipaddress.ip_address(handshake)
                except ValueError:
                    if not re.fullmatch(
                        r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                        r"[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                        r"[A-Za-z0-9])?",
                        handshake,
                    ):
                        errors.append(
                            "reality_handshake_server: must be a hostname or IP address"
                        )

            for name in ("reality_private_key", "reality_public_key"):
                value = str(params.get(name, "") or "").strip()
                if value and not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
                    errors.append(f"{name}: must be an X25519 key")
            short_id = str(params.get("reality_short_id", "") or "").strip()
            if short_id and (
                len(short_id) > 16 or len(short_id) % 2 or
                not re.fullmatch(r"[0-9a-fA-F]+", short_id)
            ):
                errors.append(
                    "reality_short_id: must be an even-length hex string up to 16 digits"
                )
            if as_bool(params.get("cloudflare_proxied", False)):
                errors.append("Reality is a direct endpoint and cannot use Cloudflare CDN")
            if as_bool(params.get("ws_enabled", False)):
                errors.append("Reality uses native TCP and cannot use WebSocket")
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "vless",
            "tag": params.get("tag", "vless-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "uuid": params.get("uuid", str(uuid.uuid4())),
                }
            ],
        }

        if params.get("flow"):
            config["users"][0]["flow"] = params["flow"]

        if as_bool(params.get("reality_enabled", False)):
            config["tls"] = {
                "enabled": True,
                "server_name": str(params.get("reality_server_name", "")).strip(),
                "reality": {
                    "enabled": True,
                    "handshake": {
                        "server": str(
                            params.get("reality_handshake_server", "")
                        ).strip(),
                        "server_port": int(
                            params.get("reality_handshake_server_port", 443)
                        ),
                    },
                    "private_key": str(
                        params.get("reality_private_key", "")
                    ).strip(),
                    "short_id": [str(
                        params.get("reality_short_id", "")
                    ).strip().lower()],
                },
            }
        else:
            apply_server_connection_options(config, params)
        if params.get("multiplex"):
            config["multiplex"] = params["multiplex"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        vless_uuid = user.get("uuid", "")
        port = config.get("listen_port", 0)
        flow = user.get("flow", "")

        query = {"type": "tcp", "encryption": "none", "security": "none"}
        tls = client_tls(config, server_address)
        transport = client_transport(config, server_address)
        server_reality = config.get("tls", {}).get("reality", {})
        reality_enabled = bool(
            isinstance(server_reality, dict)
            and server_reality
            and server_reality.get("enabled") is not False
        )
        if transport:
            query["type"] = transport.get("type", "tcp")
            if transport.get("type") == "ws":
                query["path"] = transport.get("path", "/")
                if transport.get("headers", {}).get("Host"):
                    query["host"] = transport["headers"]["Host"]
        if tls:
            query["security"] = "reality" if reality_enabled else "tls"
            if tls.get("server_name"):
                query["sni"] = tls["server_name"]
            if reality_enabled:
                reality = tls.get("reality", {})
                public_key = reality.get("public_key", "")
                short_id = reality.get("short_id", "")
                fingerprint = tls.get("utls", {}).get("fingerprint", "chrome")
                if public_key:
                    query["pbk"] = public_key
                if short_id:
                    query["sid"] = short_id
                if fingerprint:
                    query["fp"] = fingerprint
        if flow:
            query["flow"] = flow

        share_link = ""
        if not reality_enabled or query.get("pbk"):
            share_link = (
                f"vless://{quote(vless_uuid, safe='')}@"
                f"{uri_host(server_address)}:{port}?{urlencode(query)}"
            )
            if config.get("tag"):
                share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "vless",
            "tag": f"{config.get('tag', 'vless-in')}-client",
            "server": server_address,
            "server_port": port,
            "uuid": vless_uuid,
            "flow": flow,
        }
        if tls:
            client_config["tls"] = tls
        if transport:
            client_config["transport"] = transport

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "uuid": vless_uuid,
                "server": server_address,
                "port": port,
                "flow": flow,
            },
            "notes": (
                [] if share_link else
                ["Reality client public key is required to generate a share link."]
            ),
        }
