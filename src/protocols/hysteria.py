"""Hysteria protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/hysteria/

Key points:
- QUIC-based protocol (predecessor to Hysteria2, still supported)
- Requires TLS
- Bandwidth limits: up_mbps, down_mbps
- Optional obfs password
- Share link: hysteria://password@server:port?protocol=udp&...
"""

import secrets
from urllib.parse import quote, urlencode
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import client_tls, uri_fragment, uri_host


@register
class HysteriaDefinition(ProtocolDefinition):
    name = "Hysteria"
    inbound_type = "hysteria"
    description = "Hysteria proxy protocol (QUIC-based, deprecated)"
    min_version = "1.0.0"
    supports_tls = True
    share_link_prefix = "hysteria://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("password", "password", required=True,
                      description="Authentication password (auth_str)"),
        ProtocolField("user_name", "string", default="user",
                      description="User name"),
        ProtocolField("up_mbps", "int", default=100,
                      min_value=1, max_value=10000,
                      description="Max upload bandwidth (Mbps)"),
        ProtocolField("down_mbps", "int", default=100,
                      min_value=1, max_value=10000,
                      description="Max download bandwidth (Mbps)"),
        ProtocolField("obfs", "password", default="",
                      description="Obfuscation password"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "hysteria",
            "tag": params.get("tag", "hy-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "up_mbps": int(params.get("up_mbps", 100)),
            "down_mbps": int(params.get("down_mbps", 100)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "auth_str": params.get("password", ""),
                }
            ],
        }

        if params.get("obfs"):
            config["obfs"] = params["obfs"]

        if params.get("tls"):
            config["tls"] = params["tls"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        password = user.get("auth_str", "")
        port = config.get("listen_port", 0)

        query = {
            "protocol": "udp",
            "upmbps": str(config.get("up_mbps", 100)),
            "downmbps": str(config.get("down_mbps", 100)),
        }
        if config.get("obfs"):
            query["obfs"] = config["obfs"]
        if config.get("tls", {}).get("server_name"):
            query["peer"] = config["tls"]["server_name"]

        share_link = f"hysteria://{quote(password, safe='')}@{uri_host(server_address)}:{port}"
        share_link += "?" + urlencode(query)
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "hysteria",
            "tag": f"{config.get('tag', 'hy-in')}-client",
            "server": server_address,
            "server_port": port,
            "auth_str": password,
        }
        tls = client_tls(config)
        if tls:
            client_config["tls"] = tls

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "password": password,
                "server": server_address,
                "port": port,
            },
            "notes": [
                "Hysteria is the old version. Consider using Hysteria2 instead.",
                "Requires TLS. Ensure certificate and key are configured."
            ],
        }
