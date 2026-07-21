"""Hysteria2 protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/hysteria2/

Key points:
- QUIC-based protocol (successor to Hysteria)
- Requires TLS
- Supports obfs (salamander) for traffic obfuscation
- Bandwidth limits: up_mbps, down_mbps
- Share link: hysteria2://password@server:port?sni=...&insecure=...
"""

import secrets
import base64
from urllib.parse import quote, urlencode
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import client_tls, uri_fragment, uri_host


@register
class Hysteria2Definition(ProtocolDefinition):
    name = "Hysteria2"
    inbound_type = "hysteria2"
    description = "Hysteria2 proxy protocol (QUIC-based)"
    min_version = "1.8.0"
    supports_tls = True
    share_link_prefix = "hysteria2://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("password", "password", required=True,
                      description="Authentication password"),
        ProtocolField("user_name", "string", default="user",
                      description="User name"),
        ProtocolField("up_mbps", "int", default=100,
                      min_value=1, max_value=10000,
                      description="Max upload bandwidth (Mbps)"),
        ProtocolField("down_mbps", "int", default=100,
                      min_value=1, max_value=10000,
                      description="Max download bandwidth (Mbps)"),
        ProtocolField("obfs_type", "string", default="",
                      choices=["", "salamander", "gecko"],
                      description="QUIC traffic obfuscator type"),
        ProtocolField("obfs_password", "password", default="",
                      description="Obfuscator password"),
        ProtocolField("ignore_client_bandwidth", "bool", default=False,
                      description="Ignore client bandwidth settings"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        obfs_type = params.get("obfs_type", "")
        if obfs_type and not params.get("obfs_password"):
            errors.append("obfs_password: required when obfs_type is set")
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "hysteria2",
            "tag": params.get("tag", "hy2-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "up_mbps": int(params.get("up_mbps", 100)),
            "down_mbps": int(params.get("down_mbps", 100)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "password": params.get("password", ""),
                }
            ],
            "ignore_client_bandwidth": bool(params.get("ignore_client_bandwidth", False)),
        }

        if params.get("tls"):
            config["tls"] = params["tls"]

        obfs_type = params.get("obfs_type", "")
        if obfs_type:
            config["obfs"] = {
                "type": obfs_type,
                "password": params.get("obfs_password", ""),
            }

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        password = user.get("password", "")
        port = config.get("listen_port", 0)

        query = {"insecure": "0"}
        if config.get("tls", {}).get("server_name"):
            query["sni"] = config["tls"]["server_name"]
        if config.get("obfs"):
            query["obfs"] = config["obfs"]["type"]
            if config["obfs"].get("password"):
                query["obfs-password"] = config["obfs"]["password"]

        share_link = f"hysteria2://{quote(password, safe='')}@{uri_host(server_address)}:{port}"
        if query:
            share_link += "?" + urlencode(query)
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "hysteria2",
            "tag": f"{config.get('tag', 'hy2-in')}-client",
            "server": server_address,
            "server_port": port,
            "password": password,
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
                "Hysteria2 requires TLS. Ensure certificate and key are configured.",
                "Bandwidth limits (up_mbps/down_mbps) affect all users."
            ],
        }
