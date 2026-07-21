"""Naive protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/naive/

Key points:
- HTTP/2-based protocol (Chromium's network stack)
- TCP/UDP network support
- Username/password authentication
- Optional TLS
- Share link: naive+https://username:password@server:port
"""

import secrets
from urllib.parse import quote
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import client_tls, uri_fragment, uri_host


@register
class NaiveDefinition(ProtocolDefinition):
    name = "Naive"
    inbound_type = "naive"
    description = "Naive proxy protocol (Chromium network stack)"
    min_version = "1.3.0"
    supports_tls = True
    share_link_prefix = "naive+https://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("username", "string", required=True,
                      description="Naive username"),
        ProtocolField("password", "password", required=True,
                      description="Naive password"),
        ProtocolField("network", "string", default="",
                      choices=["", "tcp", "udp"],
                      description="Listen network (both if empty)"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "naive",
            "tag": params.get("tag", "naive-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "users": [
                {
                    "username": params.get("username", "user"),
                    "password": params.get("password", ""),
                }
            ],
        }

        if params.get("network"):
            config["network"] = params["network"]

        if params.get("tls"):
            config["tls"] = params["tls"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        username = user.get("username", "")
        password = user.get("password", "")
        port = config.get("listen_port", 0)

        userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}"
        share_link = f"naive+https://{userinfo}@{uri_host(server_address)}:{port}"
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "naive",
            "tag": f"{config.get('tag', 'naive-in')}-client",
            "server": server_address,
            "server_port": port,
            "username": username,
            "password": password,
        }
        tls = client_tls(config)
        if tls:
            client_config["tls"] = tls

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "username": username,
                "password": password,
                "server": server_address,
                "port": port,
            },
            "notes": [
                "Naive uses Chromium's network stack for TLS fingerprint resistance.",
                "Recommended to use with TLS for security."
            ],
        }
