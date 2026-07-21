"""Trojan protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/trojan/

Share link format: trojan://{password}@{server}:{port}?...
"""

from urllib.parse import quote, urlencode
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import (
    apply_server_connection_options,
    client_tls,
    client_transport,
    uri_fragment,
    uri_host,
)


@register
class TrojanDefinition(ProtocolDefinition):
    name = "Trojan"
    inbound_type = "trojan"
    description = "Trojan proxy protocol"
    min_version = "1.0.0"
    supports_tls = True
    supports_transport = True
    supports_multiplex = True
    share_link_prefix = "trojan://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("password", "password", required=True,
                      description="Trojan password"),
        ProtocolField("user_name", "string", default="user",
                      description="User name"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "trojan",
            "tag": params.get("tag", "trojan-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "password": params.get("password", ""),
                }
            ],
        }

        apply_server_connection_options(config, params)
        if params.get("multiplex"):
            config["multiplex"] = params["multiplex"]
        if params.get("fallback"):
            config["fallback"] = params["fallback"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        password = user.get("password", "")
        port = config.get("listen_port", 0)

        query = {}
        tls = client_tls(config, server_address)
        transport = client_transport(config, server_address)
        if transport:
            if transport.get("type") == "ws":
                query["type"] = "ws"
                query["path"] = transport.get("path", "/")
                if transport.get("headers", {}).get("Host"):
                    query["host"] = transport["headers"]["Host"]
        if tls:
            query["security"] = "tls"
            if tls.get("server_name"):
                query["sni"] = tls["server_name"]

        share_link = f"trojan://{quote(password, safe='')}@{uri_host(server_address)}:{port}"
        if query:
            share_link += "?" + urlencode(query)
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "trojan",
            "tag": f"{config.get('tag', 'trojan-in')}-client",
            "server": server_address,
            "server_port": port,
            "password": password,
        }
        if tls:
            client_config["tls"] = tls
        if transport:
            client_config["transport"] = transport

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "password": password,
                "server": server_address,
                "port": port,
            },
            "notes": [
                "Trojan requires TLS. Ensure certificate and key are configured."
            ],
        }
