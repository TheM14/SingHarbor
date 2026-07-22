"""AnyTLS protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/anytls/

Key points:
- TLS-based protocol with padding scheme for obfuscation
- Since sing-box 1.12.0
- Password-based authentication (per user)
- Standard AnyTLS URI format from the reference implementation
"""

from urllib.parse import quote, urlencode
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import client_tls, uri_fragment, uri_host


@register
class AnyTLSDefinition(ProtocolDefinition):
    name = "AnyTLS"
    inbound_type = "anytls"
    description = "AnyTLS protocol (TLS padding-based)"
    min_version = "1.12.0"
    supports_tls = True
    share_link_prefix = "anytls://"

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
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "anytls",
            "tag": params.get("tag", "anytls-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "password": params.get("password", ""),
                }
            ],
        }

        if params.get("tls"):
            config["tls"] = params["tls"]
        else:
            config["tls"] = {}

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        password = user.get("password", "")
        port = config.get("listen_port", 0)

        client_config = {
            "type": "anytls",
            "tag": f"{config.get('tag', 'anytls-in')}-client",
            "server": server_address,
            "server_port": port,
            "password": password,
        }
        tls = client_tls(config, server_address)
        if tls:
            client_config["tls"] = tls

        query = {}
        if tls and tls.get("server_name"):
            query["sni"] = tls["server_name"]
        if tls and tls.get("insecure"):
            query["insecure"] = "1"
        share_link = (
            f"anytls://{quote(password, safe='')}@"
            f"{uri_host(server_address)}:{port}/"
        )
        if query:
            share_link += "?" + urlencode(query)
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "password": password,
                "server": server_address,
                "port": port,
            },
            "notes": [
                "Requires TLS. The padding scheme defaults to the standard configuration.",
                "Since sing-box 1.12.0."
            ],
        }
