"""ShadowTLS protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/shadowtls/

Key points:
- TLS handshake-based protocol obfuscation
- Versions 1, 2, 3 supported
- V1/V2: password-based, V3: user-based
- No standard share link format - marked as unsupported
"""

import secrets
import base64
from .base import ProtocolDefinition, ProtocolField
from .registry import register


@register
class ShadowTLSDefinition(ProtocolDefinition):
    name = "ShadowTLS"
    inbound_type = "shadowtls"
    description = "ShadowTLS protocol (TLS handshake obfuscation)"
    min_version = "1.4.0"
    share_link_prefix = ""

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("version", "int", default=3,
                      choices=[1, 2, 3],
                      description="ShadowTLS protocol version"),
        ProtocolField("password", "password", required=True,
                      description="ShadowTLS password"),
        ProtocolField("handshake_server", "string", required=True,
                      description="Handshake server address"),
        ProtocolField("handshake_port", "int", default=443,
                      min_value=1, max_value=65535,
                      description="Handshake server port"),
        ProtocolField("strict_mode", "bool", default=False,
                      description="Enable strict mode (V3 only)"),
        ProtocolField("user_name", "string", default="user",
                      description="User name (V3 only)"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        version = int(params.get("version", 3))
        if version not in (1, 2, 3):
            errors.append("version: must be 1, 2, or 3")
        strict_mode = bool(params.get("strict_mode", False))
        if strict_mode and version != 3:
            errors.append("strict_mode: only available in protocol version 3")
        return errors

    def generate_config(self, params: dict) -> dict:
        version = int(params.get("version", 3))

        config = {
            "type": "shadowtls",
            "tag": params.get("tag", "st-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "version": version,
            "handshake": {
                "server": params.get("handshake_server", "google.com"),
                "server_port": int(params.get("handshake_port", 443)),
            },
            "strict_mode": bool(params.get("strict_mode", False)),
        }

        if version == 3:
            config["users"] = [
                {
                    "name": params.get("user_name", "user"),
                    "password": params.get("password", ""),
                }
            ]
        else:
            config["password"] = params.get("password", "")

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        port = config.get("listen_port", 0)
        version = config.get("version", 3)
        password = config.get("password", "")
        handshake = config.get("handshake", {})

        if version == 3 and config.get("users"):
            password = config["users"][0].get("password", "")

        client_config = {
            "type": "shadowtls",
            "tag": f"{config.get('tag', 'st-in')}-client",
            "server": server_address,
            "server_port": port,
            "handshake": handshake,
        }
        if version == 3:
            client_config["password"] = password
        else:
            client_config["password"] = password

        return {
            "share_link": "",
            "config_snippet": client_config,
            "credentials": {
                "password": password,
                "server": server_address,
                "port": port,
                "handshake_server": handshake.get("server", ""),
            },
            "notes": [
                "ShadowTLS has no standard share link format.",
                "The handshake server is the fallback destination for non-ShadowTLS traffic."
            ],
        }
