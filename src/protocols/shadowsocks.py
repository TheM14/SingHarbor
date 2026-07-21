"""Shadowsocks protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/shadowsocks/

Methods supported:
- 2022-blake3-aes-128-gcm (key length 16)
- 2022-blake3-aes-256-gcm (key length 32)
- 2022-blake3-chacha20-poly1305 (key length 32)
- aes-128-gcm, aes-192-gcm, aes-256-gcm
- chacha20-ietf-poly1305, xchacha20-ietf-poly1305
- none

Share link format: ss://{base64(method:password)}@{server}:{port}
"""

import base64
import secrets
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import uri_fragment, uri_host


@register
class ShadowsocksDefinition(ProtocolDefinition):
    name = "Shadowsocks"
    inbound_type = "shadowsocks"
    description = "Shadowsocks proxy protocol"
    min_version = "1.0.0"
    supports_multiplex = True
    share_link_prefix = "ss://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("method", "string", required=True,
                      choices=[
                          "2022-blake3-aes-128-gcm",
                          "2022-blake3-aes-256-gcm",
                          "2022-blake3-chacha20-poly1305",
                          "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
                          "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                          "none",
                      ],
                      description="Encryption method"),
        ProtocolField("password", "password", required=True,
                      description="Encryption password"),
        ProtocolField("network", "string",
                      choices=["tcp", "udp", "tcp,udp"],
                      description="Listen network"),
    ]

    @staticmethod
    def generate_password_for_method(method: str) -> str:
        """Generate an appropriate password for the given method."""
        if method.startswith("2022-blake3"):
            if "256" in method:
                key_len = 32
            else:
                key_len = 16
            raw = secrets.token_bytes(key_len)
            return base64.b64encode(raw).decode("ascii")
        elif method == "none":
            return ""
        else:
            return secrets.token_urlsafe(32)

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)

        method = params.get("method", "")
        password = params.get("password", "")

        if method.startswith("2022-blake3"):
            if "256" in method:
                key_len = 32
            else:
                key_len = 16
            try:
                decoded = base64.b64decode(password)
                if len(decoded) != key_len:
                    errors.append(
                        f"password: must be base64-encoded {key_len}-byte key"
                    )
            except Exception:
                errors.append("password: must be valid base64")

        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "shadowsocks",
            "tag": params.get("tag", "ss-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "method": params.get("method", "2022-blake3-aes-128-gcm"),
            "password": params.get("password", ""),
        }

        if params.get("network"):
            networks = params["network"]
            if networks != "tcp,udp":
                config["network"] = networks

        if params.get("multiplex"):
            config["multiplex"] = params["multiplex"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        method = config.get("method", "")
        password = config.get("password", "")
        port = config.get("listen_port", 0)

        encoded = base64.urlsafe_b64encode(
            f"{method}:{password}".encode("utf-8")
        ).decode("ascii")
        share_link = f"ss://{encoded}@{uri_host(server_address)}:{port}"
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "shadowsocks",
            "tag": f"{config.get('tag', 'ss-in')}-client",
            "server": server_address,
            "server_port": port,
            "method": method,
            "password": password,
        }

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "method": method,
                "password": password,
                "server": server_address,
                "port": port,
            },
            "notes": [],
        }
