"""TUIC protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/tuic/

Key points:
- QUIC-based protocol
- Requires TLS
- UUID + password authentication
- Custom congestion control (cubic, new_reno, bbr)
- Share link: tuic://uuid:password@server:port?sni=...&congestion_control=...
"""

import uuid
import secrets
from urllib.parse import quote, urlencode
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import client_tls, uri_fragment, uri_host


@register
class TUICDefinition(ProtocolDefinition):
    name = "TUIC"
    inbound_type = "tuic"
    description = "TUIC proxy protocol (QUIC-based)"
    min_version = "1.3.0"
    supports_tls = True
    share_link_prefix = "tuic://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("uuid", "uuid", required=True,
                      description="TUIC user UUID"),
        ProtocolField("password", "password", required=True,
                      description="TUIC user password"),
        ProtocolField("user_name", "string", default="user",
                      description="User name"),
        ProtocolField("congestion_control", "string", default="cubic",
                      choices=["cubic", "new_reno", "bbr"],
                      description="QUIC congestion control"),
        ProtocolField("auth_timeout", "string", default="3s",
                      description="Authentication timeout"),
        ProtocolField("heartbeat", "string", default="10s",
                      description="Heartbeat interval"),
        ProtocolField("zero_rtt_handshake", "bool", default=False,
                      description="Enable 0-RTT handshake"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "tuic",
            "tag": params.get("tag", "tuic-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "uuid": params.get("uuid", str(uuid.uuid4())),
                    "password": params.get("password", ""),
                }
            ],
            "congestion_control": params.get("congestion_control", "cubic"),
            "auth_timeout": params.get("auth_timeout", "3s"),
            "heartbeat": params.get("heartbeat", "10s"),
            "zero_rtt_handshake": bool(params.get("zero_rtt_handshake", False)),
        }

        if params.get("tls"):
            config["tls"] = params["tls"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        tuic_uuid = user.get("uuid", "")
        password = user.get("password", "")
        port = config.get("listen_port", 0)

        query = {
            "congestion_control": config.get("congestion_control", "cubic"),
            "udp_relay_mode": "native",
        }
        if config.get("tls", {}).get("server_name"):
            query["sni"] = config["tls"]["server_name"]

        userinfo = f"{quote(tuic_uuid, safe='')}:{quote(password, safe='')}"
        share_link = f"tuic://{userinfo}@{uri_host(server_address)}:{port}"
        share_link += "?" + urlencode(query)
        if config.get("tag"):
            share_link += f"#{uri_fragment(config['tag'])}"

        client_config = {
            "type": "tuic",
            "tag": f"{config.get('tag', 'tuic-in')}-client",
            "server": server_address,
            "server_port": port,
            "uuid": tuic_uuid,
            "password": password,
        }
        tls = client_tls(config)
        if tls:
            client_config["tls"] = tls

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "uuid": tuic_uuid,
                "password": password,
                "server": server_address,
                "port": port,
            },
            "notes": [
                "TUIC requires TLS. Ensure certificate and key are configured.",
                "0-RTT handshake is vulnerable to replay attacks - disabled by default."
            ],
        }
