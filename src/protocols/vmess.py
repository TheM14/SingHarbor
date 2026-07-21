"""VMess protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/vmess/

Share link format: vmess://{base64(json)}
"""

import json as json_lib
import base64
import uuid
from .base import ProtocolDefinition, ProtocolField
from .registry import register
from ..endpoints import (
    apply_server_connection_options,
    client_tls,
    client_transport,
)


@register
class VMessDefinition(ProtocolDefinition):
    name = "VMess"
    inbound_type = "vmess"
    description = "VMess proxy protocol"
    min_version = "1.0.0"
    supports_tls = True
    supports_transport = True
    supports_multiplex = True
    share_link_prefix = "vmess://"

    fields = [
        ProtocolField("listen", "string", default="0.0.0.0",
                      description="Listen address"),
        ProtocolField("listen_port", "int", required=True,
                      min_value=1, max_value=65535,
                      description="Listen port"),
        ProtocolField("uuid", "uuid", required=True,
                      description="VMess user UUID"),
        ProtocolField("alter_id", "int", default=0,
                      min_value=0, description="Alter ID (0 for AEAD)"),
        ProtocolField("user_name", "string", default="user",
                      description="User name"),
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        return errors

    def generate_config(self, params: dict) -> dict:
        config = {
            "type": "vmess",
            "tag": params.get("tag", "vmess-in"),
            "listen": params.get("listen", "::"),
            "listen_port": int(params.get("listen_port", 0)),
            "users": [
                {
                    "name": params.get("user_name", "user"),
                    "uuid": params.get("uuid", str(uuid.uuid4())),
                    "alterId": int(params.get("alter_id", 0)),
                }
            ],
        }

        apply_server_connection_options(config, params)
        if params.get("multiplex"):
            config["multiplex"] = params["multiplex"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        vmess_uuid = user.get("uuid", "")
        port = config.get("listen_port", 0)
        alter_id = user.get("alterId", 0)

        vmess_obj = {
            "v": "2",
            "ps": config.get("tag", "vmess-in"),
            "add": server_address,
            "port": str(port),
            "id": vmess_uuid,
            "aid": str(alter_id),
            "scy": "auto",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "",
            "sni": "",
            "alpn": "",
            "fp": "",
        }

        tls = client_tls(config, server_address)
        transport = client_transport(config, server_address)
        if tls:
            vmess_obj["tls"] = "tls"
            vmess_obj["sni"] = tls.get("server_name", "")
        if transport:
            vmess_obj["net"] = transport.get("type", "tcp")
            if transport.get("type") == "ws":
                vmess_obj["path"] = transport.get("path", "/")
                if transport.get("headers"):
                    vmess_obj["host"] = transport["headers"].get("Host", "")

        encoded = base64.b64encode(
            json_lib.dumps(vmess_obj, separators=(',', ':')).encode("utf-8")
        ).decode("ascii")
        share_link = f"vmess://{encoded}"

        client_config = {
            "type": "vmess",
            "tag": f"{config.get('tag', 'vmess-in')}-client",
            "server": server_address,
            "server_port": port,
            "uuid": vmess_uuid,
            "alter_id": alter_id,
            "security": "auto",
        }
        if tls:
            client_config["tls"] = tls
        if transport:
            client_config["transport"] = transport

        return {
            "share_link": share_link,
            "config_snippet": client_config,
            "credentials": {
                "uuid": vmess_uuid,
                "server": server_address,
                "port": port,
                "alter_id": alter_id,
            },
            "notes": [],
        }
