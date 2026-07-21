"""VLESS protocol definition for sing-box server inbound.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/vless/

Share link format: vless://{uuid}@{server}:{port}?...
"""

import uuid
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
    ]

    def validate_params(self, params: dict) -> list[str]:
        errors = self.validate_basic(params)
        flow = params.get("flow", "")
        if flow and flow not in ("xtls-rprx-vision", ""):
            errors.append("flow: must be empty or 'xtls-rprx-vision'")
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

        apply_server_connection_options(config, params)
        if params.get("multiplex"):
            config["multiplex"] = params["multiplex"]

        return config

    def generate_client_info(self, config: dict, server_address: str) -> dict:
        user = config.get("users", [{}])[0]
        vless_uuid = user.get("uuid", "")
        port = config.get("listen_port", 0)
        flow = user.get("flow", "")

        query = {"type": "tcp", "security": "none"}
        tls = client_tls(config, server_address)
        transport = client_transport(config, server_address)
        if transport:
            query["type"] = transport.get("type", "tcp")
            if transport.get("type") == "ws":
                query["path"] = transport.get("path", "/")
                if transport.get("headers", {}).get("Host"):
                    query["host"] = transport["headers"]["Host"]
        if tls:
            query["security"] = "tls"
            if tls.get("server_name"):
                query["sni"] = tls["server_name"]
        if flow:
            query["flow"] = flow

        share_link = f"vless://{quote(vless_uuid, safe='')}@{uri_host(server_address)}:{port}"
        share_link += "?" + urlencode(query)
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
            "notes": [],
        }
