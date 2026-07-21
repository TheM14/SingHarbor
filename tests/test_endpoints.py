import base64
import json

import pytest

from src.endpoints import (
    build_client_bundle,
    build_endpoint_profile,
    uri_host,
    validate_cdn_options,
)
from src.protocols import get_by_type
from src.wizard import DeploymentWizard


def _params(protocol_type):
    params = {
        "listen": "::",
        "listen_port": 10086,
        "cdn_listen_port": 443,
        "tag": f"{protocol_type}-edge",
        "user_name": "user",
        "ws_enabled": True,
        "ws_path": "/edge",
        "tls_enabled": True,
        "tls_server_name": "proxy.example.com",
        "tls_certificate_path": "/cert/fullchain.pem",
        "tls_key_path": "/cert/key.pem",
        "public_ipv4": "203.0.113.10",
        "public_ipv6": "2001:db8::10",
        "public_domain": "proxy.example.com",
        "preferred_endpoint": "domain",
        "cloudflare_proxied": True,
    }
    if protocol_type in {"vmess", "vless"}:
        params["uuid"] = "12345678-1234-1234-1234-123456789abc"
    if protocol_type == "vmess":
        params["alter_id"] = 0
    if protocol_type == "vless":
        params["flow"] = ""
    if protocol_type == "trojan":
        params["password"] = "a@b:/? secret"
    return params


def test_uri_host_brackets_only_ipv6():
    assert uri_host("203.0.113.10") == "203.0.113.10"
    assert uri_host("proxy.example.com") == "proxy.example.com"
    assert uri_host("2001:0db8::10") == "[2001:db8::10]"


def test_endpoint_profile_normalizes_all_variants():
    profile, errors = build_endpoint_profile({
        "public_ipv4": "203.0.113.10",
        "public_ipv6": "2001:0db8::10",
        "public_domain": "Proxy.Example.COM.",
        "cloudflare_proxied": "true",
        "preferred_endpoint": "domain",
    })
    assert errors == []
    assert profile["public_ipv6"] == "2001:db8::10"
    assert profile["public_domain"] == "proxy.example.com"
    assert profile["cloudflare_proxied"] is True


@pytest.mark.parametrize("protocol_type", ["vmess", "vless", "trojan"])
def test_cloudflare_ws_protocols_generate_domain_only_listener(protocol_type):
    params = _params(protocol_type)
    params["public_ipv4"] = ""
    params["public_ipv6"] = ""
    assert validate_cdn_options(protocol_type, params) == []
    wizard = DeploymentWizard(None, None, None)
    entries = wizard.build_deployment_entries(protocol_type, params)
    assert len(entries) == 1
    inbound = entries[0]["inbound"]
    bundle = build_client_bundle(get_by_type(protocol_type), inbound, entries[0]["profile"])

    assert entries[0]["role"] == "cdn"
    assert inbound["listen_port"] == 443
    assert inbound["transport"] == {"type": "ws", "path": "/edge"}
    assert inbound["tls"]["server_name"] == "proxy.example.com"
    assert [item["kind"] for item in bundle["variants"]] == ["domain"]
    assert bundle["preferred"] == "domain"

    domain = bundle["variants"][0]
    assert domain["config_snippet"]["server"] == "proxy.example.com"
    assert domain["config_snippet"]["tls"]["server_name"] == "proxy.example.com"
    assert domain["config_snippet"]["transport"]["headers"]["Host"] == "proxy.example.com"

    if protocol_type == "vmess":
        payload = json.loads(base64.b64decode(domain["share_link"].split("//", 1)[1]))
        assert payload["add"] == "proxy.example.com"
        assert payload["host"] == "proxy.example.com"
        assert payload["sni"] == "proxy.example.com"
    else:
        assert "@proxy.example.com:443" in domain["share_link"]


@pytest.mark.parametrize("protocol_type", ["vmess", "vless"])
def test_ip_and_cloudflare_domain_use_independent_listeners(protocol_type):
    params = _params(protocol_type)
    wizard = DeploymentWizard(None, None, None)
    entries = wizard.build_deployment_entries(protocol_type, params)

    assert [entry["role"] for entry in entries] == ["direct", "cdn"]
    direct, cdn = entries
    assert direct["inbound"]["listen_port"] == 10086
    assert "tls" not in direct["inbound"]
    assert "transport" not in direct["inbound"]
    assert direct["profile"]["public_domain"] == ""
    assert cdn["inbound"]["listen_port"] == 443
    assert cdn["inbound"]["transport"]["type"] == "ws"
    assert cdn["inbound"]["tls"]["enabled"] is True
    assert cdn["profile"]["public_ipv4"] == ""
    assert direct["inbound"]["users"] == cdn["inbound"]["users"]

    proto = get_by_type(protocol_type)
    direct_bundle = build_client_bundle(proto, direct["inbound"], direct["profile"])
    cdn_bundle = build_client_bundle(proto, cdn["inbound"], cdn["profile"])
    for variant in direct_bundle["variants"]:
        assert "tls" not in variant["config_snippet"]
        assert "transport" not in variant["config_snippet"]
    assert "tls" in cdn_bundle["variants"][0]["config_snippet"]
    assert "transport" in cdn_bundle["variants"][0]["config_snippet"]

    if protocol_type == "vmess":
        payload = json.loads(base64.b64decode(
            direct_bundle["variants"][0]["share_link"].split("//", 1)[1]
        ))
        assert payload["net"] == "tcp"
        assert payload["tls"] == ""


def test_trojan_credentials_are_escaped_in_share_link():
    params = _params("trojan")
    params["listen_port"] = 443
    proto = get_by_type("trojan")
    info = proto.generate_client_info(proto.generate_config(params), "2001:db8::10")
    assert "a%40b%3A%2F%3F%20secret@" in info["share_link"]
    assert "@[2001:db8::10]:443" in info["share_link"]


def test_quic_protocol_is_rejected_for_cloudflare_websocket():
    params = _params("hysteria2")
    errors = validate_cdn_options("hysteria2", params)
    assert any("not supported" in error for error in errors)
    assert any("requires VMess" in error for error in errors)


def test_trojan_plain_direct_split_is_rejected():
    errors = validate_cdn_options("trojan", _params("trojan"))
    assert any("plaintext IPv4/IPv6 listener" in error for error in errors)
