from urllib.parse import parse_qs, urlparse

from src.endpoints import build_client_bundle
from src.protocols import get_by_type
from src.wizard import DeploymentWizard


PRIVATE_KEY = "A" * 43
PUBLIC_KEY = "B" * 43


def _reality_params():
    return {
        "listen": "::",
        "listen_port": 10443,
        "tag": "vless-reality",
        "uuid": "12345678-1234-1234-1234-123456789abc",
        "flow": "xtls-rprx-vision",
        "user_name": "user",
        "public_ipv4": "203.0.113.10",
        "preferred_endpoint": "ipv4",
        "cloudflare_proxied": False,
        "ws_enabled": False,
        "tls_enabled": False,
        "reality_enabled": True,
        "reality_handshake_server": "www.example.com",
        "reality_handshake_server_port": 443,
        "reality_server_name": "www.example.com",
        "reality_private_key": PRIVATE_KEY,
        "reality_public_key": PUBLIC_KEY,
        "reality_short_id": "0123456789abcdef",
        "reality_fingerprint": "chrome",
    }


def test_vless_reality_builds_server_config_and_v2ray_share_link():
    params = _reality_params()
    wizard = DeploymentWizard(None, None, None)

    assert wizard.validate_params("vless", params) == []
    entry = wizard.build_deployment_entries("vless", params)[0]
    inbound = entry["inbound"]

    assert inbound["tls"] == {
        "enabled": True,
        "server_name": "www.example.com",
        "reality": {
            "enabled": True,
            "handshake": {
                "server": "www.example.com",
                "server_port": 443,
            },
            "private_key": PRIVATE_KEY,
            "short_id": ["0123456789abcdef"],
        },
    }
    assert PUBLIC_KEY not in str(inbound)
    assert entry["profile"]["reality_public_key"] == PUBLIC_KEY
    assert entry["profile"]["reality_fingerprint"] == "chrome"

    bundle = build_client_bundle(get_by_type("vless"), inbound, entry["profile"])
    variant = bundle["variants"][0]
    parsed = urlparse(variant["share_link"])
    query = parse_qs(parsed.query)
    assert parsed.scheme == "vless"
    assert parsed.hostname == "203.0.113.10"
    assert query == {
        "type": ["tcp"],
        "encryption": ["none"],
        "security": ["reality"],
        "sni": ["www.example.com"],
        "pbk": [PUBLIC_KEY],
        "sid": ["0123456789abcdef"],
        "fp": ["chrome"],
        "flow": ["xtls-rprx-vision"],
    }
    client_tls = variant["config_snippet"]["tls"]
    assert client_tls["reality"]["public_key"] == PUBLIC_KEY
    assert client_tls["utls"]["fingerprint"] == "chrome"
    assert "private_key" not in str(variant["config_snippet"])


def test_empty_reality_block_is_not_promoted_by_client_metadata():
    inbound = {
        "type": "vless",
        "tag": "vless-tls",
        "listen_port": 443,
        "users": [{"uuid": "12345678-1234-1234-1234-123456789abc"}],
        "tls": {
            "enabled": True,
            "server_name": "proxy.example.com",
            "reality": {},
        },
    }
    bundle = build_client_bundle(get_by_type("vless"), inbound, {
        "public_domain": "proxy.example.com",
        "reality_public_key": PUBLIC_KEY,
    })

    variant = bundle["variants"][0]
    query = parse_qs(urlparse(variant["share_link"]).query)
    assert query["security"] == ["tls"]
    assert "pbk" not in query
    assert "reality" not in variant["config_snippet"]["tls"]


def test_vless_reality_rejects_cloudflare_and_bad_short_id():
    params = _reality_params()
    params["cloudflare_proxied"] = True
    params["public_domain"] = "proxy.example.com"
    params["reality_short_id"] = "xyz"

    errors = DeploymentWizard(None, None, None).validate_params("vless", params)

    assert any("even-length hex" in error for error in errors)
    assert any("cannot use Cloudflare" in error for error in errors)


def test_anytls_generates_reference_uri_for_ipv4_and_ipv6():
    proto = get_by_type("anytls")
    config = proto.generate_config({
        "listen": "::",
        "listen_port": 8443,
        "tag": "anytls edge",
        "password": "p@ss word",
        "user_name": "user",
        "tls": {"enabled": True, "server_name": "proxy.example.com"},
    })

    ipv4 = proto.generate_client_info(config, "203.0.113.10")["share_link"]
    ipv6 = proto.generate_client_info(config, "2001:db8::10")["share_link"]

    assert ipv4 == (
        "anytls://p%40ss%20word@203.0.113.10:8443/"
        "?sni=proxy.example.com#anytls%20edge"
    )
    assert "@[2001:db8::10]:8443/" in ipv6
    assert get_by_type("anytls").share_link_prefix == "anytls://"
