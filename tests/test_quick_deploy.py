from pathlib import Path
import json
import ssl

import pytest

from src.config import AppConfig
from src.certificates import CertificateIssueError
from src.config_mgr import ConfigManager
from src.quick_deploy import (
    TLS_DIRECT_PROTOCOLS,
    QuickDeploymentService,
    _match_certificate_hostname,
)


def _service(tmp_path, app_config=None, certificate_issuer=None):
    manager = ConfigManager(
        tmp_path / "sing-box.json", tmp_path / "backups"
    )
    return QuickDeploymentService(
        manager,
        app_config=app_config,
        certificate_issuer=certificate_issuer,
    ), manager


def _full_values():
    return {
        "public_domain": "proxy.example.com",
        "certificate_directory": "/certs/proxy.example.com",
        "public_ipv4": "203.0.113.10",
        "public_ipv6": "2001:db8::10",
        "cloudflare_preferred_ip": "2606:4700:4700::1111",
    }


def test_certificate_hostname_match_supports_exact_and_wildcard_names():
    exact = {"subjectAltName": (("DNS", "proxy.example.com"),)}
    wildcard = {"subjectAltName": (("DNS", "*.example.com"),)}

    _match_certificate_hostname(exact, "proxy.example.com")
    _match_certificate_hostname(wildcard, "proxy.example.com")


def test_certificate_hostname_match_rejects_wrong_or_nested_domain():
    certificate = {"subjectAltName": (("DNS", "*.example.com"),)}

    with pytest.raises(ssl.CertificateError, match="does not match"):
        _match_certificate_hostname(certificate, "example.com")
    with pytest.raises(ssl.CertificateError, match="does not match"):
        _match_certificate_hostname(certificate, "a.proxy.example.com")


def test_certificate_hostname_match_uses_common_name_only_without_dns_san():
    certificate = {"subject": ((("commonName", "proxy.example.com"),),)}

    _match_certificate_hostname(certificate, "proxy.example.com")


def test_direct_only_quick_deploy_uses_three_native_protocols(tmp_path):
    service, _ = _service(tmp_path)
    plan = service.build_plan(
        {"public_ipv4": "203.0.113.10"}, kernel_version="1.13.14"
    )

    assert plan["errors"] == []
    assert len(plan["inbounds"]) == 3
    assert {item["type"] for item in plan["inbounds"]} == {
        "shadowsocks", "vmess", "vless"
    }
    assert all("tls" not in item for item in plan["inbounds"])
    assert all("transport" not in item for item in plan["inbounds"])
    planned = {
        item["type"] for item in plan["protocols"]
        if item["status"] == "planned"
    }
    assert planned == {"shadowsocks", "vmess", "vless"}
    assert all(
        variant["kind"] == "ipv4"
        for item in plan["protocols"] for variant in item["variants"]
    )


def test_full_quick_deploy_builds_eleven_inbounds_for_eight_protocols(
        tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.quick_deploy.find_certificate_pair",
        lambda directory, domain: (
            "/certs/proxy.example.com/fullchain.pem",
            "/certs/proxy.example.com/privkey.pem",
        ),
    )
    service, _ = _service(tmp_path)
    plan = service.build_plan(_full_values(), kernel_version="1.13.14")

    assert plan["errors"] == []
    assert len(plan["inbounds"]) == 11
    assert len({item["tag"] for item in plan["inbounds"]}) == 11
    assert len({item["listen_port"] for item in plan["inbounds"]}) == 11
    planned = {
        item["type"] for item in plan["protocols"]
        if item["status"] == "planned"
    }
    assert planned == {
        "shadowsocks", "vmess", "vless", "trojan",
        "hysteria2", "tuic", "hysteria", "anytls",
    }

    by_tag = {item["tag"]: item for item in plan["inbounds"]}
    assert "tls" not in by_tag["quick-vmess-direct"]
    assert "transport" not in by_tag["quick-vmess-direct"]
    assert by_tag["quick-vmess-cdn"]["listen_port"] == 2053
    assert all(item["listen_port"] != 443 for item in plan["inbounds"])
    assert by_tag["quick-vmess-cdn"]["transport"]["type"] == "ws"
    assert by_tag["quick-vmess-cdn"]["tls"]["enabled"] is True
    assert "cloudflare_preferred_ip" not in json.dumps(plan["inbounds"])
    assert by_tag["quick-hysteria2-tls-direct"]["tls"]["server_name"] == (
        "proxy.example.com"
    )

    vmess = next(item for item in plan["protocols"] if item["type"] == "vmess")
    vmess_cdn = next(
        variant for variant in vmess["variants"] if variant["role"] == "cdn"
    )
    assert vmess_cdn["address"] == "2606:4700:4700::1111"
    assert vmess_cdn["config_snippet"]["server"] == "2606:4700:4700::1111"
    assert vmess_cdn["config_snippet"]["tls"]["server_name"] == (
        "proxy.example.com"
    )

    hysteria2 = next(
        item for item in plan["protocols"] if item["type"] == "hysteria2"
    )
    assert all(
        variant["config_snippet"]["tls"]["server_name"] == "proxy.example.com"
        for variant in hysteria2["variants"]
    )
    skipped = {
        item["type"] for item in plan["protocols"]
        if item["status"] == "skipped"
    }
    assert skipped == {"shadowtls", "naive"}


def test_lets_encrypt_certificate_is_separate_from_origin_certificate(
        tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.quick_deploy.find_certificate_pair",
        lambda directory, domain: (
            "/origin/origin-cert.pem", "/origin/origin-key.pem"
        ),
    )
    service, _ = _service(tmp_path)
    issued = {
        "source": "letsencrypt",
        "domain": "proxy.example.com",
        "certificate_path": "/public/fullchain.pem",
        "key_path": "/public/privkey.pem",
    }

    plan = service.build_plan(
        _full_values(), kernel_version="1.13.14",
        issued_certificate=issued,
    )
    by_tag = {item["tag"]: item for item in plan["inbounds"]}

    assert by_tag["quick-trojan-tls-direct"]["tls"][
        "certificate_path"
    ] == "/public/fullchain.pem"
    assert by_tag["quick-hysteria2-tls-direct"]["tls"][
        "key_path"
    ] == "/public/privkey.pem"
    assert by_tag["quick-trojan-cdn"]["tls"][
        "certificate_path"
    ] == "/origin/origin-cert.pem"


def test_empty_quick_deploy_input_is_rejected(tmp_path):
    service, _ = _service(tmp_path)
    plan = service.build_plan({}, kernel_version="1.13.14")

    assert plan["inbounds"] == []
    assert any("Provide at least one" in error for error in plan["errors"])


def test_quick_deploy_rejects_invalid_cloudflare_preferred_ip(tmp_path):
    service, _ = _service(tmp_path)
    plan = service.build_plan({
        "public_ipv4": "203.0.113.10",
        "cloudflare_preferred_ip": "not-an-ip",
    }, kernel_version="1.13.14")

    assert plan["inbounds"] == []
    assert plan["errors"] == [
        "cloudflare_preferred_ip: must be a valid IPv4 or IPv6 address"
    ]


def test_quick_deploy_allocates_around_existing_ports(tmp_path):
    service, manager = _service(tmp_path)
    ok, _ = manager.set_config({
        "inbounds": [
            {"type": "direct", "tag": "occupied-direct", "listen_port": 10001},
            {"type": "direct", "tag": "occupied-cdn", "listen_port": 443},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    })
    assert ok is True

    plan = service.build_plan(
        {"public_ipv4": "203.0.113.10"}, kernel_version="1.13.14"
    )

    ports = [item["listen_port"] for item in plan["inbounds"]]
    assert 10001 not in ports
    assert len(ports) == len(set(ports))


def test_quick_deploy_saves_all_inbounds_atomically(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.quick_deploy.find_certificate_pair",
        lambda directory, domain: ("/cert/fullchain.pem", "/cert/privkey.pem"),
    )
    app_config = AppConfig(tmp_path / "settings.json", project_root=tmp_path)
    service, manager = _service(tmp_path, app_config)

    result = service.deploy(
        _full_values(),
        Path("unused-sing-box"),
        manager.config_path,
        kernel_version="1.13.14",
        restart=False,
    )

    assert result["success"] is True
    assert len(manager.read()["inbounds"]) == 11
    assert len(app_config.inbound_endpoint_profiles) == 11
    assert app_config.public_endpoints["preferred_endpoint"] == "domain"
    assert app_config.public_endpoints["cloudflare_preferred_ip"] == (
        "2606:4700:4700::1111"
    )


def test_lets_encrypt_replaces_existing_direct_tls_without_redeployment(
        tmp_path):
    receipt_path = tmp_path / "data" / "letsencrypt" / "last-issuance.json"

    class FakeIssuer:
        def issue(self, domain, email, token):
            assert (domain, email, token) == (
                "proxy.example.com", "admin@example.com", "one-shot-secret"
            )
            return {
                "source": "letsencrypt",
                "domain": domain,
                "certificate_path": "/public/fullchain.pem",
                "key_path": "/public/privkey.pem",
                "receipt_path": str(receipt_path),
            }

    app_config = AppConfig(tmp_path / "settings.json", project_root=tmp_path)
    service, manager = _service(tmp_path, app_config, FakeIssuer())
    inbounds = []
    port = 10001
    for protocol_type in ("shadowsocks", "vmess", "vless"):
        inbounds.append({
            "type": protocol_type,
            "tag": f"quick-{protocol_type}-existing",
            "listen_port": port,
        })
        port += 1
    for protocol_type in TLS_DIRECT_PROTOCOLS:
        inbounds.append({
            "type": protocol_type,
            "tag": f"quick-{protocol_type}-tls-direct",
            "listen_port": port,
            "tls": {
                "enabled": True,
                "server_name": "proxy.example.com",
                "certificate_path": "/origin/origin-cert.pem",
                "key_path": "/origin/origin-key.pem",
            },
        })
        port += 1
    assert manager.set_config({"inbounds": inbounds})[0] is True

    result = service.deploy(
        {
            "public_domain": "proxy.example.com",
            "public_ipv4": "203.0.113.10",
            "lets_encrypt_enabled": True,
            "lets_encrypt_email": "admin@example.com",
            "cloudflare_api_token": "one-shot-secret",
        },
        Path("unused-sing-box"),
        manager.config_path,
        kernel_version="1.13.14",
        restart=False,
    )

    assert result["success"] is True
    assert result["inbounds"] == []
    assert len(result["certificate"]["updated_inbounds"]) == len(
        TLS_DIRECT_PROTOCOLS
    )
    assert len(result["certificate"]["configured_inbounds"]) == len(
        TLS_DIRECT_PROTOCOLS
    )
    assert "one-shot-secret" not in str(result)
    saved = {
        item["tag"]: item for item in manager.read()["inbounds"]
    }
    for protocol_type in TLS_DIRECT_PROTOCOLS:
        tls = saved[f"quick-{protocol_type}-tls-direct"]["tls"]
        assert tls["certificate_path"] == "/public/fullchain.pem"
        assert tls["key_path"] == "/public/privkey.pem"
    receipt = json.loads(receipt_path.read_text("utf-8"))
    assert len(receipt["configured_inbounds"]) == len(TLS_DIRECT_PROTOCOLS)
    assert "one-shot-secret" not in str(receipt)


def test_lets_encrypt_takeover_does_not_depend_on_quick_deploy_tags(tmp_path):
    service, _ = _service(tmp_path)
    config = {
        "inbounds": [
            {
                "type": "hysteria2",
                "tag": "proxy",
                "tls": {
                    "enabled": True,
                    "certificate_path": "/origin/cert.pem",
                    "key_path": "/origin/key.pem",
                },
            },
            {
                "type": "tuic",
                "tag": "my-tuic-server",
                "tls": {
                    "enabled": True,
                    "certificate_path": "/origin/cert.pem",
                    "key_path": "/origin/key.pem",
                },
            },
            {
                "type": "trojan",
                "tag": "custom-trojan-direct",
                "tls": {
                    "enabled": True,
                    "certificate_path": "/origin/cert.pem",
                    "key_path": "/origin/key.pem",
                },
            },
            {
                "type": "trojan",
                "tag": "custom-trojan-cdn",
                "transport": {"type": "ws", "path": "/trojan"},
                "tls": {
                    "enabled": True,
                    "certificate_path": "/origin/cert.pem",
                    "key_path": "/origin/key.pem",
                },
            },
        ],
    }
    certificate = {
        "domain": "proxy.example.com",
        "certificate_path": "/public/fullchain.pem",
        "key_path": "/public/privkey.pem",
    }

    updated = service._take_over_direct_tls(config, certificate)

    assert updated == ["proxy", "my-tuic-server", "custom-trojan-direct"]
    for inbound in config["inbounds"][:3]:
        assert inbound["tls"]["certificate_path"] == "/public/fullchain.pem"
    assert config["inbounds"][3]["tls"]["certificate_path"] == (
        "/origin/cert.pem"
    )


def test_lets_encrypt_failure_never_falls_back_to_origin_ca(
        tmp_path, monkeypatch):
    class FailingIssuer:
        def issue(self, domain, email, token):
            raise CertificateIssueError("Certbot dependency is missing")

    monkeypatch.setattr(
        "src.quick_deploy.find_certificate_pair",
        lambda directory, domain: (
            "/origin/origin-cert.pem", "/origin/origin-key.pem"
        ),
    )
    service, manager = _service(
        tmp_path, certificate_issuer=FailingIssuer()
    )
    original = {"inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}]}
    assert manager.set_config(original)[0] is True

    result = service.deploy(
        {
            **_full_values(),
            "lets_encrypt_enabled": True,
            "lets_encrypt_email": "admin@example.com",
            "cloudflare_api_token": "one-shot-secret",
        },
        Path("unused-sing-box"),
        manager.config_path,
        kernel_version="1.13.14",
        restart=False,
    )

    assert result["success"] is False
    assert "Certbot dependency is missing" in result["message"]
    assert manager.read() == original
