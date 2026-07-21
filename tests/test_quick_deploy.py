from pathlib import Path
import ssl

import pytest

from src.config import AppConfig
from src.config_mgr import ConfigManager
from src.quick_deploy import QuickDeploymentService, _match_certificate_hostname


def _service(tmp_path, app_config=None):
    manager = ConfigManager(
        tmp_path / "sing-box.json", tmp_path / "backups"
    )
    return QuickDeploymentService(manager, app_config=app_config), manager


def _full_values():
    return {
        "public_domain": "proxy.example.com",
        "certificate_directory": "/certs/proxy.example.com",
        "public_ipv4": "203.0.113.10",
        "public_ipv6": "2001:db8::10",
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
    assert by_tag["quick-hysteria2-tls-direct"]["tls"]["server_name"] == (
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


def test_empty_quick_deploy_input_is_rejected(tmp_path):
    service, _ = _service(tmp_path)
    plan = service.build_plan({}, kernel_version="1.13.14")

    assert plan["inbounds"] == []
    assert any("Provide at least one" in error for error in plan["errors"])


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
