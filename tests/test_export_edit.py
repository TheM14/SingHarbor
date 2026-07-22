import base64
import builtins

import pytest

from src.app import create_app
from src.exporter import build_client_export, generate_qr_data_url
from src.protocols import get_by_type


@pytest.fixture()
def authenticated_client(tmp_path):
    app = create_app(tmp_path / "settings.json", instance_path=tmp_path)
    app.config.update(TESTING=True)
    client = app.test_client()
    assert client.post(
        "/setup/initialize",
        json={"username": "admin", "password": "strong-test-password"},
    ).status_code == 200
    login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "strong-test-password"},
    )
    assert login.status_code == 200
    return client, login.get_json()["csrf_token"]


def test_bulk_export_includes_links_and_json_fallbacks():
    anytls = get_by_type("anytls").generate_config({
        "listen": "::",
        "listen_port": 8443,
        "tag": "anytls-in",
        "password": "secret",
        "tls": {"enabled": True, "server_name": "proxy.example.com"},
    })
    shadowtls = get_by_type("shadowtls").generate_config({
        "listen": "::",
        "listen_port": 9443,
        "tag": "shadowtls-in",
        "version": 3,
        "password": "secret",
        "handshake_server": "www.example.com",
        "handshake_port": 443,
    })
    profiles = {
        "anytls-in": {"public_domain": "proxy.example.com"},
        "shadowtls-in": {"public_ipv4": "203.0.113.10"},
    }

    result = build_client_export(
        {"inbounds": [anytls, shadowtls]}, endpoint_profiles=profiles
    )

    assert len(result["inbounds"]) == 2
    assert len(result["items"]) == 2
    by_tag = {item["inbound_tag"]: item for item in result["items"]}
    assert by_tag["anytls-in"]["share_link"].startswith("anytls://")
    assert by_tag["shadowtls-in"]["share_link"] == ""
    assert by_tag["shadowtls-in"]["portable_value"].startswith("{")
    assert "# anytls-in / Domain" in result["text"]
    assert "# shadowtls-in / IPv4 direct" in result["text"]


def test_qr_data_url_is_a_png_and_rejects_empty_values():
    data_url = generate_qr_data_url("vless://example")
    raw = base64.b64decode(data_url.split(",", 1)[1])

    assert data_url.startswith("data:image/png;base64,")
    assert raw.startswith(b"\x89PNG\r\n\x1a\n")
    with pytest.raises(ValueError, match="required"):
        generate_qr_data_url("")
    with pytest.raises(ValueError, match="too large"):
        generate_qr_data_url("x" * 3000)


def test_bulk_export_does_not_require_optional_qr_dependency(monkeypatch):
    real_import = builtins.__import__

    def import_without_qrcode(name, *args, **kwargs):
        if name == "qrcode" or name.startswith("qrcode."):
            raise ImportError("qrcode intentionally unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_qrcode)
    result = build_client_export({"inbounds": []})

    assert result["format"] == "singharbor-client-export"
    with pytest.raises(RuntimeError, match="requirements.txt"):
        generate_qr_data_url("vless://example")


def test_inbound_edit_api_updates_in_place_and_moves_profile(
        authenticated_client):
    client, csrf = authenticated_client
    app = client.application
    manager = app.config["config_manager"]
    ok, _ = manager.set_config({
        "inbounds": [{
            "type": "anytls",
            "tag": "old-tag",
            "listen": "::",
            "listen_port": 8443,
            "users": [{"name": "user", "password": "secret"}],
            "tls": {"enabled": True, "server_name": "proxy.example.com"},
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    })
    assert ok is True
    app.config["app_config"].set_inbound_endpoint_profiles({
        "old-tag": {"public_domain": "proxy.example.com"}
    })

    edit_data = client.get("/api/inbounds/old-tag/edit")
    assert edit_data.status_code == 200
    assert edit_data.get_json()["inbound"]["users"][0]["password"] == "secret"

    inbound = edit_data.get_json()["inbound"]
    inbound["tag"] = "new-tag"
    inbound["listen_port"] = 9443
    response = client.put(
        "/api/inbounds/old-tag",
        headers={"X-CSRF-Token": csrf},
        json={
            "inbound": inbound,
            "endpoint_profile": {
                "public_domain": "new.example.com",
                "preferred_endpoint": "domain",
            },
            "restart": False,
        },
    )

    assert response.status_code == 200
    assert manager.get_inbounds()[0]["tag"] == "new-tag"
    assert manager.get_inbounds()[0]["listen_port"] == 9443
    profiles = app.config["app_config"].inbound_endpoint_profiles
    assert "old-tag" not in profiles
    assert profiles["new-tag"]["public_domain"] == "new.example.com"
    assert manager.list_backups()


def test_inbound_edit_api_rejects_port_conflict(authenticated_client):
    client, csrf = authenticated_client
    manager = client.application.config["config_manager"]
    ok, _ = manager.set_config({
        "inbounds": [
            {"type": "vmess", "tag": "one", "listen_port": 10001},
            {"type": "vless", "tag": "two", "listen_port": 10002},
        ]
    })
    assert ok is True

    response = client.put(
        "/api/inbounds/one",
        headers={"X-CSRF-Token": csrf},
        json={
            "inbound": {"type": "vmess", "tag": "one", "listen_port": 10002},
            "restart": False,
        },
    )

    assert response.status_code == 400
    assert "Port conflict" in response.get_json()["error"]


def test_export_and_qr_api_return_portable_clients(authenticated_client):
    client, csrf = authenticated_client
    app = client.application
    inbound = get_by_type("anytls").generate_config({
        "listen": "::",
        "listen_port": 8443,
        "tag": "anytls-in",
        "password": "secret",
        "tls": {"enabled": True, "server_name": "proxy.example.com"},
    })
    ok, _ = app.config["config_manager"].set_config({"inbounds": [inbound]})
    assert ok is True
    app.config["app_config"].set_inbound_endpoint_profiles({
        "anytls-in": {"public_domain": "proxy.example.com"}
    })

    exported = client.get("/api/inbounds/export")
    assert exported.status_code == 200
    link = exported.get_json()["items"][0]["share_link"]
    assert link.startswith("anytls://")

    qr = client.post(
        "/api/tools/qr",
        headers={"X-CSRF-Token": csrf},
        json={"value": link},
    )
    assert qr.status_code == 200
    assert qr.get_json()["data_url"].startswith("data:image/png;base64,")
