import json

import pytest

from src.app import create_app
from src.utils import mask_sensitive


@pytest.fixture()
def authenticated_client(tmp_path):
    app = create_app(tmp_path / "settings.json", instance_path=tmp_path)
    app.config.update(TESTING=True)
    client = app.test_client()
    setup = client.post(
        "/setup/initialize",
        json={"username": "admin", "password": "strong-test-password"},
    )
    assert setup.status_code == 200
    login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "strong-test-password"},
    )
    assert login.status_code == 200
    return client, login.get_json()["csrf_token"]


def test_protocol_schema_exposes_cloudflare_capability(authenticated_client):
    client, _ = authenticated_client
    vmess = client.get("/api/protocols/vmess").get_json()["protocol"]
    hysteria2 = client.get("/api/protocols/hysteria2").get_json()["protocol"]
    assert vmess["supports_cloudflare_ws"] is True
    assert hysteria2["supports_cloudflare_ws"] is False


def test_vmess_preview_separates_plain_ip_and_tls_domain_inbounds(authenticated_client):
    client, _ = authenticated_client
    response = client.post(
        "/api/protocols/preview",
        json={
            "type": "vmess",
            "params": {
                "listen": "::",
                "listen_port": 10086,
                "cdn_listen_port": 443,
                "tag": "vmess-edge",
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "alter_id": 0,
                "user_name": "user",
                "public_ipv4": "203.0.113.10",
                "public_ipv6": "2001:db8::10",
                "public_domain": "proxy.example.com",
                "preferred_endpoint": "domain",
                "cloudflare_proxied": True,
                "ws_enabled": True,
                "ws_path": "/edge",
                "tls_enabled": True,
                "tls_server_name": "proxy.example.com",
                "tls_certificate_path": "/cert/fullchain.pem",
                "tls_key_path": "/cert/key.pem",
            },
        },
    )

    assert response.status_code == 200
    direct, cdn = response.get_json()["preview"]["inbounds"]
    assert direct["tag"] == "vmess-edge-direct"
    assert direct["listen_port"] == 10086
    assert "tls" not in direct and "transport" not in direct
    assert cdn["tag"] == "vmess-edge-cdn"
    assert cdn["listen_port"] == 443
    assert cdn["tls"]["enabled"] is True
    assert cdn["transport"]["type"] == "ws"


def test_public_endpoint_settings_round_trip(authenticated_client):
    client, csrf = authenticated_client
    response = client.put(
        "/api/settings/public-endpoints",
        headers={"X-CSRF-Token": csrf},
        json={
            "public_ipv4": "203.0.113.10",
            "public_ipv6": "2001:db8::10",
            "public_domain": "proxy.example.com",
            "cloudflare_preferred_ip": "104.16.0.1",
            "preferred_endpoint": "domain",
            "cloudflare_proxied": True,
            "cloudflare_zone_id": "0123456789abcdef0123456789abcdef",
        },
    )
    assert response.status_code == 200
    settings = client.get("/api/settings").get_json()
    assert settings["public_endpoints"]["public_ipv6"] == "2001:db8::10"
    assert settings["public_endpoints"]["cloudflare_preferred_ip"] == "104.16.0.1"
    assert settings["cloudflare_zone_id"] == "0123456789abcdef0123456789abcdef"


def test_cloudflare_preview_never_requires_or_returns_token(authenticated_client):
    client, _ = authenticated_client
    response = client.post(
        "/api/cloudflare/dns/preview",
        json={
            "zone_id": "0123456789abcdef0123456789abcdef",
            "hostname": "proxy.example.com",
            "public_domain": "proxy.example.com",
            "public_ipv4": "203.0.113.10",
            "public_ipv6": "2001:db8::10",
            "cloudflare_proxied": True,
            "api_token": "must-not-be-returned",
        },
    )
    assert response.status_code == 200
    assert "must-not-be-returned" not in response.get_data(as_text=True)


def test_cloudflare_sync_requires_matching_preview(authenticated_client):
    client, csrf = authenticated_client
    response = client.post(
        "/api/cloudflare/dns/sync",
        headers={"X-CSRF-Token": csrf},
        json={
            "zone_id": "0123456789abcdef0123456789abcdef",
            "hostname": "proxy.example.com",
            "public_domain": "proxy.example.com",
            "public_ipv4": "203.0.113.10",
            "cloudflare_proxied": True,
            "api_token": "must-not-be-used",
        },
    )
    assert response.status_code == 409
    assert "Preview" in response.get_json()["error"]


def test_all_authenticated_pages_render(authenticated_client):
    client, _ = authenticated_client
    for path in (
        "/dashboard",
        "/dashboard/kernel",
        "/dashboard/config",
        "/dashboard/inbounds",
        "/dashboard/protocols",
        "/dashboard/wizard",
        "/dashboard/quick-deploy",
        "/dashboard/settings",
    ):
        assert client.get(path).status_code == 200
    response = client.get("/dashboard/wizard")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "/static/css/theme.css" in body
    assert "/static/js/wizard.js" in body
    assert "id=\"theme-toggle\"" in body
    quick = client.get("/dashboard/quick-deploy").get_data(as_text=True)
    assert "/static/js/quick_deploy.js?v=1.1.0-le3" in quick
    assert "id=\"quick-deploy-form\"" in quick
    assert "id=\"quick-cf-preferred-ip\"" in quick
    assert "id=\"quick-le-enabled\"" in quick
    assert "id=\"quick-le-email\"" in quick
    assert "id=\"quick-le-token\"" in quick
    assert 'id="quick-le-fields" hidden' not in quick
    wizard = client.get("/dashboard/wizard").get_data(as_text=True)
    assert "id=\"wizard-cf-preferred-ip\"" in wizard
    inbounds = client.get("/dashboard/inbounds").get_data(as_text=True)
    assert "/static/js/inbounds.js" in inbounds
    assert "id=\"inbound-edit-dialog\"" in inbounds


def test_config_editor_raw_json_is_valid_and_preserves_credentials(
        authenticated_client):
    client, _ = authenticated_client
    manager = client.application.config["config_manager"]
    config = {
        "inbounds": [{
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "::",
            "listen_port": 8443,
            "users": [{"password": "secret-value", "name": "client-after"}],
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    ok, _ = manager.set_config(config)
    assert ok is True

    response = client.get("/api/config")
    assert response.status_code == 200
    raw = response.get_json()["raw"]
    parsed = json.loads(raw)
    assert parsed == config
    assert parsed["inbounds"][0]["users"][0] == {
        "password": "secret-value",
        "name": "client-after",
    }


def test_log_masking_keeps_json_punctuation_valid():
    raw = '{"password": "secret", "name": "kept", "enabled": true}'
    masked = mask_sensitive(raw)

    assert json.loads(masked) == {
        "password": "***",
        "name": "kept",
        "enabled": True,
    }


def test_config_check_rejects_non_object_json(authenticated_client, monkeypatch):
    client, _ = authenticated_client
    monkeypatch.setattr(
        client.application.config["kernel_store"],
        "get_active",
        lambda: {"path": "/tmp/sing-box", "version": "test"},
    )

    response = client.post("/api/config/check", json={"config": []})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Config must be a JSON object"


def test_config_check_sends_valid_utf8_json_to_kernel(
        authenticated_client, monkeypatch):
    client, _ = authenticated_client
    app = client.application
    monkeypatch.setattr(
        app.config["kernel_store"],
        "get_active",
        lambda: {"path": "/tmp/sing-box", "version": "test"},
    )
    captured = {}

    def check_config(kernel_path, config_path):
        captured["kernel_path"] = str(kernel_path)
        captured["config"] = json.loads(config_path.read_text(encoding="utf-8"))
        return True, "configuration OK"

    monkeypatch.setattr(
        app.config["kernel_manager"], "check_config", check_config
    )
    config = {
        "inbounds": [],
        "outbounds": [{"type": "direct", "tag": "直连"}],
    }

    response = client.post("/api/config/check", json={"config": config})

    assert response.status_code == 200
    assert response.get_json() == {
        "valid": True,
        "message": "configuration OK",
    }
    assert captured["config"] == config



def test_quick_deploy_unexpected_error_is_returned_as_json(
        authenticated_client, monkeypatch):
    client, csrf = authenticated_client
    app = client.application
    monkeypatch.setattr(
        app.config["kernel_store"],
        "get_active",
        lambda: {"path": "/tmp/sing-box", "version": "1.13.14"},
    )

    def fail_deployment(*args, **kwargs):
        raise AttributeError("compatibility failure")

    monkeypatch.setattr(
        app.config["quick_deployment"], "deploy", fail_deployment
    )
    response = client.post(
        "/api/quick-deploy",
        headers={"X-CSRF-Token": csrf},
        json={"public_ipv4": "203.0.113.10"},
    )

    assert response.status_code == 500
    assert response.is_json
    assert response.get_json()["error"] == (
        "Quick deployment failed: compatibility failure"
    )
