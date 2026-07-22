from pathlib import Path

from src.analyzer import analyze_inbounds
from src.config import AppConfig
from src.config_mgr import ConfigManager
from src.wizard import DeploymentWizard


def _vmess_params():
    return {
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
        "cloudflare_preferred_ip": "104.16.0.1",
        "preferred_endpoint": "domain",
        "cloudflare_proxied": True,
        "ws_enabled": True,
        "ws_path": "/edge",
        "tls_enabled": True,
        "tls_server_name": "proxy.example.com",
        "tls_certificate_path": "/cert/fullchain.pem",
        "tls_key_path": "/cert/key.pem",
    }


def test_split_deployment_is_saved_together_and_analyzed_per_inbound(tmp_path):
    app_config = AppConfig(tmp_path / "settings.json", project_root=tmp_path)
    config_mgr = ConfigManager(
        tmp_path / "sing-box.json", tmp_path / "backups"
    )
    wizard = DeploymentWizard(config_mgr, None, None, app_config)

    result = wizard.deploy(
        "vmess",
        _vmess_params(),
        Path("unused-sing-box"),
        config_mgr.config_path,
        restart=False,
    )

    assert result["success"] is True
    assert [item["tag"] for item in result["inbounds"]] == [
        "vmess-edge-direct",
        "vmess-edge-cdn",
    ]
    stored = config_mgr.read()["inbounds"]
    assert stored == result["inbounds"]
    assert "tls" not in stored[0]
    assert "transport" not in stored[0]
    assert stored[1]["tls"]["enabled"] is True
    assert stored[1]["transport"]["type"] == "ws"
    assert "cloudflare_preferred_ip" not in str(stored)

    analyzed = analyze_inbounds(
        config_mgr.read(),
        endpoint_profile=app_config.public_endpoints,
        endpoint_profiles=app_config.inbound_endpoint_profiles,
    )
    direct, cdn = analyzed
    assert [option["kind"] for option in direct["client_options"]] == [
        "ipv4", "ipv6"
    ]
    assert [option["kind"] for option in cdn["client_options"]] == ["domain"]
    assert cdn["client_options"][0]["address"] == "104.16.0.1"
    assert cdn["client_options"][0]["config_snippet"]["server"] == "104.16.0.1"
    assert cdn["client_options"][0]["config_snippet"]["tls"]["server_name"] == (
        "proxy.example.com"
    )
    assert all(
        "tls" not in option["config_snippet"]
        for option in direct["client_options"]
    )
    assert "tls" in cdn["client_options"][0]["config_snippet"]


def test_split_deployment_rejects_same_direct_and_cdn_port(tmp_path):
    config_mgr = ConfigManager(
        tmp_path / "sing-box.json", tmp_path / "backups"
    )
    wizard = DeploymentWizard(config_mgr, None, None)
    params = _vmess_params()
    params["listen_port"] = 443

    conflicts = wizard.check_deployment_conflicts("vmess", params)

    assert conflicts == ["Port 443 is duplicated in this deployment"]
