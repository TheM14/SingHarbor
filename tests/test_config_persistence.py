from src.config import AppConfig


def test_default_settings_are_loaded_and_saved_atomically(tmp_path):
    first = AppConfig(project_root=tmp_path)
    first.ensure_dirs()
    secret = first.secret_key
    first.set_public_endpoints({
        "public_ipv4": "203.0.113.10",
        "public_ipv6": "2001:db8::10",
        "public_domain": "proxy.example.com",
        "preferred_endpoint": "domain",
        "cloudflare_proxied": True,
    }, "0123456789abcdef0123456789abcdef")

    second = AppConfig(project_root=tmp_path)
    assert second.secret_key == secret
    assert second.public_endpoints["public_domain"] == "proxy.example.com"
    assert second.cloudflare_zone_id == "0123456789abcdef0123456789abcdef"
    assert not (tmp_path / "data" / ".settings.json.tmp").exists()
