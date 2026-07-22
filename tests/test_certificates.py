import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import src.certificates as certificates_module
from src.certificates import CertificateIssueError, LetsEncryptIssuer


def test_cloudflare_dns_issue_uses_ephemeral_credentials(tmp_path):
    observed = {}

    def runner(command, **kwargs):
        credential_path = Path(
            command[command.index("--dns-cloudflare-credentials") + 1]
        )
        observed["command"] = command
        observed["credential_path"] = credential_path
        observed["credential"] = credential_path.read_text("utf-8")
        if os.name != "nt":
            assert credential_path.stat().st_mode & 0o077 == 0
        config_dir = Path(command[command.index("--config-dir") + 1])
        live_dir = config_dir / "live" / "proxy.example.com"
        live_dir.mkdir(parents=True)
        (live_dir / "fullchain.pem").write_text("certificate", "utf-8")
        (live_dir / "privkey.pem").write_text("private key", "utf-8")
        return SimpleNamespace(returncode=0, stdout="issued", stderr="")

    def validator(directory, domain):
        assert domain == "proxy.example.com"
        return (
            str(Path(directory) / "fullchain.pem"),
            str(Path(directory) / "privkey.pem"),
        )

    issuer = LetsEncryptIssuer(
        tmp_path / "data",
        runner=runner,
        module_finder=lambda name: object(),
        executable_finder=lambda: "certbot-test",
        validator=validator,
        inspector=lambda path: {
            "issuer": "organizationName=Let's Encrypt, commonName=R10",
            "not_after": "Oct 20 00:00:00 2026 GMT",
            "serial_number": "01",
            "chain_certificates": 2,
            "sha256_fingerprint": "AA:BB",
        },
    )
    runtime_dir = tmp_path / "data" / "runtime"
    runtime_dir.mkdir(parents=True)
    stale_credential = runtime_dir / ".cloudflare-acme-stale.ini"
    stale_credential.write_text("old-secret", "utf-8")
    result = issuer.issue(
        "proxy.example.com", "admin@example.com", "one-shot-secret"
    )

    assert result["source"] == "letsencrypt"
    assert result["token_source"] == "form"
    assert result["dns_authenticator"] == "cloudflare-token"
    assert result["issuer"] == "organizationName=Let's Encrypt, commonName=R10"
    assert result["certificate_path"].endswith("fullchain.pem")
    assert "one-shot-secret" in observed["credential"]
    assert all("one-shot-secret" not in item for item in observed["command"])
    assert "--server" in observed["command"]
    assert (
        observed["command"][observed["command"].index("--server") + 1]
        == certificates_module.LE_PRODUCTION_DIRECTORY
    )
    receipt = Path(result["receipt_path"])
    assert receipt.is_file()
    assert "one-shot-secret" not in receipt.read_text("utf-8")
    assert not observed["credential_path"].exists()
    assert not stale_credential.exists()


def test_non_lets_encrypt_certificate_is_rejected(tmp_path):
    def runner(command, **kwargs):
        config_dir = Path(command[command.index("--config-dir") + 1])
        live_dir = config_dir / "live" / "proxy.example.com"
        live_dir.mkdir(parents=True)
        (live_dir / "fullchain.pem").write_text("certificate", "utf-8")
        (live_dir / "privkey.pem").write_text("private key", "utf-8")
        return SimpleNamespace(returncode=0, stdout="issued", stderr="")

    issuer = LetsEncryptIssuer(
        tmp_path / "data",
        runner=runner,
        module_finder=lambda name: object(),
        executable_finder=lambda: "certbot-test",
        validator=lambda directory, domain: (
            str(Path(directory) / "fullchain.pem"),
            str(Path(directory) / "privkey.pem"),
        ),
        inspector=lambda path: {
            "issuer": "organizationName=Cloudflare, Inc.",
            "not_after": "",
            "serial_number": "01",
            "chain_certificates": 2,
            "sha256_fingerprint": "AA:BB",
        },
    )

    with pytest.raises(CertificateIssueError, match="production Let's Encrypt"):
        issuer.issue(
            "proxy.example.com", "admin@example.com", "one-shot-secret"
        )


def test_certbot_entrypoint_is_found_beside_active_python(tmp_path, monkeypatch):
    executable_name = "certbot.exe" if os.name == "nt" else "certbot"
    python_name = "python.exe" if os.name == "nt" else "python"
    fake_python = tmp_path / "venv" / "bin" / python_name
    fake_python.parent.mkdir(parents=True)
    fake_python.write_text("", "utf-8")
    certbot = fake_python.parent / executable_name
    certbot.write_text("", "utf-8")
    monkeypatch.setattr(certificates_module.sys, "executable", str(fake_python))

    assert LetsEncryptIssuer._find_certbot() == str(certbot)


def test_certificate_error_never_returns_cloudflare_token(tmp_path):
    observed = {}

    def runner(command, **kwargs):
        observed["credential_path"] = Path(
            command[command.index("--dns-cloudflare-credentials") + 1]
        )
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="provider rejected one-shot-secret",
        )

    issuer = LetsEncryptIssuer(
        tmp_path / "data",
        runner=runner,
        module_finder=lambda name: object(),
        executable_finder=lambda: "certbot-test",
    )

    with pytest.raises(CertificateIssueError) as exc_info:
        issuer.issue(
            "proxy.example.com", "admin@example.com", "one-shot-secret"
        )

    assert "one-shot-secret" not in str(exc_info.value)
    assert "***" in str(exc_info.value)
    assert not observed["credential_path"].exists()


@pytest.mark.parametrize("email", ["", "invalid", "a@b", "a b@example.com"])
def test_certificate_issue_rejects_invalid_email_without_running_certbot(
        tmp_path, email):
    issuer = LetsEncryptIssuer(
        tmp_path / "data",
        runner=lambda *args, **kwargs: pytest.fail("Certbot must not run"),
        module_finder=lambda name: object(),
        executable_finder=lambda: "certbot-test",
    )

    with pytest.raises(CertificateIssueError, match="valid Let's Encrypt email"):
        issuer.issue("proxy.example.com", email, "token")
