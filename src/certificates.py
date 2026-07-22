"""Public certificate issuance for direct TLS inbounds."""

from __future__ import annotations

import importlib.util
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .cloudflare import get_cloudflare_token
from .endpoints import normalize_domain
from .utils import json_save_atomic


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LE_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"


class CertificateIssueError(RuntimeError):
    """A sanitized certificate issuance error safe to return to the admin."""


class LetsEncryptIssuer:
    """Issue a public certificate using Certbot's Cloudflare DNS plugin.

    The Cloudflare token is written only to a mode-0600 temporary file because
    Certbot's plugin requires a credentials path.  The file is overwritten and
    removed immediately after the subprocess exits.  It is never included in
    command arguments, settings, API responses, or persistent renewal files.
    """

    def __init__(
        self,
        data_dir: Path,
        *,
        runner: Callable | None = None,
        module_finder: Callable[[str], object | None] | None = None,
        executable_finder: Callable[[], str | None] | None = None,
        validator: Callable[[str, str], tuple[str, str]] | None = None,
        inspector: Callable[[str], dict] | None = None,
        timeout: int = 300,
    ):
        self.data_dir = Path(data_dir)
        self.runner = runner or subprocess.run
        self.module_finder = module_finder or importlib.util.find_spec
        self.executable_finder = executable_finder or self._find_certbot
        self.validator = validator or self._validate_pair
        self.inspector = inspector or self._inspect_certificate
        self.timeout = timeout

    @staticmethod
    def _find_certbot() -> str | None:
        executable_name = "certbot.exe" if os.name == "nt" else "certbot"
        # Do not resolve the Python symlink: in a POSIX venv the Certbot entry
        # point is beside ``.venv/bin/python``, not beside its /usr/bin target.
        beside_python = Path(sys.executable).absolute().parent / executable_name
        if beside_python.is_file():
            return str(beside_python)
        return shutil.which("certbot")

    @staticmethod
    def _validate_pair(directory: str, domain: str) -> tuple[str, str]:
        # Imported lazily to avoid coupling the certificate runner to the
        # deployment planner at module-import time.
        from .quick_deploy import find_certificate_pair

        return find_certificate_pair(directory, domain)

    @staticmethod
    def _inspect_certificate(certificate_path: str) -> dict:
        """Return safe identity details for the issued leaf certificate."""
        path = Path(certificate_path)
        decoded = ssl._ssl._test_decode_cert(str(path))
        issuer_parts = [
            f"{key}={value}"
            for relative_name in decoded.get("issuer", ())
            for key, value in relative_name
        ]
        pem = path.read_text("utf-8")
        certificate_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem,
            re.DOTALL,
        )
        if not certificate_blocks:
            raise ValueError("certificate file does not contain a PEM certificate")
        der = ssl.PEM_cert_to_DER_cert(certificate_blocks[0])
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        return {
            "issuer": ", ".join(issuer_parts),
            "not_after": str(decoded.get("notAfter", "")),
            "serial_number": str(decoded.get("serialNumber", "")),
            "chain_certificates": len(certificate_blocks),
            "sha256_fingerprint": ":".join(
                fingerprint[index:index + 2]
                for index in range(0, len(fingerprint), 2)
            ),
        }

    @staticmethod
    def _erase_credentials(path: Path, token: str) -> None:
        """Best-effort overwrite followed by removal of the exact temp file."""
        try:
            if path.is_file():
                size = max(path.stat().st_size, len(token.encode("utf-8")))
                with path.open("r+b", buffering=0) as handle:
                    handle.write(b"\0" * size)
                    handle.flush()
                    os.fsync(handle.fileno())
        except OSError:
            pass
        finally:
            path.unlink(missing_ok=True)

    def issue(
        self,
        domain: str,
        email: str,
        api_token: str = "",
        *,
        staging: bool = False,
    ) -> dict:
        try:
            normalized_domain = normalize_domain(domain)
        except ValueError as exc:
            raise CertificateIssueError(f"domain: {exc}") from exc
        if not normalized_domain:
            raise CertificateIssueError("domain: required")

        email = str(email or "").strip()
        if not _EMAIL.fullmatch(email):
            raise CertificateIssueError("email: a valid Let's Encrypt email is required")

        supplied_token = str(api_token or "").strip()
        token = get_cloudflare_token(supplied_token)
        if not token:
            raise CertificateIssueError(
                "Cloudflare API token is required for the DNS-01 challenge"
            )
        if "\n" in token or "\r" in token:
            raise CertificateIssueError("Cloudflare API token contains invalid characters")
        if self.module_finder("certbot") is None:
            raise CertificateIssueError(
                "Certbot is not installed; run python -m pip install -r requirements.txt"
            )
        if self.module_finder("certbot_dns_cloudflare") is None:
            raise CertificateIssueError(
                "certbot-dns-cloudflare is not installed; run python -m pip install "
                "-r requirements.txt"
            )
        certbot_executable = self.executable_finder()
        if not certbot_executable:
            raise CertificateIssueError(
                "Certbot executable was not found in the active Python environment"
            )

        root = self.data_dir / "letsencrypt"
        config_dir = root / "config"
        work_dir = root / "work"
        logs_dir = root / "logs"
        runtime_dir = self.data_dir / "runtime"
        for directory in (root, config_dir, work_dir, logs_dir, runtime_dir):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700)
            except OSError:
                pass
        for stale_path in runtime_dir.glob(".cloudflare-acme-*.ini"):
            if stale_path.is_file():
                self._erase_credentials(stale_path, "")

        descriptor, credential_name = tempfile.mkstemp(
            prefix=".cloudflare-acme-", suffix=".ini", dir=runtime_dir
        )
        credential_path = Path(credential_name)
        try:
            try:
                os.chmod(credential_path, 0o600)
            except OSError:
                pass
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(f"dns_cloudflare_api_token = {token}\n")

            command = [
                certbot_executable,
                "certonly",
                "--authenticator",
                "dns-cloudflare",
                "--dns-cloudflare-credentials",
                str(credential_path),
                "--dns-cloudflare-propagation-seconds",
                "30",
                "--preferred-challenges",
                "dns-01",
                "--non-interactive",
                "--agree-tos",
                "--email",
                email,
                "--domain",
                normalized_domain,
                "--cert-name",
                normalized_domain,
                "--server",
                LE_PRODUCTION_DIRECTORY,
                "--key-type",
                "ecdsa",
                "--keep-until-expiring",
                "--config-dir",
                str(config_dir),
                "--work-dir",
                str(work_dir),
                "--logs-dir",
                str(logs_dir),
            ]
            if staging:
                command.append("--staging")

            try:
                completed = self.runner(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise CertificateIssueError(
                    "Let's Encrypt issuance timed out; check DNS and Cloudflare permissions"
                ) from exc
            except OSError as exc:
                raise CertificateIssueError(f"Unable to start Certbot: {exc}") from exc

            output = "\n".join(
                part.strip() for part in (completed.stdout, completed.stderr)
                if part and part.strip()
            ).replace(token, "***")
            if completed.returncode != 0:
                detail = output[-4000:] or f"Certbot exited with code {completed.returncode}"
                raise CertificateIssueError(f"Let's Encrypt issuance failed: {detail}")

            live_dir = config_dir / "live" / normalized_domain
            try:
                certificate_path, key_path = self.validator(
                    str(live_dir), normalized_domain
                )
            except ValueError as exc:
                raise CertificateIssueError(
                    f"Let's Encrypt returned an unusable certificate: {exc}"
                ) from exc
            try:
                certificate_details = self.inspector(certificate_path)
            except (OSError, ValueError, ssl.SSLError) as exc:
                raise CertificateIssueError(
                    f"Unable to inspect the issued certificate: {exc}"
                ) from exc
            issuer = str(certificate_details.get("issuer", ""))
            if not staging and "let's encrypt" not in issuer.lower():
                raise CertificateIssueError(
                    "Certbot did not return a production Let's Encrypt certificate; "
                    f"reported issuer: {issuer or 'unknown'}"
                )
            if not staging and int(
                certificate_details.get("chain_certificates", 0)
            ) < 2:
                raise CertificateIssueError(
                    "Let's Encrypt fullchain.pem does not contain an intermediate "
                    "certificate"
                )

            result = {
                "source": "letsencrypt",
                "domain": normalized_domain,
                "certificate_path": certificate_path,
                "key_path": key_path,
                "config_dir": str(config_dir),
                "acme_server": LE_PRODUCTION_DIRECTORY,
                "dns_authenticator": "cloudflare-token",
                "token_source": "form" if supplied_token else "environment",
                "verified_at": datetime.now(timezone.utc).isoformat(),
                **certificate_details,
            }
            receipt_path = root / "last-issuance.json"
            json_save_atomic(result, receipt_path)
            try:
                receipt_path.chmod(0o600)
            except OSError:
                pass
            result["receipt_path"] = str(receipt_path)
            return result
        finally:
            # If os.fdopen failed, close the still-open descriptor first.
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._erase_credentials(credential_path, token)
