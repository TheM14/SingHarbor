"""One-click multi-protocol deployment planning and execution."""

from __future__ import annotations

import copy
import re
import ssl
import time
from pathlib import Path

from .endpoints import (
    as_bool,
    build_client_bundle,
    normalize_domain,
    normalize_ip,
    normalize_ip_literal,
)
from .certificates import CertificateIssueError
from .protocols import get_server_protocols
from .utils import generate_password, generate_uuid, json_save_atomic


NATIVE_DIRECT_PROTOCOLS = ("shadowsocks", "vmess", "vless")
TLS_DIRECT_PROTOCOLS = ("trojan", "hysteria2", "tuic", "hysteria", "anytls")
CDN_PROTOCOLS = ("vmess", "vless", "trojan")

DIRECT_PORTS = {
    "shadowsocks": 10001,
    "vmess": 10002,
    "vless": 10003,
    "trojan": 10004,
    "hysteria2": 10005,
    "tuic": 10006,
    "hysteria": 10007,
    "anytls": 10008,
}
# One-click deployment reserves 443 for Nginx-hosted WebUIs.  Manual
# deployments may still choose 443 explicitly when Nginx is not using it.
CDN_PORTS = (2053, 2083, 2087, 2096, 8443)
NO_NEW_INBOUNDS = "No new protocol inbounds can be deployed with these inputs."

MANUAL_ONLY_REASONS = {
    "shadowtls": (
        "ShadowTLS needs a separate TLS handshake server, which cannot be "
        "safely inferred from the quick-deploy inputs."
    ),
    "naive": (
        "Naive needs a dedicated directly reachable TLS hostname/routing "
        "decision and is not compatible with the orange-cloud WS plan."
    ),
}


def _version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", str(value or ""))
    return tuple(int(item) for item in numbers[:3]) or (0,)


def _version_supported(current: str, minimum: str) -> bool:
    current_parts = _version_tuple(current)
    minimum_parts = _version_tuple(minimum)
    width = max(len(current_parts), len(minimum_parts))
    return current_parts + (0,) * (width - len(current_parts)) >= (
        minimum_parts + (0,) * (width - len(minimum_parts))
    )


def _dnsname_matches(pattern: str, hostname: str) -> bool:
    """Match an ASCII hostname against an RFC 6125-style DNS pattern."""
    pattern = str(pattern or "").strip().rstrip(".").lower()
    hostname = str(hostname or "").strip().rstrip(".").lower()
    if not pattern or not hostname:
        return False
    if "*" not in pattern:
        return pattern == hostname

    pattern_labels = pattern.split(".")
    hostname_labels = hostname.split(".")
    return (
        pattern_labels[0] == "*"
        and all("*" not in label for label in pattern_labels[1:])
        and len(pattern_labels) == len(hostname_labels)
        and pattern_labels[1:] == hostname_labels[1:]
    )


def _match_certificate_hostname(certificate: dict, domain: str) -> None:
    """Validate a decoded certificate hostname without ssl.match_hostname.

    ``ssl.match_hostname`` was removed in Python 3.12.  Certificate discovery
    only needs DNS-name matching, so keep the small compatible subset here.
    Subject Alternative Names take precedence; the common name is considered
    only for older certificates that do not contain DNS SAN entries.
    """
    dns_names = [
        str(value)
        for kind, value in certificate.get("subjectAltName", ())
        if str(kind).upper() == "DNS"
    ]
    if not dns_names:
        for relative_distinguished_name in certificate.get("subject", ()):
            for key, value in relative_distinguished_name:
                if str(key).lower() == "commonname":
                    dns_names.append(str(value))

    if any(_dnsname_matches(name, domain) for name in dns_names):
        return

    presented = ", ".join(repr(name) for name in dns_names) or "no DNS names"
    raise ssl.CertificateError(
        f"hostname {domain!r} does not match certificate names: {presented}"
    )


def find_certificate_pair(directory: str, domain: str) -> tuple[str, str]:
    """Find and validate a certificate/private-key pair in a directory."""
    raw = str(directory or "").strip()
    if not raw:
        raise ValueError("certificate_directory: required")
    cert_dir = Path(raw).expanduser().absolute()
    if not cert_dir.is_dir():
        raise ValueError("certificate_directory: directory does not exist")

    common_pairs = (
        (f"{domain}.pem", f"{domain}.key"),
        ("fullchain.pem", "privkey.pem"),
        ("origin-cert.pem", "origin-key.pem"),
        ("cert.pem", "key.pem"),
        ("certificate.pem", "private.key"),
    )
    selected = None
    for cert_name, key_name in common_pairs:
        cert_path = cert_dir / cert_name
        key_path = cert_dir / key_name
        if cert_path.is_file() and key_path.is_file():
            selected = (cert_path, key_path)
            break

    if selected is None:
        cert_files = sorted({
            item for pattern in ("*.pem", "*.crt")
            for item in cert_dir.glob(pattern)
            if item.is_file() and not any(
                marker in item.name.lower() for marker in ("key", "priv")
            )
        })
        key_files = sorted({
            item for pattern in ("*.key", "*privkey*.pem", "*key*.pem")
            for item in cert_dir.glob(pattern) if item.is_file()
        })
        if len(cert_files) == 1 and len(key_files) == 1:
            selected = (cert_files[0], key_files[0])

    if selected is None:
        raise ValueError(
            "certificate_directory: could not identify one certificate/key "
            "pair; use fullchain.pem + privkey.pem, origin-cert.pem + "
            "origin-key.pem, cert.pem + key.pem, or <domain>.pem + <domain>.key"
        )

    cert_path, key_path = selected
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        certificate = ssl._ssl._test_decode_cert(str(cert_path))
        _match_certificate_hostname(certificate, domain)
    except ssl.CertificateError as exc:
        raise ValueError(
            f"certificate_directory: certificate does not cover {domain}: {exc}"
        ) from exc
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(
            f"certificate_directory: certificate/private key cannot be loaded: {exc}"
        ) from exc
    return str(cert_path), str(key_path)


class QuickDeploymentService:
    """Build and atomically deploy every protocol supported by simple inputs."""

    def __init__(self, config_mgr, process_mgr=None, app_config=None,
                 certificate_issuer=None):
        self.config_mgr = config_mgr
        self.process_mgr = process_mgr
        self.app_config = app_config
        self.certificate_issuer = certificate_issuer

    @staticmethod
    def _base_params(protocol_type: str, proto) -> dict:
        params = {
            "listen": "::",
            "user_name": "user",
            "username": "user",
        }
        if protocol_type == "shadowsocks":
            params.update({
                "method": "2022-blake3-aes-128-gcm",
                "network": "tcp,udp",
            })
        for field in proto.fields:
            if field.name in params or field.name in {"listen_port", "tag"}:
                continue
            if field.field_type == "uuid":
                params[field.name] = generate_uuid()
            elif field.field_type == "password":
                if protocol_type == "shadowsocks" and field.name == "password":
                    params[field.name] = proto.generate_password_for_method(
                        params["method"]
                    )
                else:
                    params[field.name] = generate_password()
            elif field.default is not None:
                params[field.name] = copy.deepcopy(field.default)
        return params

    @staticmethod
    def _direct_profile(ipv4: str, ipv6: str) -> dict:
        return {
            "public_ipv4": ipv4,
            "public_ipv6": ipv6,
            "public_domain": "",
            "cloudflare_preferred_ip": "",
            "preferred_endpoint": "ipv4" if ipv4 else "ipv6",
            "cloudflare_proxied": False,
        }

    @staticmethod
    def _cdn_profile(domain: str, cloudflare_preferred_ip: str = "") -> dict:
        return {
            "public_ipv4": "",
            "public_ipv6": "",
            "public_domain": domain,
            "cloudflare_preferred_ip": cloudflare_preferred_ip,
            "preferred_endpoint": "domain",
            "cloudflare_proxied": True,
        }

    @staticmethod
    def _allocate_direct_port(preferred: int, used_ports: set[int]) -> int | None:
        for port in range(preferred, 65536):
            if port not in used_ports:
                used_ports.add(port)
                return port
        for port in range(10000, preferred):
            if port not in used_ports:
                used_ports.add(port)
                return port
        return None

    @staticmethod
    def _allocate_cdn_port(used_ports: set[int]) -> int | None:
        for port in CDN_PORTS:
            if port not in used_ports:
                used_ports.add(port)
                return port
        return None

    @staticmethod
    def _normalize_inputs(
        values: dict,
        issued_certificate: dict | None = None,
    ) -> tuple[dict, list[str], list[str]]:
        errors = []
        warnings = []
        try:
            ipv4 = normalize_ip(values.get("public_ipv4", ""), 4)
        except ValueError as exc:
            ipv4 = ""
            errors.append(f"public_ipv4: {exc}")
        try:
            ipv6 = normalize_ip(values.get("public_ipv6", ""), 6)
        except ValueError as exc:
            ipv6 = ""
            errors.append(f"public_ipv6: {exc}")
        try:
            domain = normalize_domain(values.get("public_domain", ""))
        except ValueError as exc:
            domain = ""
            errors.append(f"public_domain: {exc}")
        try:
            cloudflare_preferred_ip = normalize_ip_literal(
                values.get("cloudflare_preferred_ip", "")
            )
        except ValueError as exc:
            cloudflare_preferred_ip = ""
            errors.append(f"cloudflare_preferred_ip: {exc}")

        certificate_directory = str(
            values.get("certificate_directory", "") or ""
        ).strip()
        certificate_path = ""
        key_path = ""
        if domain and certificate_directory and not errors:
            try:
                certificate_path, key_path = find_certificate_pair(
                    certificate_directory, domain
                )
            except ValueError as exc:
                errors.append(str(exc))
        elif domain and not certificate_directory and not issued_certificate:
            warnings.append(
                "Domain/CDN and TLS-only protocols were skipped because the "
                "certificate directory is empty."
            )
        elif certificate_directory and not domain:
            warnings.append(
                "The certificate directory was ignored because the domain is empty."
            )

        issued_certificate_path = str(
            (issued_certificate or {}).get("certificate_path", "")
        ).strip()
        issued_key_path = str(
            (issued_certificate or {}).get("key_path", "")
        ).strip()
        direct_certificate_path = issued_certificate_path or certificate_path
        direct_key_path = issued_key_path or key_path
        # A public Let's Encrypt certificate can also serve the CDN endpoint
        # when no separate Origin CA/public certificate directory was supplied.
        cdn_certificate_path = certificate_path or issued_certificate_path
        cdn_key_path = key_path or issued_key_path
        direct_tls_ready = bool(
            domain and direct_certificate_path and direct_key_path
        )
        cdn_tls_ready = bool(domain and cdn_certificate_path and cdn_key_path)
        tls_ready = direct_tls_ready or cdn_tls_ready
        if not ipv4 and not ipv6 and not tls_ready and not errors:
            errors.append(
                "Provide at least one valid IPv4/IPv6 address, or a domain "
                "with a valid certificate directory."
            )
        return {
            "public_ipv4": ipv4,
            "public_ipv6": ipv6,
            "public_domain": domain,
            "cloudflare_preferred_ip": cloudflare_preferred_ip,
            "certificate_directory": certificate_directory,
            "certificate_path": cdn_certificate_path,
            "key_path": cdn_key_path,
            "direct_certificate_path": direct_certificate_path,
            "direct_key_path": direct_key_path,
            "direct_tls_ready": direct_tls_ready,
            "cdn_tls_ready": cdn_tls_ready,
            "tls_ready": tls_ready,
        }, errors, warnings

    def build_plan(self, values: dict, kernel_version: str = "",
                   issued_certificate: dict | None = None) -> dict:
        inputs, errors, warnings = self._normalize_inputs(
            values, issued_certificate
        )
        result = {
            "inputs": inputs,
            "inbounds": [],
            "profiles": {},
            "protocols": [],
            "warnings": warnings,
            "errors": errors,
        }
        if errors:
            return result

        protocols = get_server_protocols()
        existing = self.config_mgr.get_inbounds()
        used_ports = {
            int(item.get("listen_port", 0))
            for item in existing if item.get("listen_port")
        }
        existing_tags = {
            str(item.get("tag", "")) for item in existing if item.get("tag")
        }
        existing_quick_types = {
            tag.split("-")[1]
            for tag in existing_tags
            if tag.startswith("quick-") and len(tag.split("-")) >= 3
        }

        has_ip = bool(inputs["public_ipv4"] or inputs["public_ipv6"])
        direct_tls_ready = inputs["direct_tls_ready"]
        cdn_tls_ready = inputs["cdn_tls_ready"]
        base_params = {
            ptype: self._base_params(ptype, proto)
            for ptype, proto in protocols.items()
        }
        planned_by_type: dict[str, list[dict]] = {
            ptype: [] for ptype in protocols
        }
        reasons: dict[str, list[str]] = {ptype: [] for ptype in protocols}

        for ptype, reason in MANUAL_ONLY_REASONS.items():
            if ptype in reasons:
                reasons[ptype].append(reason)

        for ptype, proto in protocols.items():
            if kernel_version and not _version_supported(
                kernel_version, proto.min_version
            ):
                reasons[ptype].append(
                    f"Requires sing-box {proto.min_version} or newer."
                )
            if ptype in existing_quick_types:
                reasons[ptype].append(
                    "A quick-deploy inbound for this protocol already exists."
                )

        blocked = {
            ptype for ptype, items in reasons.items() if items
        }
        direct_profile = self._direct_profile(
            inputs["public_ipv4"], inputs["public_ipv6"]
        )
        direct_tls_config = {
            "enabled": True,
            "server_name": inputs["public_domain"],
            "certificate_path": inputs["direct_certificate_path"],
            "key_path": inputs["direct_key_path"],
        }

        def add_entry(ptype: str, role: str, port: int | None,
                      profile: dict, connection: dict | None = None):
            if ptype in blocked:
                return
            if port is None:
                reasons[ptype].append(f"No free port is available for {role}.")
                blocked.add(ptype)
                return
            proto = protocols[ptype]
            params = copy.deepcopy(base_params[ptype])
            params.update({
                "listen_port": port,
                "tag": f"quick-{ptype}-{role}",
            })
            if connection:
                params.update(copy.deepcopy(connection))
            validation_errors = proto.validate_params(params)
            if validation_errors:
                reasons[ptype].append("; ".join(validation_errors))
                blocked.add(ptype)
                return
            inbound = proto.generate_config(params)
            entry = {
                "protocol": ptype,
                "name": proto.name,
                "role": role,
                "inbound": inbound,
                "profile": copy.deepcopy(profile),
            }
            result["inbounds"].append(inbound)
            result["profiles"][inbound["tag"]] = copy.deepcopy(profile)
            planned_by_type[ptype].append(entry)

        if has_ip:
            for ptype in NATIVE_DIRECT_PROTOCOLS:
                if ptype in blocked:
                    continue
                add_entry(
                    ptype,
                    "direct",
                    self._allocate_direct_port(DIRECT_PORTS[ptype], used_ports),
                    direct_profile,
                )
        else:
            for ptype in NATIVE_DIRECT_PROTOCOLS:
                reasons[ptype].append("Direct IP deployment skipped: no IP address.")

        if has_ip and direct_tls_ready:
            for ptype in TLS_DIRECT_PROTOCOLS:
                if ptype in blocked:
                    continue
                add_entry(
                    ptype,
                    "tls-direct",
                    self._allocate_direct_port(DIRECT_PORTS[ptype], used_ports),
                    direct_profile,
                    {"tls": direct_tls_config},
                )
        else:
            missing = "no IP address" if not has_ip else "domain/certificate incomplete"
            for ptype in TLS_DIRECT_PROTOCOLS:
                reasons[ptype].append(f"TLS direct deployment skipped: {missing}.")

        if cdn_tls_ready:
            cdn_profile = self._cdn_profile(
                inputs["public_domain"], inputs["cloudflare_preferred_ip"]
            )
            for ptype in CDN_PROTOCOLS:
                if ptype in blocked:
                    continue
                add_entry(
                    ptype,
                    "cdn",
                    self._allocate_cdn_port(used_ports),
                    cdn_profile,
                    {
                        "ws_enabled": True,
                        "ws_path": f"/{ptype}",
                        "tls_enabled": True,
                        "tls_server_name": inputs["public_domain"],
                        "tls_certificate_path": inputs["certificate_path"],
                        "tls_key_path": inputs["key_path"],
                    },
                )
        else:
            for ptype in CDN_PROTOCOLS:
                reasons[ptype].append(
                    "Cloudflare domain deployment skipped: domain/certificate incomplete."
                )

        # If an entry failed after another role was already planned, remove the
        # partial protocol so credentials and behavior remain predictable.
        if blocked:
            result["inbounds"] = [
                item for item in result["inbounds"]
                if item.get("type") not in blocked
            ]
            result["profiles"] = {
                tag: profile for tag, profile in result["profiles"].items()
                if not any(tag.startswith(f"quick-{ptype}-") for ptype in blocked)
            }
            for ptype in blocked:
                planned_by_type[ptype] = []

        for ptype, proto in protocols.items():
            entries = planned_by_type[ptype]
            variants = []
            for entry in entries:
                bundle = build_client_bundle(
                    proto, entry["inbound"], entry["profile"]
                )
                for variant in bundle.get("variants", []):
                    variants.append({"role": entry["role"], **variant})
            result["protocols"].append({
                "type": ptype,
                "name": proto.name,
                "status": "planned" if entries else "skipped",
                "roles": [entry["role"] for entry in entries],
                "variants": variants,
                "reasons": reasons[ptype],
            })

        if not result["inbounds"]:
            result["errors"].append(NO_NEW_INBOUNDS)
        return result

    def _issue_direct_certificate(self, values: dict) -> dict | None:
        if not as_bool(values.get("lets_encrypt_enabled", False)):
            return None
        if self.certificate_issuer is None:
            raise CertificateIssueError(
                "Let's Encrypt certificate service is not configured"
            )
        try:
            domain = normalize_domain(values.get("public_domain", ""))
            ipv4 = normalize_ip(values.get("public_ipv4", ""), 4)
            ipv6 = normalize_ip(values.get("public_ipv6", ""), 6)
            normalize_ip_literal(values.get("cloudflare_preferred_ip", ""))
        except ValueError as exc:
            raise CertificateIssueError(f"Let's Encrypt input: {exc}") from exc
        if not domain:
            raise CertificateIssueError(
                "A public domain is required for Let's Encrypt"
            )
        if not ipv4 and not ipv6:
            raise CertificateIssueError(
                "A public IPv4 or IPv6 address is required for TLS Direct"
            )
        certificate_directory = str(
            values.get("certificate_directory", "") or ""
        ).strip()
        if certificate_directory:
            try:
                find_certificate_pair(certificate_directory, domain)
            except ValueError as exc:
                raise CertificateIssueError(str(exc)) from exc
        return self.certificate_issuer.issue(
            domain,
            values.get("lets_encrypt_email", ""),
            values.get("cloudflare_api_token", ""),
        )

    def _is_direct_tls_inbound(self, inbound: dict) -> bool:
        """Identify native TLS Direct independently of optional metadata."""
        if inbound.get("type") not in TLS_DIRECT_PROTOCOLS:
            return False
        tls = inbound.get("tls")
        if not isinstance(tls, dict) or tls.get("enabled") is False:
            return False
        profiles = (
            self.app_config.inbound_endpoint_profiles
            if self.app_config else {}
        )
        tag = str(inbound.get("tag", ""))
        profile = profiles.get(tag, {})
        transport_type = str(
            (inbound.get("transport") or {}).get("type", "")
        ).lower()
        # Trojan is the only member that can also be a Cloudflare WebSocket
        # inbound.  Preserve those CDN listeners and their Origin CA cert.
        is_cdn = bool(
            tag.endswith("-cdn")
            or profile.get("cloudflare_proxied")
            or transport_type in {"ws", "httpupgrade", "grpc"}
        )
        return not is_cdn

    def _take_over_direct_tls(self, config: dict, certificate: dict) -> list[str]:
        """Point every existing native TLS Direct inbound at the public cert."""
        if not certificate:
            return []
        updated = []
        for inbound in config.get("inbounds", []):
            if not self._is_direct_tls_inbound(inbound):
                continue
            tag = str(inbound.get("tag", ""))
            tls = inbound.get("tls")
            tls.update({
                "enabled": True,
                "server_name": certificate["domain"],
                "certificate_path": certificate["certificate_path"],
                "key_path": certificate["key_path"],
            })
            updated.append(tag)
        return updated

    def deploy(self, values: dict, kernel_path: Path, config_path: Path,
               kernel_version: str = "", restart: bool = True) -> dict:
        try:
            issued_certificate = self._issue_direct_certificate(values)
        except CertificateIssueError as exc:
            return {
                "success": False,
                "message": str(exc),
                "inputs": {},
                "inbounds": [],
                "profiles": {},
                "protocols": [],
                "warnings": [],
                "errors": [str(exc)],
            }

        plan = self.build_plan(
            values, kernel_version, issued_certificate=issued_certificate
        )
        config = self.config_mgr.read()
        updated_tls_tags = self._take_over_direct_tls(
            config, issued_certificate or {}
        )
        blocking_errors = [
            error for error in plan["errors"]
            if error != NO_NEW_INBOUNDS
        ]
        if blocking_errors:
            return {
                "success": False,
                "message": "; ".join(blocking_errors),
                **plan,
            }
        if not plan["inbounds"] and not updated_tls_tags:
            return {
                "success": False,
                "message": "; ".join(plan["errors"]),
                **plan,
            }
        if updated_tls_tags:
            plan["errors"] = [
                error for error in plan["errors"]
                if error != NO_NEW_INBOUNDS
            ]

        config.setdefault("inbounds", []).extend(plan["inbounds"])
        configured_tls_tags = []
        if issued_certificate:
            expected_certificate = issued_certificate["certificate_path"]
            expected_key = issued_certificate["key_path"]
            for inbound in config.get("inbounds", []):
                if not self._is_direct_tls_inbound(inbound):
                    continue
                tls = inbound.get("tls") or {}
                if (
                    tls.get("certificate_path") == expected_certificate
                    and tls.get("key_path") == expected_key
                ):
                    configured_tls_tags.append(str(inbound.get("tag", "")))
            if not configured_tls_tags:
                return {
                    "success": False,
                    "message": (
                        "Let's Encrypt succeeded, but no TLS Direct inbound "
                        "accepted the issued certificate. Configuration was not saved."
                    ),
                    **plan,
                }

        ok, message = self.config_mgr.set_config(config, kernel_path)
        if not ok:
            return {
                "success": False,
                "message": f"Failed to save quick deployment: {message}",
                **plan,
            }

        if issued_certificate:
            saved_by_tag = {
                str(item.get("tag", "")): item
                for item in self.config_mgr.read().get("inbounds", [])
            }
            mismatched = []
            for tag in configured_tls_tags:
                tls = (saved_by_tag.get(tag, {}).get("tls") or {})
                if (
                    tls.get("certificate_path")
                    != issued_certificate["certificate_path"]
                    or tls.get("key_path") != issued_certificate["key_path"]
                ):
                    mismatched.append(tag)
            if mismatched:
                return {
                    "success": False,
                    "message": (
                        "Saved configuration did not retain the Let's Encrypt "
                        f"certificate for: {', '.join(mismatched)}"
                    ),
                    **plan,
                }
            receipt_path = str(issued_certificate.get("receipt_path", "")).strip()
            if receipt_path:
                try:
                    receipt = {
                        **issued_certificate,
                        "updated_inbounds": updated_tls_tags,
                        "configured_inbounds": configured_tls_tags,
                    }
                    json_save_atomic(receipt, Path(receipt_path))
                    try:
                        Path(receipt_path).chmod(0o600)
                    except OSError:
                        pass
                except OSError as exc:
                    plan["warnings"].append(
                        "Certificate was configured, but the verification "
                        f"receipt could not be updated: {exc}"
                    )

        if self.app_config:
            if plan["profiles"]:
                self.app_config.set_inbound_endpoint_profiles(plan["profiles"])
            inputs = plan["inputs"]
            public_profile = {
                "public_ipv4": inputs["public_ipv4"],
                "public_ipv6": inputs["public_ipv6"],
                "public_domain": inputs["public_domain"] if inputs["tls_ready"] else "",
                "cloudflare_preferred_ip": (
                    inputs["cloudflare_preferred_ip"] if inputs["tls_ready"] else ""
                ),
                "preferred_endpoint": (
                    "domain" if inputs["tls_ready"] else
                    "ipv4" if inputs["public_ipv4"] else "ipv6"
                ),
                "cloudflare_proxied": inputs["tls_ready"],
            }
            self.app_config.set_public_endpoints(
                public_profile, self.app_config.cloudflare_zone_id
            )

        restart_message = ""
        if restart and self.process_mgr:
            try:
                log_path = config_path.parent / "logs" / "sing-box.log"
                if self.process_mgr.status().running:
                    self.process_mgr.restart(kernel_path, config_path, log_path)
                else:
                    self.process_mgr.start(kernel_path, config_path, log_path)
                time.sleep(1)
                if not self.process_mgr.status().running:
                    restart_message = " sing-box did not remain running; check logs."
            except Exception as exc:
                restart_message = f" Restart failed: {exc}"

        deployed_protocols = sum(
            item["status"] == "planned" for item in plan["protocols"]
        )
        message = (
            f"Deployed {len(plan['inbounds'])} inbounds across "
            f"{deployed_protocols} protocols."
        )
        if issued_certificate:
            message += (
                f" Configured the verified Let's Encrypt certificate on "
                f"{len(configured_tls_tags)} direct inbounds."
            )
        message += restart_message
        return {
            "success": True,
            "message": message,
            "certificate": ({
                **issued_certificate,
                "updated_inbounds": updated_tls_tags,
                "configured_inbounds": configured_tls_tags,
            } if issued_certificate else None),
            **plan,
        }
