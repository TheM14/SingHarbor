"""Protocol deployment wizard.

Guides through:
1. Check kernel version supports the protocol.
2. Collect parameters.
3. Check port/tag conflicts.
4. Generate config preview.
5. Show diff.
6. Validate with kernel.
7. Backup config.
8. Atomic save.
9. Restart/reload sing-box.
10. Check start status.
11. Generate client connection info.
"""

import time
import logging
from pathlib import Path
from .protocols import get_by_type, ProtocolDefinition
from .config_mgr import ConfigManager
from .kernel import KernelManager
from .process import ProcessManager
from .utils import generate_uuid, generate_ss_password, generate_password
from .endpoints import (
    CLOUDFLARE_WS_PROTOCOLS,
    build_client_bundle,
    build_endpoint_profile,
    validate_cdn_options,
)

logger = logging.getLogger(__name__)


class DeploymentWizard:
    """Wizard for deploying server-side proxy protocols."""

    def __init__(self, config_mgr: ConfigManager, kernel_mgr: KernelManager,
                 process_mgr: ProcessManager, app_config=None):
        self.config_mgr = config_mgr
        self.kernel_mgr = kernel_mgr
        self.process_mgr = process_mgr
        self.app_config = app_config

    def get_available_protocols(self) -> list[dict]:
        """Get list of server-side protocols available for deployment."""
        from .protocols import get_server_protocols
        protocols = get_server_protocols()
        result = []
        for ptype, proto in protocols.items():
            result.append({
                "type": ptype,
                "name": proto.name,
                "description": proto.description,
                "supports_tls": proto.supports_tls,
                "supports_transport": proto.supports_transport,
                "supports_multiplex": proto.supports_multiplex,
                "share_link_prefix": proto.share_link_prefix,
                "supports_cloudflare_ws": ptype in CLOUDFLARE_WS_PROTOCOLS,
                "required_fields": [
                    {"name": f.name, "type": f.field_type,
                     "description": f.description}
                    for f in proto.get_required_fields()
                ],
                "optional_fields": [
                    {"name": f.name, "type": f.field_type,
                     "default": str(f.default) if f.default is not None else None,
                     "description": f.description, "choices": f.choices}
                    for f in proto.get_optional_fields()
                ],
            })
        return result

    def get_protocol_schema(self, protocol_type: str) -> dict | None:
        """Get the schema/definition for a specific protocol type."""
        proto = get_by_type(protocol_type)
        if not proto:
            return None
        return {
            "type": protocol_type,
            "name": proto.name,
            "description": proto.description,
            "supports_tls": proto.supports_tls,
            "supports_transport": proto.supports_transport,
            "supports_multiplex": proto.supports_multiplex,
            "supports_cloudflare_ws": protocol_type in CLOUDFLARE_WS_PROTOCOLS,
            "fields": [
                {
                    "name": f.name,
                    "type": f.field_type,
                    "required": f.required,
                    "default": str(f.default) if f.default is not None else None,
                    "description": f.description,
                    "choices": f.choices,
                    "min": f.min_value,
                    "max": f.max_value,
                }
                for f in proto.fields
            ],
        }

    def generate_defaults(self, protocol_type: str) -> dict:
        """Generate secure default values for a protocol."""
        proto = get_by_type(protocol_type)
        if not proto:
            raise ValueError(f"Unknown protocol: {protocol_type}")

        defaults = {
            "listen": "::",
            "listen_port": 10086 if protocol_type in CLOUDFLARE_WS_PROTOCOLS else 0,
            "cdn_listen_port": 443,
            "tag": f"{protocol_type}-in",
        }

        for field in proto.fields:
            if field.name in defaults:
                continue
            if field.field_type == "uuid":
                defaults[field.name] = generate_uuid()
            elif field.field_type == "password":
                if field.name == "password" and protocol_type == "shadowsocks":
                    method = defaults.get("method", "2022-blake3-aes-128-gcm")
                    defaults[field.name] = proto.generate_password_for_method(method)
                else:
                    defaults[field.name] = generate_password()
            elif field.default is not None:
                defaults[field.name] = field.default

        if self.app_config:
            defaults.update(self.app_config.public_endpoints)
        defaults.update({
            "ws_enabled": False,
            "ws_path": f"/{protocol_type}",
            "tls_enabled": False,
            "tls_server_name": defaults.get("public_domain", ""),
            "tls_certificate_path": "",
            "tls_key_path": "",
        })
        return defaults

    def validate_params(self, protocol_type: str, params: dict) -> list[str]:
        """Validate protocol parameters."""
        proto = get_by_type(protocol_type)
        if not proto:
            return [f"Unknown protocol: {protocol_type}"]
        errors = proto.validate_params(params)
        _, endpoint_errors = build_endpoint_profile(params)
        errors.extend(endpoint_errors)
        errors.extend(validate_cdn_options(protocol_type, params))
        return errors

    @staticmethod
    def normalize_params(params: dict) -> dict:
        """Return typed endpoint values ready for config generation."""
        normalized = dict(params)
        profile, _ = build_endpoint_profile(params)
        normalized.update(profile)
        if profile.get("public_domain") and not normalized.get("tls_server_name"):
            normalized["tls_server_name"] = profile["public_domain"]
        return normalized

    def check_conflicts(self, tag: str, port: int) -> list[str]:
        """Check for tag and port conflicts in current config."""
        conflicts = []
        inbounds = self.config_mgr.get_inbounds()

        for inbound in inbounds:
            existing_tag = inbound.get("tag", "")
            existing_port = inbound.get("listen_port", 0)

            if tag and existing_tag == tag:
                conflicts.append(f"Tag '{tag}' already in use")
            if port and existing_port == port:
                conflicts.append(
                    f"Port {port} already in use by '{existing_tag}'"
                )

        return conflicts

    def build_deployment_entries(self, protocol_type: str,
                                 params: dict) -> list[dict]:
        """Build one normal inbound or independent direct/CDN inbounds.

        Cloudflare cannot forward a raw VMess/VLESS TCP stream.  When a
        deployment publishes both IP literals and an orange-cloud hostname,
        the IP addresses therefore point to a plaintext TCP inbound while the
        hostname points to a second WebSocket + TLS inbound.
        """
        proto = get_by_type(protocol_type)
        if not proto:
            raise ValueError(f"Unknown protocol: {protocol_type}")

        normalized = self.normalize_params(params)
        profile, _ = build_endpoint_profile(normalized)
        if not profile.get("cloudflare_proxied"):
            return [{
                "role": "standard",
                "inbound": proto.generate_config(normalized),
                "profile": profile,
            }]

        base_tag = str(normalized.get("tag") or f"{protocol_type}-in")
        entries = []
        if profile.get("public_ipv4") or profile.get("public_ipv6"):
            direct_params = dict(normalized)
            direct_params.update({
                "tag": f"{base_tag}-direct",
                "ws_enabled": False,
                "tls_enabled": False,
            })
            direct_params.pop("transport", None)
            direct_params.pop("tls", None)
            direct_preferred = profile.get("preferred_endpoint")
            if direct_preferred not in {"ipv4", "ipv6"}:
                direct_preferred = (
                    "ipv4" if profile.get("public_ipv4") else "ipv6"
                )
            direct_profile = {
                "public_ipv4": profile.get("public_ipv4", ""),
                "public_ipv6": profile.get("public_ipv6", ""),
                "public_domain": "",
                "preferred_endpoint": direct_preferred,
                "cloudflare_proxied": False,
            }
            entries.append({
                "role": "direct",
                "inbound": proto.generate_config(direct_params),
                "profile": direct_profile,
            })

        cdn_params = dict(normalized)
        cdn_params.update({
            "tag": f"{base_tag}-cdn",
            "listen_port": int(normalized.get("cdn_listen_port", 443)),
            "ws_enabled": True,
            "tls_enabled": True,
        })
        cdn_profile = {
            "public_ipv4": "",
            "public_ipv6": "",
            "public_domain": profile.get("public_domain", ""),
            "preferred_endpoint": "domain",
            "cloudflare_proxied": True,
        }
        entries.append({
            "role": "cdn",
            "inbound": proto.generate_config(cdn_params),
            "profile": cdn_profile,
        })
        return entries

    def check_deployment_conflicts(self, protocol_type: str,
                                   params: dict) -> list[str]:
        """Check every generated tag and port, including pair conflicts."""
        entries = self.build_deployment_entries(protocol_type, params)
        conflicts = []
        pending_tags = set()
        pending_ports = set()
        for entry in entries:
            inbound = entry["inbound"]
            tag = inbound.get("tag", "")
            port = inbound.get("listen_port", 0)
            if tag in pending_tags:
                conflicts.append(f"Tag '{tag}' is duplicated in this deployment")
            if port in pending_ports:
                conflicts.append(f"Port {port} is duplicated in this deployment")
            pending_tags.add(tag)
            pending_ports.add(port)
            conflicts.extend(self.check_conflicts(tag, port))
        return conflicts

    def generate_preview(self, protocol_type: str, params: dict) -> dict:
        """Generate a preview of all inbounds created by the deployment."""
        inbounds = [
            entry["inbound"]
            for entry in self.build_deployment_entries(protocol_type, params)
        ]
        return inbounds[0] if len(inbounds) == 1 else {"inbounds": inbounds}

    def generate_diff(self, inbound: dict) -> dict:
        """Generate a diff between current config and all previewed inbounds."""
        current = self.config_mgr.read()
        new_config = dict(current)
        new_config.setdefault("inbounds", [])
        new_config["inbounds"] = list(new_config["inbounds"])
        additions = inbound.get("inbounds", []) if (
            isinstance(inbound, dict) and set(inbound) == {"inbounds"}
        ) else [inbound]
        new_config["inbounds"].extend(additions)
        return self.config_mgr.diff(new_config)

    @staticmethod
    def _combine_client_info(proto: ProtocolDefinition, entries: list[dict],
                             preferred: str) -> dict:
        variants = []
        errors = []
        for entry in entries:
            bundle = build_client_bundle(
                proto, entry["inbound"], entry["profile"]
            )
            variants.extend(bundle.get("variants", []))
            errors.extend(bundle.get("validation_errors", []))

        primary = next(
            (item for item in variants if item.get("kind") == preferred), None
        )
        if primary is None and variants:
            primary = variants[0]
        result = {
            "preferred": primary.get("kind", "") if primary else "",
            "variants": variants,
            "validation_errors": errors,
        }
        if primary:
            for key in ("share_link", "config_snippet", "credentials", "notes"):
                result[key] = primary.get(key, [] if key == "notes" else {})
        else:
            result.update({
                "share_link": "",
                "config_snippet": {},
                "credentials": {},
                "notes": ["Configure a public IPv4, IPv6, or domain endpoint."],
            })
        return result

    def deploy(self, protocol_type: str, params: dict,
               kernel_path: Path, config_path: Path,
               restart: bool = True) -> dict:
        """Full deployment workflow.

        Steps:
        1. Validate parameters.
        2. Check conflicts.
        3. Generate inbound config.
        4. Add to config.
        5. Validate with kernel.
        6. Backup current config.
        7. Save config.
        8. Restart/reload sing-box.
        9. Check status.
        10. Generate client info.

        Returns:
            dict with keys: success, message, inbound, client_info
        """
        result = {
            "success": False,
            "message": "",
            "inbound": None,
            "inbounds": [],
            "client_info": None,
        }

        proto = get_by_type(protocol_type)
        if not proto:
            result["message"] = f"Unknown protocol: {protocol_type}"
            return result

        errors = self.validate_params(protocol_type, params)
        if errors:
            result["message"] = "Validation errors: " + "; ".join(errors)
            return result

        params = self.normalize_params(params)
        entries = self.build_deployment_entries(protocol_type, params)
        conflicts = self.check_deployment_conflicts(protocol_type, params)
        if conflicts:
            result["message"] = "Conflicts: " + "; ".join(conflicts)
            return result

        inbounds = [entry["inbound"] for entry in entries]
        ok, msg = self.config_mgr.add_inbounds(inbounds, kernel_path)

        if not ok:
            result["message"] = f"Failed to add inbound: {msg}"
            return result

        profile, _ = build_endpoint_profile(params)
        client_info = self._combine_client_info(
            proto, entries, profile.get("preferred_endpoint", "")
        )
        primary_role = "cdn" if profile.get("preferred_endpoint") == "domain" else "direct"
        primary_entry = next(
            (entry for entry in entries if entry["role"] == primary_role), entries[0]
        )
        result["inbound"] = primary_entry["inbound"]
        result["inbounds"] = inbounds
        result["client_info"] = client_info

        if self.app_config and any(
            profile.get(key) for key in ("public_ipv4", "public_ipv6", "public_domain")
        ):
            self.app_config.set_public_endpoints(
                profile, self.app_config.cloudflare_zone_id
            )
            self.app_config.set_inbound_endpoint_profiles({
                entry["inbound"].get("tag", ""): entry["profile"]
                for entry in entries if entry["inbound"].get("tag")
            })

        if restart:
            try:
                current = self.process_mgr.status()
                if current.running:
                    log_path = config_path.parent / "logs" / "sing-box.log"
                    self.process_mgr.restart(kernel_path, config_path, log_path)
                else:
                    log_path = config_path.parent / "logs" / "sing-box.log"
                    self.process_mgr.start(kernel_path, config_path, log_path)
            except Exception as e:
                result["success"] = True
                result["message"] = (
                    f"Inbound added but restart failed: {e}. "
                    "You may need to start sing-box manually."
                )
                return result

            time.sleep(1)
            state = self.process_mgr.status()
            if not state.running:
                result["success"] = True
                result["message"] = (
                    "Inbound added but sing-box failed to start. "
                    "Check logs for details."
                )
                return result

        result["success"] = True
        result["message"] = "Deployment successful"
        return result
