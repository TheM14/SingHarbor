"""Minimal Cloudflare DNS client used for explicit A/AAAA synchronization."""

from __future__ import annotations

import os
import re

import requests

from .endpoints import build_endpoint_profile, normalize_domain


API_ROOT = "https://api.cloudflare.com/client/v4"
_ZONE_ID = re.compile(r"^[0-9a-fA-F]{32}$")


class CloudflareError(RuntimeError):
    """A sanitized Cloudflare API error safe to show in the WebUI."""


class CloudflareDNSClient:
    def __init__(self, token: str, timeout: int = 15, session=None):
        token = str(token or "").strip()
        if not token:
            raise CloudflareError("Cloudflare API token is required")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs):
        try:
            response = self.session.request(
                method,
                f"{API_ROOT}{path}",
                headers=self.headers,
                timeout=self.timeout,
                **kwargs,
            )
            data = response.json()
        except requests.RequestException as exc:
            raise CloudflareError("Unable to reach the Cloudflare API") from exc
        except ValueError as exc:
            raise CloudflareError("Cloudflare returned an invalid response") from exc

        if not response.ok or not data.get("success", False):
            messages = []
            for item in data.get("errors", []):
                if isinstance(item, dict):
                    messages.append(str(item.get("message") or item.get("code") or "error"))
            detail = "; ".join(messages) or f"HTTP {response.status_code}"
            raise CloudflareError(f"Cloudflare API request failed: {detail}")
        return data.get("result")

    def upsert_record(self, zone_id: str, record_type: str, name: str,
                      content: str, proxied: bool = True, ttl: int = 1) -> dict:
        existing = self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": record_type, "name": name, "per_page": 100},
        ) or []
        if len(existing) > 1:
            raise CloudflareError(
                f"Multiple {record_type} records already exist for {name}; "
                "resolve the conflict in Cloudflare first"
            )

        payload = {
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": bool(proxied),
            "ttl": 1 if proxied else ttl,
            "comment": "Managed by SingHarbor",
        }
        if existing:
            current = existing[0]
            unchanged = (
                current.get("content") == content
                and bool(current.get("proxied")) == bool(proxied)
                and (proxied or int(current.get("ttl", ttl)) == ttl)
            )
            if unchanged:
                return {"action": "unchanged", "record": current}
            record = self._request(
                "PUT",
                f"/zones/{zone_id}/dns_records/{current['id']}",
                json=payload,
            )
            return {"action": "updated", "record": record}

        record = self._request(
            "POST", f"/zones/{zone_id}/dns_records", json=payload
        )
        return {"action": "created", "record": record}


def get_cloudflare_token(explicit_token: str = "") -> str:
    """Use a one-shot token first, then the process environment."""
    return str(explicit_token or os.environ.get("CLOUDFLARE_API_TOKEN", "")).strip()


def build_dns_plan(values: dict) -> tuple[dict, list[str]]:
    """Validate a DNS sync request without changing Cloudflare state."""
    profile, errors = build_endpoint_profile(values)
    zone_id = str(values.get("zone_id", "")).strip()
    if not _ZONE_ID.fullmatch(zone_id):
        errors.append("zone_id: must be the 32-character Cloudflare Zone ID")

    try:
        hostname = normalize_domain(values.get("hostname") or profile["public_domain"])
    except ValueError as exc:
        hostname = ""
        errors.append(f"hostname: {exc}")
    if not hostname:
        errors.append("hostname: required")

    records = []
    if profile["public_ipv4"]:
        records.append({
            "type": "A", "name": hostname, "content": profile["public_ipv4"]
        })
    if profile["public_ipv6"]:
        records.append({
            "type": "AAAA", "name": hostname, "content": profile["public_ipv6"]
        })
    if not records:
        errors.append("At least one public IPv4 or IPv6 address is required")

    try:
        ttl = int(values.get("ttl", 300))
    except (TypeError, ValueError):
        ttl = 300
        errors.append("ttl: must be an integer")
    if ttl != 1 and not 60 <= ttl <= 86400:
        errors.append("ttl: must be 1 (automatic) or between 60 and 86400")

    proxied = bool(profile["cloudflare_proxied"])
    return {
        "zone_id": zone_id,
        "hostname": hostname,
        "proxied": proxied,
        "ttl": 1 if proxied else ttl,
        "records": records,
    }, errors


def sync_dns_records(values: dict, session=None) -> dict:
    """Create or update the requested A/AAAA records idempotently."""
    plan, errors = build_dns_plan(values)
    if errors:
        raise CloudflareError("; ".join(errors))
    token = get_cloudflare_token(values.get("api_token", ""))
    client = CloudflareDNSClient(token, session=session)
    results = []
    for record in plan["records"]:
        result = client.upsert_record(
            plan["zone_id"],
            record["type"],
            record["name"],
            record["content"],
            proxied=plan["proxied"],
            ttl=plan["ttl"],
        )
        results.append({
            "type": record["type"],
            "name": record["name"],
            "content": record["content"],
            "action": result["action"],
        })
    return {"success": True, "plan": plan, "results": results}
