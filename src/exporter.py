"""Client export and QR-code helpers for configured inbounds."""

from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone

from .analyzer import analyze_inbounds


def build_client_export(config: dict, endpoint_profile: dict | None = None,
                        endpoint_profiles: dict | None = None) -> dict:
    """Build a portable export for every inbound and endpoint variant."""
    analyzed = analyze_inbounds(
        config,
        endpoint_profile=endpoint_profile,
        endpoint_profiles=endpoint_profiles,
    )
    inbounds = []
    items = []
    text_sections = []
    for inbound in analyzed:
        variants = []
        for option in inbound.get("client_options", []):
            item = {
                "inbound_tag": inbound["tag"],
                "protocol": inbound["type"],
                "kind": option.get("kind", ""),
                "label": option.get("label", ""),
                "address": option.get("address", ""),
                "domain": option.get("domain", ""),
                "share_link": option.get("share_link", ""),
                "client_config": option.get("config_snippet", {}),
            }
            item["portable_value"] = item["share_link"] or json.dumps(
                item["client_config"], ensure_ascii=False, indent=2
            )
            variants.append(item)
            items.append(item)
            text_sections.append(
                f"# {item['inbound_tag']} / {item['label']}\n"
                f"{item['portable_value']}"
            )
        inbounds.append({
            "tag": inbound["tag"],
            "protocol": inbound["type"],
            "recognized": inbound["recognized"],
            "variants": variants,
        })

    return {
        "format": "singharbor-client-export",
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inbounds": inbounds,
        "items": items,
        "text": "\n\n".join(text_sections),
    }


def generate_qr_data_url(value: str) -> str:
    """Return a PNG QR code as a data URL."""
    try:
        import qrcode
        from qrcode.exceptions import DataOverflowError
    except ImportError as exc:
        raise RuntimeError(
            "QR dependencies are not installed; run pip install -r requirements.txt"
        ) from exc

    value = str(value or "")
    if not value:
        raise ValueError("value: required")
    if len(value.encode("utf-8")) > 8192:
        raise ValueError("value: QR content exceeds 8192 bytes")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=4,
    )
    qr.add_data(value)
    try:
        qr.make(fit=True)
    except (DataOverflowError, ValueError) as exc:
        raise ValueError("value: QR content is too large") from exc
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
