"""Protocol registry - maps protocol names to their definitions.

sing-box version target: v1.13.14
"""

import logging
from .base import ProtocolDefinition

logger = logging.getLogger(__name__)

_registry: dict[str, type[ProtocolDefinition]] = {}
_instances: dict[str, ProtocolDefinition] = {}


def register(cls: type[ProtocolDefinition]):
    """Decorator to register a protocol definition class."""
    instance = cls()
    key = instance.inbound_type
    _registry[key] = cls
    _instances[key] = instance
    logger.debug("Registered protocol: %s", key)
    return cls


def get_all() -> dict[str, ProtocolDefinition]:
    """Get all registered protocol definition instances."""
    return dict(_instances)


def get_by_type(inbound_type: str) -> ProtocolDefinition | None:
    """Get a protocol definition by inbound type string."""
    return _instances.get(inbound_type)


def get_server_protocols() -> dict[str, ProtocolDefinition]:
    """Get protocols that function as server-side proxy protocols."""
    server_types = {
        "shadowsocks", "vmess", "trojan", "vless",
        "hysteria2", "tuic", "shadowtls", "naive",
        "hysteria", "anytls",
    }
    return {
        k: _instances[k] for k in _registry
        if k in server_types
    }


def get_shareable_protocols() -> dict[str, ProtocolDefinition]:
    """Get protocols that have share link format support."""
    return {
        k: _instances[k] for k in _registry
        if _instances[k].share_link_prefix
    }
