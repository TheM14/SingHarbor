"""Protocol package - imports all protocol definitions to register them."""

from .base import ProtocolDefinition, ProtocolField
from .registry import register, get_all, get_by_type, get_server_protocols, get_shareable_protocols

from .shadowsocks import ShadowsocksDefinition
from .vmess import VMessDefinition
from .trojan import TrojanDefinition
from .vless import VLESSDefinition
from .hysteria2 import Hysteria2Definition
from .tuic import TUICDefinition
from .shadowtls import ShadowTLSDefinition
from .naive import NaiveDefinition
from .hysteria import HysteriaDefinition
from .anytls import AnyTLSDefinition

__all__ = [
    "ProtocolDefinition",
    "ProtocolField",
    "register",
    "get_all",
    "get_by_type",
    "get_server_protocols",
    "get_shareable_protocols",
    "ShadowsocksDefinition",
    "VMessDefinition",
    "TrojanDefinition",
    "VLESSDefinition",
    "Hysteria2Definition",
    "TUICDefinition",
    "ShadowTLSDefinition",
    "NaiveDefinition",
    "HysteriaDefinition",
    "AnyTLSDefinition",
]
