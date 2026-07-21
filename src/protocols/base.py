"""Base protocol definition for sing-box server-side inbound protocols.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/inbound/

Each protocol definition maps to a sing-box inbound type and describes:
- Name, type, version compatibility
- Required and optional fields
- TLS, transport combination rules
- Config generation rules
- Config validation rules
- Client connection info generation rules
"""

import json
import copy
from abc import ABC, abstractmethod
from typing import Any


class ProtocolField:
    """Describes a field in a protocol configuration."""
    def __init__(self, name: str, field_type: str = "string",
                 required: bool = False, default: Any = None,
                 description: str = "", min_value: int | None = None,
                 max_value: int | None = None, choices: list | None = None):
        self.name = name
        self.field_type = field_type
        self.required = required
        self.default = default
        self.description = description
        self.min_value = min_value
        self.max_value = max_value
        self.choices = choices


class ProtocolDefinition(ABC):
    """Base class for protocol definitions.

    Subclass this to define a new protocol.
    """
    name: str = ""
    inbound_type: str = ""
    description: str = ""
    min_version: str = "1.0.0"
    max_version: str | None = None
    fields: list = []
    supports_tls: bool = False
    supports_transport: bool = False
    supports_multiplex: bool = False
    share_link_prefix: str = ""

    @abstractmethod
    def validate_params(self, params: dict) -> list[str]:
        """Validate user-provided parameters. Returns list of error messages."""
        ...

    @abstractmethod
    def generate_config(self, params: dict) -> dict:
        """Generate a sing-box inbound config snippet from parameters."""
        ...

    @abstractmethod
    def generate_client_info(self, config: dict, server_address: str) -> dict:
        """Generate client connection info from an inbound config.

        Returns dict with keys: share_link, config_snippet, credentials, notes
        """
        ...

    def validate_basic(self, params: dict) -> list[str]:
        """Validate basic field types and required fields."""
        errors = []
        for field in self.fields:
            value = params.get(field.name)
            if field.required and (value is None or value == ""):
                errors.append(f"{field.name}: required")
                continue
            if value is not None and value != "":
                if field.field_type == "int":
                    try:
                        int_val = int(value)
                        if field.min_value is not None and int_val < field.min_value:
                            errors.append(f"{field.name}: minimum is {field.min_value}")
                        if field.max_value is not None and int_val > field.max_value:
                            errors.append(f"{field.name}: maximum is {field.max_value}")
                    except (ValueError, TypeError):
                        errors.append(f"{field.name}: must be an integer")
                elif field.field_type == "uuid":
                    import re
                    if not re.match(
                        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                        str(value),
                        re.IGNORECASE
                    ):
                        errors.append(f"{field.name}: must be a valid UUID")
                if field.choices and value not in field.choices and str(value) not in {
                    str(choice) for choice in field.choices
                }:
                    errors.append(
                        f"{field.name}: must be one of {field.choices}"
                    )
        return errors

    def get_required_fields(self) -> list[ProtocolField]:
        return [f for f in self.fields if f.required]

    def get_optional_fields(self) -> list[ProtocolField]:
        return [f for f in self.fields if not f.required]
