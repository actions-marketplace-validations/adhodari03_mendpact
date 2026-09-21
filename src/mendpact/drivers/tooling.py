"""Shared normalization helpers for provider tool-selection drivers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from mendpact.domain import CapabilityNode


class ProviderToolCatalogError(ValueError):
    """Raised when an MCP tool catalog cannot be mapped without ambiguity."""


@dataclass(frozen=True)
class ProviderToolNames:
    """Bidirectional mapping between MCP names and provider-safe names."""

    original_to_provider: dict[str, str]
    provider_to_original: dict[str, str]

    def for_tool(self, tool: CapabilityNode) -> str:
        return self.original_to_provider[tool.name]

    def to_original(self, provider_name: str) -> str:
        return self.provider_to_original.get(provider_name, provider_name)


def build_provider_tool_names(
    tools: list[CapabilityNode],
    *,
    valid_name: re.Pattern[str],
    max_length: int,
) -> ProviderToolNames:
    """Create deterministic aliases for names a provider cannot accept directly."""

    if max_length < 16:
        raise ValueError("Provider tool names must allow at least 16 characters.")

    original_to_provider: dict[str, str] = {}
    provider_to_original: dict[str, str] = {}
    for tool in tools:
        if tool.name in original_to_provider:
            raise ProviderToolCatalogError(
                f"The MCP catalog contains the duplicate tool name {tool.name!r}."
            )

        provider_name = tool.name
        if not valid_name.fullmatch(provider_name):
            slug = re.sub(r"[^A-Za-z0-9_-]", "_", tool.name).strip("_") or "tool"
            suffix = f"_{sha256(tool.id.encode()).hexdigest()[:10]}"
            provider_name = f"{slug[: max_length - len(suffix)]}{suffix}"

        if provider_name in provider_to_original:
            suffix = f"_{sha256(tool.id.encode()).hexdigest()[:10]}"
            provider_name = f"{provider_name[: max_length - len(suffix)]}{suffix}"
        if provider_name in provider_to_original:
            raise ProviderToolCatalogError(
                f"Could not create a unique provider name for MCP tool {tool.name!r}."
            )

        original_to_provider[tool.name] = provider_name
        provider_to_original[provider_name] = tool.name

    return ProviderToolNames(
        original_to_provider=original_to_provider,
        provider_to_original=provider_to_original,
    )


def tool_input_schema(tool: CapabilityNode) -> dict[str, Any]:
    """Return the MCP schema or a strict empty-object schema when it is absent."""

    return tool.input_schema or {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }


def tool_description(tool: CapabilityNode) -> str:
    """Return useful provider text even when MCP metadata omits a description."""

    return tool.description or f"MCP tool named {tool.name}."


def decode_object_arguments(raw_arguments: Any) -> tuple[dict[str, Any], str | None]:
    """Normalize provider arguments while retaining a readable parsing failure."""

    if isinstance(raw_arguments, dict):
        return raw_arguments, None
    try:
        decoded = json.loads(raw_arguments)
    except (json.JSONDecodeError, TypeError) as exc:
        return {}, str(exc)
    if not isinstance(decoded, dict):
        return {}, "function arguments were not a JSON object"
    return decoded, None


def usage_value(usage: Any, name: str) -> int | None:
    """Read an integer token counter from an SDK response object."""

    value = getattr(usage, name, None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
