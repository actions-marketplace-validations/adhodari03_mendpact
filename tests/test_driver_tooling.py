import re
from types import SimpleNamespace

import pytest

from mendpact.domain import CapabilityNode, NodeKind
from mendpact.drivers.tooling import (
    ProviderToolCatalogError,
    build_provider_tool_names,
    decode_object_arguments,
    tool_description,
    tool_input_schema,
    usage_value,
)

VALID_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _tool(name: str, *, tool_id: str | None = None) -> CapabilityNode:
    return CapabilityNode(
        id=tool_id or f"tool:{name}",
        kind=NodeKind.TOOL,
        name=name,
    )


def test_preserves_valid_names_and_round_trips_provider_aliases() -> None:
    valid = _tool("read_status")
    invalid = _tool("project.status/read", tool_id="tool:project.status/read")

    names = build_provider_tool_names(
        [valid, invalid],
        valid_name=VALID_NAME,
        max_length=64,
    )

    assert names.for_tool(valid) == "read_status"
    alias = names.for_tool(invalid)
    assert VALID_NAME.fullmatch(alias)
    assert len(alias) <= 64
    assert names.to_original(alias) == "project.status/read"
    assert names.to_original("provider_added_tool") == "provider_added_tool"


def test_provider_aliases_are_deterministic_and_unique() -> None:
    first = _tool("status.read", tool_id="tool:first")
    second = _tool("status/read", tool_id="tool:second")

    initial = build_provider_tool_names(
        [first, second],
        valid_name=VALID_NAME,
        max_length=24,
    )
    repeated = build_provider_tool_names(
        [first, second],
        valid_name=VALID_NAME,
        max_length=24,
    )

    assert initial == repeated
    assert initial.for_tool(first) != initial.for_tool(second)


def test_rejects_duplicate_original_tool_names() -> None:
    with pytest.raises(ProviderToolCatalogError, match="duplicate tool name"):
        build_provider_tool_names(
            [
                _tool("read_status", tool_id="tool:first"),
                _tool("read_status", tool_id="tool:second"),
            ],
            valid_name=VALID_NAME,
            max_length=64,
        )


@pytest.mark.parametrize(
    ("raw", "expected", "has_error"),
    [
        ({"component": "api"}, {"component": "api"}, False),
        ('{"component":"api"}', {"component": "api"}, False),
        ("[]", {}, True),
        ("not-json", {}, True),
        (None, {}, True),
    ],
)
def test_decodes_provider_arguments(
    raw: object,
    expected: dict[str, object],
    has_error: bool,
) -> None:
    arguments, error = decode_object_arguments(raw)

    assert arguments == expected
    assert (error is not None) is has_error


def test_supplies_schema_description_and_integer_usage_defaults() -> None:
    tool = _tool("read_status")

    assert tool_input_schema(tool) == {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }
    assert tool_description(tool) == "MCP tool named read_status."
    assert usage_value(SimpleNamespace(total_tokens=12), "total_tokens") == 12
    assert usage_value(SimpleNamespace(total_tokens=True), "total_tokens") is None
    assert usage_value(None, "total_tokens") is None
