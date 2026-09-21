from types import SimpleNamespace
from typing import Any

import pytest

from mendpact.domain import (
    BehaviorExpectation,
    BehaviorScenario,
    CapabilityNode,
    NodeKind,
)
from mendpact.drivers.anthropic import (
    AnthropicDriverConfigurationError,
    AnthropicMessagesDriver,
)


class FakeMessages:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.request: dict[str, Any] = {}

    async def create(self, **kwargs: Any) -> Any:
        self.request = kwargs
        return self.response


class FakeClient:
    def __init__(self, response: Any) -> None:
        self.messages = FakeMessages(response)


def _scenario() -> BehaviorScenario:
    return BehaviorScenario(
        id="read-api-status",
        name="Read API status",
        task="Check the API status.",
        expectation=BehaviorExpectation(
            tool="read_status",
            arguments={"component": "api"},
        ),
    )


def _tool(name: str = "read_status") -> CapabilityNode:
    return CapabilityNode(
        id=f"tool:{name}",
        kind=NodeKind.TOOL,
        name=name,
        description="Read component status.",
        input_schema={
            "type": "object",
            "properties": {"component": {"type": "string"}},
            "required": ["component"],
            "additionalProperties": False,
        },
    )


@pytest.mark.anyio
async def test_normalizes_tool_use_without_executing_tool() -> None:
    response = SimpleNamespace(
        id="msg_123",
        model="claude-test-20260801",
        content=[
            SimpleNamespace(type="text", text="I will inspect the API status."),
            SimpleNamespace(
                type="tool_use",
                id="toolu_123",
                name="read_status",
                input={"component": "api"},
            ),
        ],
        usage=SimpleNamespace(input_tokens=30, output_tokens=8),
    )
    client = FakeClient(response)
    driver = AnthropicMessagesDriver("claude-test", client=client)

    trace = await driver.select_tool(_scenario(), [_tool()], 1)

    assert trace.provider == "anthropic"
    assert trace.selected_tool == "read_status"
    assert trace.arguments == {"component": "api"}
    assert trace.tool_call_count == 1
    assert trace.response_id == "msg_123"
    assert trace.model == "claude-test-20260801"
    assert trace.message == "I will inspect the API status."
    assert trace.input_tokens == 30
    assert trace.output_tokens == 8
    assert trace.total_tokens == 38
    assert trace.latency_ms is not None
    assert client.messages.request["max_tokens"] == 256
    assert client.messages.request["tool_choice"] == {
        "type": "any",
        "disable_parallel_tool_use": True,
    }
    assert client.messages.request["messages"] == [
        {"role": "user", "content": "Check the API status."}
    ]


@pytest.mark.anyio
async def test_maps_provider_safe_name_back_to_original_mcp_tool() -> None:
    response = SimpleNamespace(
        id="msg_alias",
        model="claude-test",
        content=[],
        usage=None,
    )
    client = FakeClient(response)
    driver = AnthropicMessagesDriver("claude-test", client=client)
    tool = _tool("status.read")

    first_trace = await driver.select_tool(_scenario(), [tool], 1)
    provider_name = client.messages.request["tools"][0]["name"]
    response.content = [
        SimpleNamespace(
            type="tool_use",
            id="toolu_alias",
            name=provider_name,
            input={"component": "api"},
        )
    ]
    second_trace = await driver.select_tool(_scenario(), [tool], 2)

    assert first_trace.selected_tool is None
    assert "." not in provider_name
    assert second_trace.selected_tool == "status.read"
    assert second_trace.provider_selected_tool == provider_name


@pytest.mark.anyio
async def test_rejects_empty_tool_catalog() -> None:
    client = FakeClient(SimpleNamespace())
    driver = AnthropicMessagesDriver("claude-test", client=client)

    with pytest.raises(AnthropicDriverConfigurationError, match="does not expose any tools"):
        await driver.select_tool(_scenario(), [], 1)


def test_requires_api_key_for_real_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(AnthropicDriverConfigurationError, match="ANTHROPIC_API_KEY"):
        AnthropicMessagesDriver("claude-test")


def test_rejects_invalid_max_tokens() -> None:
    with pytest.raises(AnthropicDriverConfigurationError, match="max_tokens"):
        AnthropicMessagesDriver("claude-test", client=FakeClient(SimpleNamespace()), max_tokens=0)
