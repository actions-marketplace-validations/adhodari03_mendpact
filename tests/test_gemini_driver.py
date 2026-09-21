from types import SimpleNamespace
from typing import Any

import pytest

from mendpact.domain import (
    BehaviorExpectation,
    BehaviorScenario,
    CapabilityNode,
    NodeKind,
)
from mendpact.drivers.gemini import (
    GeminiDriverConfigurationError,
    GeminiGenerateContentDriver,
)


class FakeModels:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.request: dict[str, Any] = {}

    async def generate_content(self, **kwargs: Any) -> Any:
        self.request = kwargs
        return self.response


class FakeClient:
    def __init__(self, response: Any) -> None:
        self.aio = SimpleNamespace(models=FakeModels(response))


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
        },
    )


def _response(*, name: str = "read_status") -> SimpleNamespace:
    return SimpleNamespace(
        response_id="gemini-response-123",
        model_version="gemini-test-20260801",
        function_calls=[
            SimpleNamespace(
                name=name,
                args={"component": "api"},
            )
        ],
        candidates=[
            SimpleNamespace(
                content=SimpleNamespace(
                    parts=[SimpleNamespace(text="I will inspect the API status.")]
                )
            )
        ],
        usage_metadata=SimpleNamespace(
            prompt_token_count=25,
            candidates_token_count=7,
            total_token_count=32,
        ),
    )


@pytest.mark.anyio
async def test_normalizes_function_call_without_executing_tool() -> None:
    client = FakeClient(_response())
    driver = GeminiGenerateContentDriver("gemini-test", client=client)

    trace = await driver.select_tool(_scenario(), [_tool()], 1)

    assert trace.provider == "gemini"
    assert trace.selected_tool == "read_status"
    assert trace.arguments == {"component": "api"}
    assert trace.tool_call_count == 1
    assert trace.response_id == "gemini-response-123"
    assert trace.model == "gemini-test-20260801"
    assert trace.message == "I will inspect the API status."
    assert trace.input_tokens == 25
    assert trace.output_tokens == 7
    assert trace.total_tokens == 32
    assert trace.latency_ms is not None

    request = client.aio.models.request
    assert request["contents"] == "Check the API status."
    assert request["config"]["tool_config"] == {
        "function_calling_config": {"mode": "ANY"}
    }
    assert request["config"]["automatic_function_calling"] == {"disable": True}
    declaration = request["config"]["tools"][0]["function_declarations"][0]
    assert declaration["name"] == "read_status"
    assert declaration["parameters_json_schema"]["required"] == ["component"]


@pytest.mark.anyio
async def test_maps_provider_safe_name_back_to_original_mcp_tool() -> None:
    response = _response()
    response.function_calls = []
    client = FakeClient(response)
    driver = GeminiGenerateContentDriver("gemini-test", client=client)
    tool = _tool("status/read")

    first_trace = await driver.select_tool(_scenario(), [tool], 1)
    declaration = client.aio.models.request["config"]["tools"][0][
        "function_declarations"
    ][0]
    provider_name = declaration["name"]
    response.function_calls = [
        SimpleNamespace(name=provider_name, args={"component": "api"})
    ]
    second_trace = await driver.select_tool(_scenario(), [tool], 2)

    assert first_trace.selected_tool is None
    assert "/" not in provider_name
    assert second_trace.selected_tool == "status/read"
    assert second_trace.provider_selected_tool == provider_name


@pytest.mark.anyio
async def test_rejects_empty_tool_catalog() -> None:
    client = FakeClient(SimpleNamespace())
    driver = GeminiGenerateContentDriver("gemini-test", client=client)

    with pytest.raises(GeminiDriverConfigurationError, match="does not expose any tools"):
        await driver.select_tool(_scenario(), [], 1)


def test_requires_api_key_for_real_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(GeminiDriverConfigurationError, match="GOOGLE_API_KEY"):
        GeminiGenerateContentDriver("gemini-test")
