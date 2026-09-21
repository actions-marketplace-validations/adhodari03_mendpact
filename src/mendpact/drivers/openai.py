"""OpenAI Responses API driver for observational tool-selection evaluations."""

from __future__ import annotations

import os
import re
from importlib import import_module
from time import perf_counter
from typing import Any, Protocol

from mendpact.domain import BehaviorScenario, CapabilityNode, ToolCallTrace
from mendpact.drivers.tooling import (
    build_provider_tool_names,
    decode_object_arguments,
    tool_description,
    tool_input_schema,
    usage_value,
)


class OpenAIDriverConfigurationError(RuntimeError):
    """Raised when the optional OpenAI driver cannot be configured."""


class _ResponsesAPI(Protocol):
    async def create(self, **kwargs: Any) -> Any:
        """Create one Responses API result."""

        ...


class _OpenAIClient(Protocol):
    responses: _ResponsesAPI


def _strict_compatible(schema: dict[str, Any]) -> bool:
    """Check the documented structural requirements for strict function schemas."""

    schema_type = schema.get("type")
    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            return False
        if schema.get("additionalProperties") is not False:
            return False
        if set(required) != set(properties):
            return False
        if any(
            isinstance(value, dict) and not _strict_compatible(value)
            for value in properties.values()
        ):
            return False
    elif schema_type == "array":
        items = schema.get("items")
        if isinstance(items, dict) and not _strict_compatible(items):
            return False

    for keyword in ("anyOf", "oneOf", "allOf"):
        alternatives = schema.get(keyword)
        if isinstance(alternatives, list) and any(
            isinstance(value, dict) and not _strict_compatible(value)
            for value in alternatives
        ):
            return False
    for keyword in ("$defs", "definitions"):
        definitions = schema.get(keyword)
        if isinstance(definitions, dict) and any(
            isinstance(value, dict) and not _strict_compatible(value)
            for value in definitions.values()
        ):
            return False
    return True


_OPENAI_FUNCTION_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _tool_definition(tool: CapabilityNode, provider_name: str) -> dict[str, Any]:
    parameters = tool_input_schema(tool)
    return {
        "type": "function",
        "name": provider_name,
        "description": tool_description(tool),
        "parameters": parameters,
        "strict": _strict_compatible(parameters),
    }


class OpenAIResponsesDriver:
    """Ask an OpenAI model to select a function without executing that function."""

    name = "openai"

    def __init__(
        self,
        model: str,
        *,
        client: _OpenAIClient | None = None,
        api_key: str | None = None,
    ) -> None:
        if not model.strip():
            raise OpenAIDriverConfigurationError("An OpenAI model name is required.")
        self.model = model
        if client is not None:
            self._client = client
            return

        resolved_api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not resolved_api_key:
            raise OpenAIDriverConfigurationError(
                "OPENAI_API_KEY is not set. Export it before using --driver openai."
            )
        try:
            openai_module = import_module("openai")
        except ImportError as exc:
            raise OpenAIDriverConfigurationError(
                "The OpenAI SDK is not installed. Install MendPact with the 'openai' extra."
            ) from exc
        self._client = openai_module.AsyncOpenAI(api_key=resolved_api_key)

    async def select_tool(
        self,
        scenario: BehaviorScenario,
        tools: list[CapabilityNode],
        attempt: int,
    ) -> ToolCallTrace:
        if not tools:
            raise OpenAIDriverConfigurationError(
                "The discovered MCP endpoint does not expose any tools to evaluate."
            )

        started_at = perf_counter()
        tool_names = build_provider_tool_names(
            tools,
            valid_name=_OPENAI_FUNCTION_NAME,
            max_length=64,
        )
        response = await self._client.responses.create(
            model=self.model,
            instructions=(
                "You are evaluating an MCP tool catalog. Select exactly one function that best "
                "satisfies the user's task. Do not execute the function and do not invent tools."
            ),
            input=scenario.task,
            tools=[_tool_definition(tool, tool_names.for_tool(tool)) for tool in tools],
            tool_choice="required",
            parallel_tool_calls=False,
            store=False,
        )
        latency_ms = (perf_counter() - started_at) * 1000
        function_calls = [
            item for item in response.output if getattr(item, "type", None) == "function_call"
        ]

        selected_tool: str | None = None
        provider_selected_tool: str | None = None
        arguments: dict[str, Any] = {}
        parse_error: str | None = None
        if function_calls:
            raw_selected_tool = getattr(function_calls[0], "name", None)
            if isinstance(raw_selected_tool, str):
                provider_selected_tool = raw_selected_tool
                selected_tool = tool_names.to_original(raw_selected_tool)
            raw_arguments = getattr(function_calls[0], "arguments", "{}")
            arguments, parse_error = decode_object_arguments(raw_arguments)

        usage = getattr(response, "usage", None)
        resolved_model = getattr(response, "model", None)
        return ToolCallTrace(
            scenario_id=scenario.id,
            attempt=attempt,
            provider=self.name,
            model=resolved_model if isinstance(resolved_model, str) else self.model,
            available_tools=sorted(tool.name for tool in tools),
            selected_tool=selected_tool,
            provider_selected_tool=provider_selected_tool,
            tool_call_count=len(function_calls),
            arguments=arguments,
            arguments_parse_error=parse_error,
            message=getattr(response, "output_text", None) or None,
            response_id=getattr(response, "id", None),
            latency_ms=latency_ms,
            input_tokens=usage_value(usage, "input_tokens"),
            output_tokens=usage_value(usage, "output_tokens"),
            total_tokens=usage_value(usage, "total_tokens"),
        )
