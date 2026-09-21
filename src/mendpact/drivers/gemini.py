"""Google Gemini driver for observational tool-selection evaluations."""

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


class GeminiDriverConfigurationError(RuntimeError):
    """Raised when the optional Gemini driver cannot be configured."""


class _ModelsAPI(Protocol):
    async def generate_content(self, **kwargs: Any) -> Any:
        """Generate one Gemini response."""

        ...


class _AsyncAPI(Protocol):
    models: _ModelsAPI


class _GeminiClient(Protocol):
    aio: _AsyncAPI


_GEMINI_FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


def _function_declaration(tool: CapabilityNode, provider_name: str) -> dict[str, Any]:
    return {
        "name": provider_name,
        "description": tool_description(tool),
        "parameters_json_schema": tool_input_schema(tool),
    }


def _response_text(response: Any) -> str | None:
    texts: list[str] = []
    for candidate in getattr(response, "candidates", None) or []:
        content = getattr(candidate, "content", None)
        for part in getattr(content, "parts", None) or []:
            part_text = getattr(part, "text", None)
            if isinstance(part_text, str) and part_text:
                texts.append(part_text)
    return "\n".join(texts) or None


class GeminiGenerateContentDriver:
    """Ask Gemini to select an MCP tool without executing the returned function call."""

    name = "gemini"

    def __init__(
        self,
        model: str,
        *,
        client: _GeminiClient | None = None,
        api_key: str | None = None,
    ) -> None:
        if not model.strip():
            raise GeminiDriverConfigurationError("A Gemini model name is required.")

        self.model = model
        if client is not None:
            self._client = client
            return

        resolved_api_key = api_key or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not resolved_api_key:
            raise GeminiDriverConfigurationError(
                "GOOGLE_API_KEY or GEMINI_API_KEY is not set. Export one before using "
                "--driver gemini."
            )
        try:
            genai_module = import_module("google.genai")
        except ImportError as exc:
            raise GeminiDriverConfigurationError(
                "The Google Gen AI SDK is not installed. Install MendPact with the 'gemini' extra."
            ) from exc
        self._client = genai_module.Client(api_key=resolved_api_key)

    async def select_tool(
        self,
        scenario: BehaviorScenario,
        tools: list[CapabilityNode],
        attempt: int,
    ) -> ToolCallTrace:
        if not tools:
            raise GeminiDriverConfigurationError(
                "The discovered MCP endpoint does not expose any tools to evaluate."
            )

        started_at = perf_counter()
        tool_names = build_provider_tool_names(
            tools,
            valid_name=_GEMINI_FUNCTION_NAME,
            max_length=64,
        )
        response = await self._client.aio.models.generate_content(
            model=self.model,
            contents=scenario.task,
            config={
                "system_instruction": (
                    "You are evaluating an MCP tool catalog. Select exactly one function that "
                    "best satisfies the user's task. Do not execute it and do not invent tools."
                ),
                "tools": [
                    {
                        "function_declarations": [
                            _function_declaration(tool, tool_names.for_tool(tool)) for tool in tools
                        ]
                    }
                ],
                "tool_config": {"function_calling_config": {"mode": "ANY"}},
                "automatic_function_calling": {"disable": True},
            },
        )
        latency_ms = (perf_counter() - started_at) * 1000
        function_calls = list(getattr(response, "function_calls", None) or [])

        selected_tool: str | None = None
        provider_selected_tool: str | None = None
        arguments: dict[str, Any] = {}
        parse_error: str | None = None
        if function_calls:
            raw_selected_tool = getattr(function_calls[0], "name", None)
            if isinstance(raw_selected_tool, str):
                provider_selected_tool = raw_selected_tool
                selected_tool = tool_names.to_original(raw_selected_tool)
            arguments, parse_error = decode_object_arguments(
                getattr(function_calls[0], "args", {})
            )

        usage = getattr(response, "usage_metadata", None)
        resolved_model = getattr(response, "model_version", None)
        response_id = getattr(response, "response_id", None)
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
            message=_response_text(response),
            response_id=response_id if isinstance(response_id, str) else None,
            latency_ms=latency_ms,
            input_tokens=usage_value(usage, "prompt_token_count"),
            output_tokens=usage_value(usage, "candidates_token_count"),
            total_tokens=usage_value(usage, "total_token_count"),
        )
