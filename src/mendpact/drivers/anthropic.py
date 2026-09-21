"""Anthropic Messages API driver for observational tool-selection evaluations."""

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


class AnthropicDriverConfigurationError(RuntimeError):
    """Raised when the optional Anthropic driver cannot be configured."""


class _MessagesAPI(Protocol):
    async def create(self, **kwargs: Any) -> Any:
        """Create one Messages API result."""

        ...


class _AnthropicClient(Protocol):
    messages: _MessagesAPI


_ANTHROPIC_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _tool_definition(tool: CapabilityNode, provider_name: str) -> dict[str, Any]:
    return {
        "name": provider_name,
        "description": tool_description(tool),
        "input_schema": tool_input_schema(tool),
    }


def _text_content(content: list[Any]) -> str | None:
    text = "\n".join(
        block_text
        for block in content
        if getattr(block, "type", None) == "text"
        and isinstance((block_text := getattr(block, "text", None)), str)
        and block_text
    )
    return text or None


class AnthropicMessagesDriver:
    """Ask Claude to select an MCP tool without executing the returned tool call."""

    name = "anthropic"

    def __init__(
        self,
        model: str,
        *,
        client: _AnthropicClient | None = None,
        api_key: str | None = None,
        max_tokens: int = 256,
    ) -> None:
        if not model.strip():
            raise AnthropicDriverConfigurationError("An Anthropic model name is required.")
        if max_tokens < 1:
            raise AnthropicDriverConfigurationError("Anthropic max_tokens must be positive.")

        self.model = model
        self.max_tokens = max_tokens
        if client is not None:
            self._client = client
            return

        resolved_api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not resolved_api_key:
            raise AnthropicDriverConfigurationError(
                "ANTHROPIC_API_KEY is not set. Export it before using --driver anthropic."
            )
        try:
            anthropic_module = import_module("anthropic")
        except ImportError as exc:
            raise AnthropicDriverConfigurationError(
                "The Anthropic SDK is not installed. Install MendPact with the 'anthropic' extra."
            ) from exc
        self._client = anthropic_module.AsyncAnthropic(api_key=resolved_api_key)

    async def select_tool(
        self,
        scenario: BehaviorScenario,
        tools: list[CapabilityNode],
        attempt: int,
    ) -> ToolCallTrace:
        if not tools:
            raise AnthropicDriverConfigurationError(
                "The discovered MCP endpoint does not expose any tools to evaluate."
            )

        started_at = perf_counter()
        tool_names = build_provider_tool_names(
            tools,
            valid_name=_ANTHROPIC_TOOL_NAME,
            max_length=64,
        )
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=(
                "You are evaluating an MCP tool catalog. Select exactly one tool that best "
                "satisfies the user's task. Do not execute the tool and do not invent tools."
            ),
            messages=[{"role": "user", "content": scenario.task}],
            tools=[_tool_definition(tool, tool_names.for_tool(tool)) for tool in tools],
            tool_choice={"type": "any", "disable_parallel_tool_use": True},
        )
        latency_ms = (perf_counter() - started_at) * 1000
        content = list(getattr(response, "content", []))
        tool_calls = [block for block in content if getattr(block, "type", None) == "tool_use"]

        selected_tool: str | None = None
        provider_selected_tool: str | None = None
        arguments: dict[str, Any] = {}
        parse_error: str | None = None
        if tool_calls:
            raw_selected_tool = getattr(tool_calls[0], "name", None)
            if isinstance(raw_selected_tool, str):
                provider_selected_tool = raw_selected_tool
                selected_tool = tool_names.to_original(raw_selected_tool)
            arguments, parse_error = decode_object_arguments(getattr(tool_calls[0], "input", {}))

        usage = getattr(response, "usage", None)
        input_tokens = usage_value(usage, "input_tokens")
        output_tokens = usage_value(usage, "output_tokens")
        total_tokens = (
            input_tokens + output_tokens
            if input_tokens is not None and output_tokens is not None
            else None
        )
        resolved_model = getattr(response, "model", None)
        response_id = getattr(response, "id", None)
        return ToolCallTrace(
            scenario_id=scenario.id,
            attempt=attempt,
            provider=self.name,
            model=resolved_model if isinstance(resolved_model, str) else self.model,
            available_tools=sorted(tool.name for tool in tools),
            selected_tool=selected_tool,
            provider_selected_tool=provider_selected_tool,
            tool_call_count=len(tool_calls),
            arguments=arguments,
            arguments_parse_error=parse_error,
            message=_text_content(content),
            response_id=response_id if isinstance(response_id, str) else None,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
        )
