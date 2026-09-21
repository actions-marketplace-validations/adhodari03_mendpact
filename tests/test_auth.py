from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest

from mendpact.adapters.mcp import _authenticated_transport
from mendpact.domain import ScanStatus
from mendpact.scanner import scan_mcp_url
from mendpact.security.auth import (
    AuthenticationConfigurationError,
    BearerAuthentication,
    load_bearer_authentication,
    redact_authentication,
    render_exception,
)
from mendpact.security.targets import TargetPolicy


def test_loads_bearer_token_without_exposing_it_in_representation() -> None:
    authentication = load_bearer_authentication(
        "MENDPACT_TOKEN",
        environment={"MENDPACT_TOKEN": "secret-token-value"},
    )

    assert authentication is not None
    assert authentication.headers == {"Authorization": "Bearer secret-token-value"}
    assert "secret-token-value" not in repr(authentication)


@pytest.mark.parametrize(
    ("environment_variable", "environment", "message"),
    [
        ("INVALID-NAME", {}, "valid environment name"),
        ("MISSING_TOKEN", {}, "is not set"),
        ("EMPTY_TOKEN", {"EMPTY_TOKEN": ""}, "is empty"),
        ("SPACE_TOKEN", {"SPACE_TOKEN": "secret value"}, "RFC 6750"),
        ("UNICODE_TOKEN", {"UNICODE_TOKEN": "secret-☃"}, "RFC 6750"),
    ],
)
def test_rejects_invalid_bearer_configuration_without_echoing_values(
    environment_variable: str,
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(AuthenticationConfigurationError, match=message) as captured:
        load_bearer_authentication(environment_variable, environment=environment)

    assert "secret value" not in str(captured.value)


def test_redacts_bearer_token_from_error_boundary() -> None:
    authentication = BearerAuthentication(
        environment_variable="MENDPACT_TOKEN",
        token="secret-token-value",
    )

    rendered = redact_authentication(
        "server echoed Bearer secret-token-value",
        authentication,
    )

    assert rendered == "server echoed Bearer [REDACTED]"


def test_renders_actionable_leaves_from_nested_exception_group() -> None:
    exception = ExceptionGroup(
        "unhandled errors in a TaskGroup",
        [
            ConnectionError("connection refused"),
            ExceptionGroup("request failed", [TimeoutError("connection timed out")]),
        ],
    )

    rendered = render_exception(exception, None)

    assert rendered == (
        "ConnectionError: connection refused; TimeoutError: connection timed out"
    )


def test_bounds_nested_exception_details() -> None:
    exception = ExceptionGroup(
        "many failures",
        [RuntimeError(f"failure {index}") for index in range(6)],
    )

    rendered = render_exception(exception, None)

    assert "RuntimeError: failure 0" in rendered
    assert "RuntimeError: failure 3" in rendered
    assert "failure 4" not in rendered
    assert rendered.endswith("Additional nested errors omitted.")


@pytest.mark.anyio
async def test_authenticated_transport_configures_default_http_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    @asynccontextmanager
    async def fake_http_client(*, headers: dict[str, str], **kwargs: object) -> Any:
        captured["headers"] = headers
        yield object()

    @asynccontextmanager
    async def fake_transport(target: str, *, http_client: object) -> Any:
        captured["target"] = target
        captured["http_client"] = http_client
        yield (object(), object())

    monkeypatch.setattr("mendpact.adapters.mcp.httpx2.AsyncClient", fake_http_client)
    monkeypatch.setattr("mendpact.adapters.mcp.streamable_http_client", fake_transport)
    authentication = BearerAuthentication(
        environment_variable="MENDPACT_TOKEN",
        token="secret-token-value",
    )

    async with _authenticated_transport(
        "https://api.example.com/mcp",
        authentication,
    ):
        pass

    assert captured["headers"] == {"Authorization": "Bearer secret-token-value"}
    assert captured["target"] == "https://api.example.com/mcp"


@pytest.mark.anyio
async def test_scan_report_redacts_token_echoed_by_remote_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authentication = BearerAuthentication(
        environment_variable="MENDPACT_TOKEN",
        token="secret-token-value",
    )

    async def fake_validate(*args: object, **kwargs: object) -> None:
        return None

    async def fake_discover(*args: object, **kwargs: object) -> None:
        raise RuntimeError("server echoed secret-token-value")

    async def fake_oauth_metadata(*args: object, **kwargs: object) -> tuple[None, list[object]]:
        return None, []

    monkeypatch.setattr("mendpact.scanner.validate_target_url", fake_validate)
    monkeypatch.setattr("mendpact.scanner.discover_mcp_target", fake_discover)
    monkeypatch.setattr("mendpact.scanner.inspect_oauth_metadata", fake_oauth_metadata)

    report = await scan_mcp_url(
        "https://api.example.com/mcp",
        policy=TargetPolicy(),
        authentication=authentication,
    )

    assert report.status == ScanStatus.ERROR
    assert "secret-token-value" not in report.model_dump_json()
    assert "[REDACTED]" in report.errors[0]


@pytest.mark.anyio
async def test_scan_report_exposes_nested_connection_error_without_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authentication = BearerAuthentication(
        environment_variable="MENDPACT_TOKEN",
        token="secret-token-value",
    )

    async def fake_validate(*args: object, **kwargs: object) -> None:
        return None

    async def fake_discover(*args: object, **kwargs: object) -> None:
        raise ExceptionGroup(
            "unhandled errors in a TaskGroup",
            [ConnectionError("connection refused for secret-token-value")],
        )

    async def fake_oauth_metadata(*args: object, **kwargs: object) -> tuple[None, list[object]]:
        return None, []

    monkeypatch.setattr("mendpact.scanner.validate_target_url", fake_validate)
    monkeypatch.setattr("mendpact.scanner.discover_mcp_target", fake_discover)
    monkeypatch.setattr("mendpact.scanner.inspect_oauth_metadata", fake_oauth_metadata)

    report = await scan_mcp_url(
        "https://api.example.com/mcp",
        policy=TargetPolicy(),
        authentication=authentication,
    )

    assert report.status == ScanStatus.ERROR
    assert report.errors == ["ConnectionError: connection refused for [REDACTED]"]
    assert "secret-token-value" not in report.model_dump_json()
