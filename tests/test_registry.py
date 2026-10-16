import json
from urllib.parse import unquote

import httpx2
import pytest

from mendpact.registry import (
    RegistryError,
    candidate_from_record,
    inspect_registry_server,
    registry_identity,
    registry_search_terms,
    search_registry,
)


def _record(
    name: str,
    *,
    title: str | None = None,
    description: str | None = None,
    package: bool = False,
    remote: bool = True,
) -> dict[str, object]:
    server: dict[str, object] = {
        "name": name,
        "version": "1.2.3",
        "title": title,
        "description": description,
    }
    if remote:
        server["remotes"] = [
            {"type": "streamable-http", "url": "https://mcp.example.test/mcp"}
        ]
    if package:
        server["packages"] = [
            {
                "registryType": "npm",
                "identifier": "@example/video-mcp",
                "version": "1.2.3",
                "runtimeHint": "npx",
                "transport": {"type": "stdio"},
                "environmentVariables": [
                    {
                        "name": "VIDEO_API_KEY",
                        "isRequired": True,
                        "isSecret": True,
                        "value": "must-not-survive-parsing",
                    },
                    {
                        "name": "OPTIONAL_REGION",
                        "isRequired": False,
                        "isSecret": False,
                    },
                ],
            }
        ]
    return {
        "server": server,
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "status": "active",
                "isLatest": True,
                "publishedAt": "2026-01-01T00:00:00Z",
            }
        },
    }


@pytest.mark.anyio
async def test_search_uses_bounded_terms_deduplicates_and_ranks_metadata() -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        term = request.url.params["search"]
        records = {
            "video": [
                _record(
                    "com.example/video-library",
                    title="Video library",
                    description="Search stored video clips.",
                ),
                _record(
                    "com.example/video-editor",
                    title="Video editor",
                    description="Edit video scenes and captions.",
                    package=True,
                ),
            ],
            "editing": [
                _record(
                    "com.example/video-editor",
                    title="Video editor",
                    description="Edit video scenes and captions.",
                    package=True,
                )
            ],
            "edit": [],
        }[term]
        return httpx2.Response(200, json={"servers": records, "metadata": {}})

    report = await search_registry(
        "  video   editing ",
        limit=2,
        transport=httpx2.MockTransport(handler),
    )

    assert report.query == "video editing"
    assert report.registry_queries == ["video", "editing", "edit"]
    assert [result.name for result in report.results] == [
        "com.example/video-editor",
        "com.example/video-library",
    ]
    assert report.results[0].delivery == [
        "package:npx",
        "remote:streamable-http",
    ]
    assert report.results[0].required_secret_names == ["VIDEO_API_KEY"]
    assert len(requests) == 3
    assert all(request.method == "GET" for request in requests)
    assert all(request.url.host == "registry.modelcontextprotocol.io" for request in requests)
    assert all(request.url.params["version"] == "latest" for request in requests)


@pytest.mark.anyio
async def test_inspect_fetches_encoded_exact_name_and_does_not_follow_redirects() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(
            200,
            json=_record(
                "io.github.acme/video-tools",
                title="Video tools",
                package=True,
            ),
        )

    record = await inspect_registry_server(
        "io.github.acme/video-tools",
        transport=httpx2.MockTransport(handler),
    )

    assert record.server.name == "io.github.acme/video-tools"
    assert registry_identity(record.server.name) == "GitHub namespace: acme"
    assert unquote(seen[0].url.path) == (
        "/v0.1/servers/io.github.acme/video-tools/versions/latest"
    )
    assert seen[0].headers["accept"] == "application/json"
    assert "authorization" not in seen[0].headers


def test_candidate_projection_omits_environment_values() -> None:
    from mendpact.registry import RegistryRecord

    raw = _record("com.example/video-editor", package=True)
    record = RegistryRecord.model_validate(raw)
    candidate = candidate_from_record(record)

    assert candidate.required_secret_names == ["VIDEO_API_KEY"]
    assert "must-not-survive-parsing" not in candidate.model_dump_json()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx2.Response(503), "HTTP 503"),
        (httpx2.Response(200, text="not json"), "invalid JSON"),
        (httpx2.Response(200, json={"servers": "wrong"}), "unsupported"),
        (
            httpx2.Response(
                200,
                json={
                    "servers": [
                        _record("com.example/video", description="x" * 5_001)
                    ]
                },
            ),
            "unsupported",
        ),
    ],
)
async def test_search_rejects_registry_failures(
    response: httpx2.Response,
    message: str,
) -> None:
    transport = httpx2.MockTransport(lambda request: response)

    with pytest.raises(RegistryError, match=message):
        await search_registry("video", transport=transport)


@pytest.mark.anyio
async def test_registry_response_size_is_bounded() -> None:
    payload = json.dumps({"servers": [], "padding": "x" * 2_000_001})
    transport = httpx2.MockTransport(lambda request: httpx2.Response(200, text=payload))

    with pytest.raises(RegistryError, match="exceeded"):
        await search_registry("video", transport=transport)


@pytest.mark.anyio
async def test_inspect_rejects_invalid_name_without_network_access() -> None:
    called = False

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal called
        called = True
        return httpx2.Response(200, json={})

    with pytest.raises(RegistryError, match="namespace"):
        await inspect_registry_server(
            "https://attacker.example/mcp",
            transport=httpx2.MockTransport(handler),
        )

    assert called is False


@pytest.mark.parametrize(
    ("query", "terms"),
    [
        ("video editing", ["video", "editing", "edit"]),
        ("files", ["files", "file"]),
        ("status", ["status"]),
    ],
)
def test_registry_search_terms_are_deterministic(query: str, terms: list[str]) -> None:
    assert registry_search_terms(query) == terms


def test_registry_search_terms_reject_empty_or_oversized_queries() -> None:
    with pytest.raises(RegistryError, match="empty"):
        registry_search_terms("   ")
    with pytest.raises(RegistryError, match="200"):
        registry_search_terms("x" * 201)
