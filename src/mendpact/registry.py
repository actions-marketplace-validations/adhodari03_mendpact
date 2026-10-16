"""Read-only discovery through the official MCP Registry."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any, Literal
from urllib.parse import quote

import httpx2
from pydantic import BaseModel, ConfigDict, Field, ValidationError

OFFICIAL_REGISTRY_URL = "https://registry.modelcontextprotocol.io"
REGISTRY_SCHEMA_VERSION: Literal["mendpact.registry-discovery.v1"] = (
    "mendpact.registry-discovery.v1"
)
_OFFICIAL_METADATA_KEY = "io.modelcontextprotocol.registry/official"
_MAX_RESPONSE_BYTES = 2_000_000
_MAX_QUERY_CHARACTERS = 200
_MAX_SEARCH_TERMS = 5
_SERVER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_WORD = re.compile(r"[a-z0-9][a-z0-9._-]*")


class RegistryError(ValueError):
    """Raised when registry discovery cannot produce trustworthy metadata."""


class RegistryEnvironmentVariable(BaseModel):
    """Non-value metadata for one package environment variable."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str = Field(max_length=255)
    description: str | None = Field(default=None, max_length=2_000)
    is_required: bool = Field(default=False, alias="isRequired")
    is_secret: bool = Field(default=False, alias="isSecret")


class RegistryPackage(BaseModel):
    """Install metadata retained without executing the package."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    registry_type: str = Field(alias="registryType", max_length=100)
    identifier: str = Field(max_length=1_024)
    version: str | None = Field(default=None, max_length=255)
    runtime_hint: str | None = Field(default=None, alias="runtimeHint", max_length=100)
    transport: dict[str, Any] = Field(default_factory=dict)
    environment_variables: list[RegistryEnvironmentVariable] = Field(
        default_factory=list,
        alias="environmentVariables",
        max_length=100,
    )


class RegistryRemote(BaseModel):
    """Public remote transport advertised by a registry entry."""

    model_config = ConfigDict(extra="ignore")

    type: str = Field(max_length=100)
    url: str = Field(max_length=2_048)


class RegistryRepository(BaseModel):
    """Public source repository advertised by a registry entry."""

    model_config = ConfigDict(extra="ignore")

    url: str = Field(max_length=2_048)
    source: str | None = Field(default=None, max_length=100)
    id: str | None = Field(default=None, max_length=255)
    subfolder: str | None = Field(default=None, max_length=1_024)


class RegistryServer(BaseModel):
    """Useful, bounded subset of an official registry server document."""

    model_config = ConfigDict(extra="ignore")

    name: str = Field(max_length=255)
    title: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=5_000)
    version: str = Field(max_length=255)
    repository: RegistryRepository | None = None
    packages: list[RegistryPackage] = Field(default_factory=list, max_length=100)
    remotes: list[RegistryRemote] = Field(default_factory=list, max_length=100)


class RegistryOfficialMetadata(BaseModel):
    """Lifecycle metadata assigned by the official registry."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    status: str = Field(default="unknown", max_length=100)
    published_at: str | None = Field(default=None, alias="publishedAt", max_length=100)
    updated_at: str | None = Field(default=None, alias="updatedAt", max_length=100)
    is_latest: bool = Field(default=False, alias="isLatest")


class RegistryRecord(BaseModel):
    """One parsed server record plus registry-owned metadata."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    server: RegistryServer
    metadata: dict[str, Any] = Field(default_factory=dict, alias="_meta")

    @property
    def official(self) -> RegistryOfficialMetadata:
        value = self.metadata.get(_OFFICIAL_METADATA_KEY, {})
        if not isinstance(value, dict):
            value = {}
        return RegistryOfficialMetadata.model_validate(value)


class RegistryCandidate(BaseModel):
    """Privacy-minimized, non-executable discovery result."""

    name: str = Field(max_length=255)
    title: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=5_000)
    version: str = Field(max_length=255)
    status: str = Field(max_length=100)
    identity: str = Field(max_length=500)
    delivery: list[str] = Field(default_factory=list, max_length=200)
    required_secret_names: list[str] = Field(default_factory=list, max_length=100)


class RegistryDiscoveryReport(BaseModel):
    """Machine-readable output for one read-only registry search."""

    schema_version: Literal["mendpact.registry-discovery.v1"] = REGISTRY_SCHEMA_VERSION
    registry: str = OFFICIAL_REGISTRY_URL
    query: str
    registry_queries: list[str] = Field(max_length=_MAX_SEARCH_TERMS)
    result_count: int
    results: list[RegistryCandidate] = Field(max_length=50)
    execution_boundary: str = (
        "Registry metadata only; no MCP server was contacted and no package was installed or run."
    )


class _RegistryList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    servers: list[RegistryRecord]


def registry_identity(server_name: str) -> str:
    """Describe the namespace proof without claiming the server itself is safe."""

    namespace = server_name.partition("/")[0]
    if namespace.startswith("io.github.") and len(namespace) > len("io.github."):
        return f"GitHub namespace: {namespace.removeprefix('io.github.')}"
    return f"Domain namespace: {namespace}"


def _delivery(record: RegistryRecord) -> list[str]:
    values: set[str] = set()
    for remote in record.server.remotes:
        values.add(f"remote:{remote.type}")
    for package in record.server.packages:
        runtime = package.runtime_hint or package.registry_type
        values.add(f"package:{runtime}")
    return sorted(values)


def _required_secret_names(record: RegistryRecord) -> list[str]:
    return sorted(
        {
            variable.name
            for package in record.server.packages
            for variable in package.environment_variables
            if variable.is_required and variable.is_secret
        }
    )


def candidate_from_record(record: RegistryRecord) -> RegistryCandidate:
    """Project one raw registry record into safe discovery output."""

    server = record.server
    return RegistryCandidate(
        name=server.name,
        title=server.title,
        description=server.description,
        version=server.version,
        status=record.official.status,
        identity=registry_identity(server.name),
        delivery=_delivery(record),
        required_secret_names=_required_secret_names(record),
    )


def _validate_query(query: str) -> str:
    normalized = " ".join(query.split())
    if not normalized:
        raise RegistryError("Discovery query must not be empty.")
    if len(normalized) > _MAX_QUERY_CHARACTERS:
        raise RegistryError(
            f"Discovery query must not exceed {_MAX_QUERY_CHARACTERS} characters."
        )
    return normalized


def _stem(term: str) -> str | None:
    for suffix, minimum in (("ing", 6), ("ed", 5)):
        if term.endswith(suffix) and len(term) >= minimum:
            return term[: -len(suffix)]
    if term.endswith("s") and not term.endswith(("ss", "us")) and len(term) >= 4:
        return term[:-1]
    return None


def registry_search_terms(query: str) -> list[str]:
    """Create a small, deterministic set of name-search probes from user intent."""

    normalized = _validate_query(query).lower()
    words = _WORD.findall(normalized)
    terms: list[str] = []
    for word in words:
        for candidate in (word, _stem(word)):
            if candidate and candidate not in terms:
                terms.append(candidate)
            if len(terms) == _MAX_SEARCH_TERMS:
                return terms
    if not terms:
        raise RegistryError("Discovery query must contain letters or numbers.")
    return terms


def _rank(record: RegistryRecord, query: str) -> int:
    server = record.server
    name = server.name.lower()
    title = (server.title or "").lower()
    description = (server.description or "").lower()
    normalized = query.lower()
    score = 0
    if normalized in f"{name} {title} {description}":
        score += 25
    for term in registry_search_terms(query):
        if term in name:
            score += 10
        if term in title:
            score += 6
        if term in description:
            score += 3
    if record.official.status == "active":
        score += 1
    return score


def _deduplicate(records: Iterable[RegistryRecord]) -> list[RegistryRecord]:
    selected: dict[tuple[str, str], RegistryRecord] = {}
    for record in records:
        selected.setdefault((record.server.name, record.server.version), record)
    return list(selected.values())


async def _registry_json(
    client: httpx2.AsyncClient,
    path: str,
    *,
    params: dict[str, str | int] | None = None,
) -> object:
    try:
        async with client.stream("GET", path, params=params) as response:
            if response.status_code != 200:
                raise RegistryError(
                    f"Official MCP Registry returned HTTP {response.status_code}."
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise RegistryError(
                        f"Official MCP Registry response exceeded {_MAX_RESPONSE_BYTES} bytes."
                    )
    except RegistryError:
        raise
    except httpx2.HTTPError as exc:
        raise RegistryError(
            f"Could not reach the official MCP Registry: {type(exc).__name__}."
        ) from exc
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError("Official MCP Registry returned invalid JSON.") from exc


def _client(transport: httpx2.AsyncBaseTransport | None) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        base_url=OFFICIAL_REGISTRY_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "mendpact-registry-discovery",
        },
        follow_redirects=False,
        timeout=httpx2.Timeout(10.0),
        transport=transport,
    )


async def search_registry(
    query: str,
    *,
    limit: int = 10,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> RegistryDiscoveryReport:
    """Search official registry names using bounded intent terms and rank their metadata."""

    normalized = _validate_query(query)
    if not 1 <= limit <= 50:
        raise RegistryError("Discovery result limit must be between 1 and 50.")
    terms = registry_search_terms(normalized)
    records: list[RegistryRecord] = []
    request_limit = min(max(limit * 5, 20), 100)
    async with _client(transport) as client:
        for term in terms:
            payload = await _registry_json(
                client,
                "/v0.1/servers",
                params={"search": term, "version": "latest", "limit": request_limit},
            )
            try:
                records.extend(_RegistryList.model_validate(payload).servers)
            except ValidationError as exc:
                raise RegistryError(
                    "Official MCP Registry returned an unsupported server-list document."
                ) from exc

    ranked = sorted(
        _deduplicate(records),
        key=lambda record: (-_rank(record, normalized), record.server.name),
    )[:limit]
    candidates = [candidate_from_record(record) for record in ranked]
    return RegistryDiscoveryReport(
        query=normalized,
        registry_queries=terms,
        result_count=len(candidates),
        results=candidates,
    )


async def inspect_registry_server(
    server_name: str,
    *,
    version: str = "latest",
    transport: httpx2.AsyncBaseTransport | None = None,
) -> RegistryRecord:
    """Fetch one exact registry record without contacting or running the MCP server."""

    normalized_name = server_name.strip()
    normalized_version = version.strip()
    if not _SERVER_NAME.fullmatch(normalized_name):
        raise RegistryError(
            "Server name must use a registry namespace and name, for example "
            "io.github.example/video-tools."
        )
    if not normalized_version or len(normalized_version) > 255:
        raise RegistryError("Registry version must contain between 1 and 255 characters.")
    path = (
        f"/v0.1/servers/{quote(normalized_name, safe='')}/versions/"
        f"{quote(normalized_version, safe='')}"
    )
    async with _client(transport) as client:
        payload = await _registry_json(client, path)
    try:
        return RegistryRecord.model_validate(payload)
    except ValidationError as exc:
        raise RegistryError(
            "Official MCP Registry returned an unsupported server document."
        ) from exc
