"""Read-only discovery through the official MCP Registry."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from hashlib import sha256
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import httpx2
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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


class RegistryValidationRemote(BaseModel):
    """One deliberately selected, structurally safe remote endpoint."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["streamable-http"] = "streamable-http"
    url: str = Field(max_length=2_048)


class RegistryValidationAdvertisedRemote(BaseModel):
    """One normalized remote retained from the exact registry record."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(max_length=100)
    url: str = Field(max_length=2_048)


class RegistryValidationSourceRecord(BaseModel):
    """Bounded registry fields required to verify a candidate internally."""

    model_config = ConfigDict(extra="forbid")

    server_name: str = Field(max_length=255)
    server_version: str = Field(max_length=255)
    registry_status: str = Field(max_length=100)
    repository_url: str | None = Field(default=None, max_length=2_048)
    advertised_remotes: list[RegistryValidationAdvertisedRemote] = Field(max_length=100)
    required_package_secret_names: list[str] = Field(default_factory=list, max_length=100)


class RegistryValidationCandidate(BaseModel):
    """Provenance-bound handoff from registry metadata to human authorization."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.registry-validation-candidate.v1"] = (
        "mendpact.registry-validation-candidate.v1"
    )
    registry: Literal["https://registry.modelcontextprotocol.io"] = (
        "https://registry.modelcontextprotocol.io"
    )
    source_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_record: RegistryValidationSourceRecord
    identity: str = Field(max_length=500)
    selected_remote: RegistryValidationRemote
    review_warnings: list[str] = Field(default_factory=list, max_length=20)
    next_step: Literal[
        "Review the source and obtain permission, then create a draft validation workspace."
    ] = (
        "Review the source and obtain permission, then create a draft validation workspace."
    )
    execution_boundary: Literal[
        "Registry metadata only; the selected MCP endpoint was not contacted, no package was "
        "installed, and no credential was loaded."
    ] = (
        "Registry metadata only; the selected MCP endpoint was not contacted, no package was "
        "installed, and no credential was loaded."
    )

    @model_validator(mode="after")
    def validate_candidate(self) -> RegistryValidationCandidate:
        secrets = self.source_record.required_package_secret_names
        if secrets != sorted(set(secrets)):
            raise ValueError("required package secret names must be unique and sorted")
        remotes = [
            (remote.type.lower().replace("_", "-"), remote.url)
            for remote in self.source_record.advertised_remotes
        ]
        if remotes != sorted(set(remotes)):
            raise ValueError("advertised remotes must be unique and sorted")
        if self.source_record_sha256 != _source_record_sha256(self.source_record):
            raise ValueError("source record digest does not match the embedded metadata")
        if self.identity != registry_identity(self.source_record.server_name):
            raise ValueError("registry identity does not match the embedded server name")
        if (self.selected_remote.type, self.selected_remote.url) not in remotes:
            raise ValueError("selected remote is not present in the embedded source record")
        _validate_remote_url(self.selected_remote.url)
        return self


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


def _source_record_sha256(record: RegistryValidationSourceRecord) -> str:
    canonical = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return sha256(canonical).hexdigest()


def _validate_remote_url(selected: str) -> None:
    try:
        if any(character.isspace() for character in selected):
            raise ValueError
        parts = urlsplit(selected)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError
        _ = parts.port
        hostname = parts.hostname.rstrip(".").lower()
        if hostname == "localhost":
            raise ValueError
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            if any(
                (
                    address.is_private,
                    address.is_loopback,
                    address.is_link_local,
                    address.is_multicast,
                    address.is_reserved,
                    address.is_unspecified,
                )
            ):
                raise ValueError
    except ValueError as exc:
        raise RegistryError(
            "The selected validation endpoint must be public HTTPS without credentials, "
            "query parameters, or fragments."
        ) from exc


def _validation_remote(record: RegistryRecord, remote_url: str) -> RegistryValidationRemote:
    selected = remote_url.strip()
    matching = [
        remote
        for remote in record.server.remotes
        if remote.url == selected
        and remote.type.lower().replace("_", "-") == "streamable-http"
    ]
    if len(matching) != 1:
        raise RegistryError(
            "--remote-url must exactly match one advertised Streamable HTTP endpoint."
        )
    _validate_remote_url(selected)
    return RegistryValidationRemote(url=selected)


def validation_candidate_from_record(
    record: RegistryRecord,
    *,
    remote_url: str,
) -> RegistryValidationCandidate:
    """Create a non-executable candidate from one exact reviewed registry record."""

    selected_remote = _validation_remote(record, remote_url)
    secrets = _required_secret_names(record)
    advertised_remotes = sorted(
        {
            (remote.type.lower().replace("_", "-"), remote.url)
            for remote in record.server.remotes
        }
    )
    source_record = RegistryValidationSourceRecord(
        server_name=record.server.name,
        server_version=record.server.version,
        registry_status=record.official.status,
        repository_url=(
            record.server.repository.url if record.server.repository is not None else None
        ),
        advertised_remotes=[
            RegistryValidationAdvertisedRemote(type=remote_type, url=url)
            for remote_type, url in advertised_remotes
        ],
        required_package_secret_names=secrets,
    )
    warnings: list[str] = []
    if record.official.status != "active":
        warnings.append(f"Registry lifecycle status is {record.official.status!r}, not 'active'.")
    if secrets:
        warnings.append(
            "Package delivery metadata advertises required secrets; this does not establish "
            "the selected remote's authentication requirements."
        )
    return RegistryValidationCandidate(
        source_record_sha256=_source_record_sha256(source_record),
        source_record=source_record,
        identity=registry_identity(record.server.name),
        selected_remote=selected_remote,
        review_warnings=warnings,
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
        record = RegistryRecord.model_validate(payload)
    except ValidationError as exc:
        raise RegistryError(
            "Official MCP Registry returned an unsupported server document."
        ) from exc
    if record.server.name != normalized_name:
        raise RegistryError("Official MCP Registry returned a different server identity.")
    if normalized_version != "latest" and record.server.version != normalized_version:
        raise RegistryError("Official MCP Registry returned a different server version.")
    return record


async def prepare_registry_validation_candidate(
    server_name: str,
    *,
    version: str,
    remote_url: str,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> RegistryValidationCandidate:
    """Fetch exact registry metadata and bind one explicitly selected remote endpoint."""

    record = await inspect_registry_server(
        server_name,
        version=version,
        transport=transport,
    )
    return validation_candidate_from_record(record, remote_url=remote_url)
