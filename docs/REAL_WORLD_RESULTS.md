# Real-world MCP validation results

This document records sanitized, reproducible observations from independently developed open-source
servers. It is not a security audit, safety certification, ecosystem benchmark, or measurement of
precision/recall. Raw reports, server logs, local target URLs, and history databases remain in the
ignored `reports/validation/` workspace.

## September 7, 2026 — first validation set

Scope was metadata discovery only: two sequential scans per runnable target followed by offline
contract diff, evidence export, history import, and rule re-evaluation. No MCP tool was called, no
provider model was used, no credential was loaded, and no hosted third-party MCP endpoint was
contacted. Both processes ran on loopback with an otherwise empty environment.

| Target | Reproducible source | Environment | Observed surface | Released-rule result |
| --- | --- | --- | --- | --- |
| Fastly MCP 2.1.5 | [MIT source](https://github.com/fastly/mcp/tree/905d1485b189bf07e4d86ef3d935a1f67321f66d) | Node 22.23.1; Streamable HTTP; MCP 2026-07-28 | 3 tools, 0 resources, 0 prompts; stable across two scans | Passed at `high`; only plaintext loopback HTTP reported (`MP-NET-001`, medium) |
| Streamable HTTP TypeScript starter 0.1.0 | [MIT source](https://github.com/ferrants/mcp-streamable-http-typescript-server/tree/719131a8ff0f0727b2770bd4bd9d7eb858387efe) | Node 22.23.1; stateful Streamable HTTP implementation; MCP 2024-11-05 negotiated | 3 tools, 0 resources, 0 prompts; stable across two scans | Passed at `high`; only plaintext loopback HTTP reported (`MP-NET-001`, medium) |
| IMF MCP 0.4.1 | [Apache-2.0 source](https://github.com/cyanheads/imf-mcp-server/tree/0145c2866722a6095053e1e220aaf839a49725c1) | Requires Bun 1.3+/Node 24+ or Docker | Not scanned | Blocked before build because the local Docker daemon was not running; no service was started |

The two completed contract diffs contained zero changes. This establishes repeatability for those
short, unchanged runs only. It does not establish long-term stability or complete runtime behavior.

## Findings that changed MendPact

### 1. Code-execution false negative

Fastly intentionally exposes `search`, `inspect`, and `execute`. Its `execute` tool accepts a
required `code` string and describes JavaScript execution with a pre-authenticated API client. The
released deterministic rules did not identify this generic name, so both scans passed the strict
`high` threshold. Source review and the discovered schema agreed that this is a consequential
capability; no call was needed to establish the metadata signal.

MendPact now emits critical `MP-MCP-007` when an explicit execution-oriented tool name is combined
with a `code`, `command`, `script`, or `shell_command` input field. The rule uses both signals to
avoid labeling a tool such as `execute_query(query_id)` as arbitrary code execution. Offline
re-evaluation of the saved Fastly graph produces `MP-MCP-007` for `tool:execute`. Tests use a
paraphrased synthetic graph rather than copied upstream metadata.

This is a heuristic warning, not a claim that Fastly's sandbox is exploitable. It says the tool
needs isolation, least-privilege credentials, and explicit behavior tests before production use.

### 2. Legacy protocol compatibility visibility

The TypeScript starter accepted MendPact's fallback handshake and negotiated `2024-11-05` while
serving a Streamable HTTP-style endpoint. The MCP specification documents that revision's HTTP+SSE
transport as deprecated and introduces Streamable HTTP in `2025-03-26` ([transport
specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)).
Discovery succeeded, so this is compatibility context rather than a vulnerability.

MendPact now emits low `MP-MCP-008` for the exact `2024-11-05` revision. It remains visible in
reports but does not fail the strict `high` policy. A current `2026-07-28` graph remains clear.

## Upstream and setup observations

- Fastly's committed `package.json` and `package-lock.json` did not pass `npm ci`: npm reported
  mismatched Fastly SDK and Biome versions. The disposable clone's lock was regenerated with
  lifecycle scripts disabled, and its resulting SHA-256 was recorded locally before installation.
  This is onboarding evidence, not a MendPact scan result; no upstream issue has been opened.
- The legacy starter logged MendPact's modern `server/discover` probe failing before the successful
  handshake fallback. This is expected compatibility behavior. Its log also said session entries
  remained after DELETE; that server behavior was not investigated beyond the approved discovery
  scope and is not presented as a confirmed defect.
- The first local workspace was created with system Python and exposed stale MendPact distribution
  metadata (`0.1.0` versus source/CLI `0.2.0`). The preparer now rejects a missing or mismatched
  installed version before creating a workspace. After reinstalling the editable package, the
  manifest recorded `0.2.0` correctly.

## Evidence and next validation

Each completed target has private scan artifacts, exact SHA-256 values, a local review, minimized
HTML evidence, and an isolated history database scheduled for manual review/deletion within 14
days. Nothing was prepared for public sharing. Sanitized facts above were checked against public
source at the exact revisions linked in the table.

The next useful run is the IMF server from its reviewed source once a suitable Bun/Node runtime or
Docker daemon is available. After that, prioritize a richer resource/prompt server and an
authenticated HTTPS target only with explicit owner permission and a separately reviewed
least-privilege credential. Keep provider behavior testing separate from metadata validation.
