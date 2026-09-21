# Security boundary

MendPact inspects systems that may be untrusted. Safety therefore depends on keeping discovery,
execution, credentials, and stored evidence within explicit boundaries.

## Implemented in v0.1

- HTTPS is required by default.
- URLs containing embedded credentials are rejected.
- Hostnames are resolved before connection.
- Private, loopback, link-local, multicast, reserved, and unspecified addresses are blocked.
- Local development requires both `--allow-private` and `--allow-insecure-http` when applicable.
- Reports identify heuristic findings as findings rather than certifications.
- The conformance wrapper executes a pinned package with an argument list rather than a shell.
- Only the initialization scenario runs without explicit tool-call authorization.
- Behavioral replay discovers tool metadata but neither contacts a model nor invokes an MCP tool.
- Live behavioral evaluation asks a provider to select a tool but does not execute that tool.
- Model comparison reads local behavior-report JSON and makes no network request.

## Live model evaluation

The drivers read `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` from the process
environment and pass the selected credential directly to its official SDK. MendPact does not
include provider keys in traces, reports, replay files, CLI arguments, Action inputs, or logs.
OpenAI requests set `store=False`; all drivers disable automatic or parallel execution controls
where their APIs expose them and request one function or tool choice.

Live evaluation sends the scenario task plus discovered MCP tool names, descriptions, and input
schemas to the selected provider. Do not use it when those values contain data that cannot be
shared with that provider. Reports retain normalized choices, response identifiers, latency, and
token counts but not the complete provider response. Provider-side retention remains governed by
the selected account and API terms. Real `.env` files remain ignored; `.env.example` contains only
empty variable names.

The GitHub Action's live `evaluate` mode defaults to a 10-trial ceiling and checks the requested
scenario/repetition product before calling a provider. Provider keys belong in GitHub Actions
secrets mapped to environment variables, never in `with:` inputs. Use protected manual workflows
for live checks and offline replay for routine pull requests.

## Authenticated targets

- `auth-check` never loads a token, and Action auth mode rejects `auth-token-env`.
- Bearer token values are loaded only from explicitly named environment variables.
- Tokens are never accepted in policy files, CLI arguments, Action inputs, or target URLs.
- The configured token is defensively removed from captured MCP exceptions before reporting.
- OAuth metadata requests are unauthenticated, HTTPS-only, do not follow redirects, and remain
  subject to MendPact's private-address boundary.
- Protected-resource identifiers and authorization-server issuers are compared exactly.
- MendPact consumes a pre-issued token; it does not persist, refresh, mint, or validate the claims
  of that token.
- A successful metadata preflight does not prove token issuance, token audience, scope
  enforcement, or authorization on individual MCP methods.

## Conformance execution

The official conformance suite can invoke MCP tools. A full suite must never be aimed at a
production server unless every possible side effect is understood and accepted. MendPact
defaults to `server-initialize`; any other scenario or suite requires `--allow-tool-calls` and
should run against an isolated fixture with disposable data and credentials.

The first conformance invocation downloads the pinned npm package through `npx` into an ephemeral
cache rather than modifying the user's global npm cache. Pinning limits unexpected upstream
changes but does not eliminate package-registry or transitive-dependency risk. Hosted execution
will require a prebuilt, verified runner image without runtime installs.

## Known limitation

Pre-connection DNS resolution alone does not fully prevent DNS rebinding because the MCP SDK
performs its own network connection. Before operating MendPact as a public scanning service,
route all target traffic through an egress proxy that revalidates the connected address and
blocks private ranges.

## Required before stdio/repository scanning

- one ephemeral container or microVM per target;
- read-only root filesystem and fresh workspace;
- no inherited secrets;
- network disabled unless a test explicitly grants an allowlisted destination;
- CPU, memory, process, file-size, and wall-clock limits;
- structured redaction before trace persistence;
- short-lived, least-privilege credentials only.

Security reports should go through a private disclosure process once a public repository exists.
