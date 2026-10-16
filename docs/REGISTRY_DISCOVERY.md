# MCP registry discovery

MendPact can search and inspect public metadata from the
[official MCP Registry](https://registry.modelcontextprotocol.io). Discovery helps a developer
find a plausible server before deciding whether to configure or scan it.

## Find candidates by intent

```bash
mendpact discover "video editing" --limit 10
```

The command breaks the intent into at most five bounded name-search probes, queries only the
official registry over HTTPS, removes duplicate name/version pairs, and ranks the returned
metadata against the original query. Results show:

- exact registry name and version;
- title or purpose;
- remote and package delivery mechanisms;
- GitHub or domain namespace identity;
- names of required variables marked as secrets, without their values.

Write the same privacy-minimized result to a new file when automation needs stable JSON:

```bash
mendpact discover "video editing" \
  --limit 10 \
  --output registry-discovery.json
```

The output uses schema `mendpact.registry-discovery.v1`. MendPact refuses to replace an existing
file.

## Inspect one exact entry

Use the exact name returned by discovery:

```bash
mendpact registry inspect com.example/video-editor
```

Select an exact historical version when needed:

```bash
mendpact registry inspect com.example/video-editor --version 1.2.3
```

Inspection displays the registry lifecycle status, public repository, remote transports, package
identifiers, runtime hints, transport type, and required secret **names**. It intentionally omits
all environment-variable values.

## Trust boundary

Both commands are metadata-only:

- only `https://registry.modelcontextprotocol.io` is contacted;
- registry redirects are not followed;
- responses are limited to 2 MB and request time is limited;
- no listed MCP endpoint or source repository is contacted;
- no package is downloaded, installed, or executed;
- no credential or model provider is loaded;
- registry-controlled strings are rendered as terminal text, not Rich markup.

The official registry verifies publisher namespace and package ownership. That proves control of a
publishing identity; it does not prove that the server is secure, reliable, suitable for a task, or
endorsed by the company a user may associate with its name.

After reviewing a candidate, deliberately copy a remote Streamable HTTP endpoint into a normal
MendPact scan:

```bash
mendpact scan https://reviewed-server.example/mcp --output report.json
```

The scan remains a separate action because it contacts the server. Local package execution is not
part of registry discovery and should eventually require an explicit sandboxed workflow.

## Search limitations

The official registry currently offers a simple case-insensitive substring search over server
names. MendPact improves multi-word queries by issuing bounded word and stem probes and ranking the
returned titles and descriptions, but this is not a complete semantic index. A server whose name
contains none of the probes may not appear even when its description is relevant.

Exit code `0` means the registry request and parsing succeeded, including a valid empty result.
Exit code `2` means the query, network request, registry response, or output write failed.
