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

Use the exact name returned by discovery. The placeholder below must be replaced with a returned
name; it is not a real registry entry:

```bash
SERVER_NAME='paste-exact-name-from-discovery'
mendpact registry inspect "$SERVER_NAME"
```

Select an exact historical version when needed:

```bash
mendpact registry inspect "$SERVER_NAME" --version 1.2.3
```

Inspection displays the registry lifecycle status, public repository, remote transports, package
identifiers, runtime hints, transport type, and required secret **names**. It intentionally omits
all environment-variable values.

## Prepare a validation candidate

After inspecting one exact entry, deliberately copy one advertised HTTPS Streamable HTTP URL from
the inspection output. MendPact requires the exact URL instead of automatically choosing among
multiple transports or endpoints:

```bash
REMOTE_URL='paste-exact-https-streamable-http-url-from-inspection'
mkdir -p reports/candidates
mendpact registry prepare "$SERVER_NAME" \
  --remote-url "$REMOTE_URL" \
  --output reports/candidates/registry-candidate.json
```

The resulting `mendpact.registry-validation-candidate.v1` artifact binds the concrete returned
version, publisher namespace, repository, lifecycle status, advertised remotes, selected remote,
required package-secret names, and a recomputable normalized-record digest. It rejects
non-advertised URLs, non-Streamable-HTTP
transports, plaintext HTTP, embedded credentials, query strings, fragments, localhost, and private
IP literals. This check is structural and performs no DNS lookup; normal scan target validation
still resolves and checks the host immediately before a permitted connection.

The embedded source projection makes later local edits detectable because its digest can be
recomputed and the selected endpoint must remain in the advertised list. The artifact is still
unsigned locally captured metadata: it does not cryptographically prove what the registry served.

From a clean MendPact source checkout with its editable environment active, create a private
offline workspace from the candidate:

```bash
mendpact validation prepare video-review \
  --candidate reports/candidates/registry-candidate.json
```

This copies the candidate into the ignored mode-700 workspace, binds its exact bytes in the
workspace manifest, and pre-fills only the target alias and URL in `authorization.json`. The
authorization remains `draft`: MendPact does not infer permission from registry publication,
HTTPS, or publisher identity. Review the repository, obtain permission, complete the approval
record, then run `mendpact validation preflight` before any network operation.

## Trust boundary

Search, inspection, candidate preparation, and draft-workspace preparation keep these boundaries:

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

For an endpoint you already own or are otherwise authorized to contact, a direct scan remains
available:

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
