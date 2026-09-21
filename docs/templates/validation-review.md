# MCP validation review — NOT RUN

Keep this working copy local. Fill in actual observations, not expected results.
Do not paste tokens, headers, customer data, or private server descriptions into an issue.

## Authorization and reproducibility

- Reviewer / UTC date:
- Target alias (use a non-sensitive label):
- Exact target URL (must match local `authorization.json`; no URL credentials/query secrets):
- Owner permission or documented testing permission / approved scope and local reference:
- Upstream repository, exact commit or image digest, license, transport:
- Launch instructions and configuration (secret names only, never values):
- Environment manifest reviewed; source working tree clean or changes explained:
- Policy selected, SHA-256, and reason (production HTTPS or isolated loopback):
- Discovery request budget / stop conditions agreed (maximum two scans in guarded runner):
- Auth required? Credential-free preflight outcome; no credentials provisioned by default:

## Results — leave blank until executed

| Operation | UTC time | Exit code | Artifact / SHA-256 | Observation |
| --- | --- | --- | --- | --- |
| Initial scan | | | | |
| Repeat scan, same server revision | | | | |
| Offline contract diff | | | | |
| Offline evidence export / history | | | | |

Exit 0 means the configured gate passed, not vulnerability-free. Exit 1 means a policy finding;
exit 2 means an operational/configuration error, not a successful validation. Export/history
success does not change the source report's verdict. Mark unavailable evidence as blocked.

## Finding triage (repeat for each finding)

- Rule / severity / subject (sanitize before sharing):
- What MendPact observed:
- Independent evidence: upstream schema/source/documentation and exact revision:
- Classification: confirmed concern / expected capability / suspected false positive / unknown:
- Reason and reviewer confidence:
- Reproduction using a minimal synthetic fixture (no copied sensitive payload):
- Proposed regression test or product/docs fix:
- Follow-up issue (only after review) / owner:

## Scope and limitations

- Expected tools/resources/prompts checked against independent source:
- Missing capabilities, crashes, unsupported transport/schema, or confusing messages:
- Did repeated discovery change? Explain legitimate dynamic metadata vs possible defect:
- Tool execution: NOT PERFORMED (unless separately authorized and recorded):
- Provider evaluation: NOT PERFORMED (unless separately budgeted and recorded):
- Customer workload / load testing: NOT PERFORMED:
- No precision, recall, safety certification, or provider compatibility claim from this sample.

## Closeout

- Actual conclusion: not run / blocked / completed with limitations:
- Reviewed minimized summary; raw evidence remains local:
- Explicit permission for any public disclosure (default: none):
- Cleanup due date from manifest; manually remove raw artifacts within 14 days or sooner:
- History cleanup handled separately; copies/backups are not erased by history prune:
