# Static public evidence

MendPact can prepare a reviewed sharing package as a small static site for a separate GitHub Pages
or static-hosting step. Preparation and verification are local and offline. They do not push a
commit, call GitHub, upload files, or create a public URL.

This workflow does not publish raw scan data. Start with the privacy-minimized, exact-byte review
process in the [sharing guide](SHARING.md).

## Prepare the static directory

After inspecting and acknowledging the exact sharing ZIP, run:

```bash
mendpact share prepare-site reports/review-package.zip \
  --approval reports/sharing-approval.json \
  --output reports/public-evidence
```

The command revalidates the package and its current, matching acknowledgement before creating a
new directory. It never replaces an existing directory. The output contains exactly:

| File | Purpose |
| --- | --- |
| `index.html` | Canonical, script-free minimized evidence page from the reviewed ZIP |
| `summary.json` | Canonical versioned aggregate evidence from the reviewed ZIP |
| `publication.json` | Versioned manifest binding file digests to the package and approval window |
| `.nojekyll` | Tells GitHub Pages to serve the directory as plain static files |

The publication manifest records the package and source SHA-256 values, source schema and capture
time, recorded result, preparation time, acknowledgement expiry, artifact digests, and a fixed
limitation statement. It contains no reviewer identity or signature.

## Verify immediately before publishing

```bash
mendpact share verify-site reports/public-evidence \
  --package reports/review-package.zip \
  --approval reports/sharing-approval.json
```

Verification requires the original reviewed ZIP and receipt. It checks the current approval
window, all four filenames, regular-file and symlink boundaries, bounded sizes, canonical JSON and
HTML bytes, and every recorded digest. Extra or changed files fail closed. The directory itself is
not a source of trust: its manifest is unsigned and could be rewritten together with its files.

Keep the verified directory unchanged between this check and your separate publishing step. Do
not add the private source report, review ZIP, or receipt to the public directory.

## Use with GitHub Pages

Publish the four generated files from a repository or branch intended for evidence, rather than
replacing MendPact's own project website. Review the pending Git diff and repository visibility
before committing. Configure GitHub Pages to deploy that exact directory through a reviewed
workflow, then verify the deployed URL manually.

MendPact deliberately does not run `git`, create a pull request, change Pages settings, or upload
the directory. That preserves a visible human boundary between acknowledgement and publication.
An authenticated publisher can be added later after access control, deletion, expiry, and
revocation behavior have been designed.

## Expiry and removal

An acknowledgement is valid for at most 14 days and must still be current when preparing or
verifying the site. Expiry does not remove an already published page, revoke downloaded files, or
make old evidence fresh. Removing a published page remains the publisher's responsibility.

The recorded `passed`, `failed`, or `error` result is preserved. Successful preparation means the
files match an acknowledged minimized package; it is not a safety certificate, authenticated
review, proof of a live provider call, or proof that the source deployment is still current.

## Exit behavior

- `0`: the directory was prepared or its complete package/receipt binding verified.
- `2`: the package, receipt, approval window, output path, manifest, or static files were invalid.

No MCP endpoint or model provider is contacted, and no MCP tool is executed.
