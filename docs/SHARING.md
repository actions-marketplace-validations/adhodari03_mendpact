# Reviewed sharing packages

This is local preparation for reviewed publication, not a hosting or upload service. It builds
on minimized [evidence export](EVIDENCE_EXPORT.md) and adds an exact-byte review boundary. It
requires no new dependency, provider key, account, network connection, or paid service. These
commands are development-branch features until included in a published release.

## Workflow

### 1. Prepare locally

```bash
mkdir -p reports
mendpact share prepare guard-report.json --output reports/review-package.zip
```

Sources are the same original scan, behavior, and guard report types accepted by `export-report`.
The command produces a deterministic ZIP with exactly these files:

| File | Contents |
| --- | --- |
| `index.html` | Script-free, self-contained minimized report |
| `summary.json` | Versioned, aggregate MendPact evidence |
| `manifest.json` | `mendpact.sharing-package.v1`, source digest, and artifact digests |

The source report, target URL, raw errors, arguments, prompts, provider responses, and credentials
are not copied into the package. Counts, thresholds, outcomes, capture time, and source digests
remain and can still disclose information. This is minimization, not anonymization.

The same input yields identical bytes with a fixed ZIP timestamp and no compression. It does
not embed local paths or an operating-system username. The output must be a new filename in an
existing directory; overwrite and symlink-directory protections match evidence export.

### 2. Inspect and review

```bash
mendpact share inspect reports/review-package.zip
```

Inspection verifies exact member names, manifest digests, the summary's allowed fields and
metric values, aggregate consistency, and canonical HTML/ZIP bytes. It never extracts files.
Open the prepared ZIP yourself and review `index.html` before acknowledging public sharing.

Input ZIPs are capped at 1 MiB and members at 256 KiB. Extra files, duplicate members, traversal
paths, symlinks, compressed/encrypted members, modified HTML, arbitrary summary text, and trailing
payloads are rejected. Canonical ZIP bytes also rule out hidden ZIP metadata and comments. The
renderer and canonical archive format are part of the package v1 contract; a future incompatible
renderer requires a format migration rather than silently treating old packages as reviewed.

The displayed **package SHA-256** identifies the exact ZIP you reviewed. It is distinct from the
source SHA-256, which identifies the original private report. Neither digest authenticates its
author or establishes that a real provider request happened.

### 3. Acknowledge the exact package

Paste the package fingerprint from the inspected artifact, not the source fingerprint:

```bash
mendpact share approve reports/review-package.zip \
  --accept-sha256 REVIEWED_PACKAGE_SHA256 \
  --acknowledge-public \
  --valid-for-days 7 \
  --output reports/sharing-approval.json
```

`REVIEWED_PACKAGE_SHA256` is a placeholder to replace. The acknowledgement flag is mandatory,
and a different fingerprint fails closed. Do not pipe an automatically computed fingerprint
straight into approval and describe that as human review.

The command creates an unsigned `mendpact.sharing-approval.v1` receipt with the package and source
digests, approval time, expiry, and the fixed disclosure acknowledgement. No reviewer identity,
contact information, key, or signature is stored. Its default lifetime is seven days; the
allowed range is 1–14 days. Existing receipts are not replaced; re-review and create a new file
when necessary.

A current receipt does not make old source evidence fresh; review the displayed capture time
as part of deciding whether the report is relevant to what you intend to share.

This flag records a local acknowledgement for a future sharing decision. It does not cause an
upload or grant another application access. A failed or error report can be reviewed for sharing
without turning its outcome into passed.

### 4. Verify immediately before a separate sharing action

```bash
mendpact share verify reports/review-package.zip \
  --approval reports/sharing-approval.json
```

Verification rechecks the actual ZIP, matches its fingerprint and source digest to the receipt,
and checks the current clock against approval and expiry times. Expiry is exclusive: a receipt
is invalid at its exact expiry timestamp. Future approvals, timezone-free timestamps, inverted
time windows, lifetimes over 14 days, and a missing public acknowledgement are rejected.

This is a local check, not an authenticated authorization system. A person who can rewrite both
the package and receipt can forge an acknowledgement. There is no trusted issuer, signature,
protected approver identity, or remote revocation mechanism. Those belong to the planned signed
passport and authenticated publication work.

Keep the verified file unchanged between verification and the next step. MendPact can prepare and
verify a static evidence directory from that package, but it does not upload the directory. See
the [static evidence guide](PUBLIC_EVIDENCE.md).

### 5. Prepare and verify static files

```bash
mendpact share prepare-site reports/review-package.zip \
  --approval reports/sharing-approval.json \
  --output reports/public-evidence

mendpact share verify-site reports/public-evidence \
  --package reports/review-package.zip \
  --approval reports/sharing-approval.json
```

Preparation writes canonical `index.html` and `summary.json` bytes, a versioned publication
manifest, and `.nojekyll` into a new directory. Verification checks those exact files against the
original package and a still-current receipt. Neither command invokes Git, changes GitHub Pages,
or publishes a URL.

## Expiry is not deletion

Approval expiry blocks later verification; it does not delete the ZIP, remove an already
published page, or recall somebody else's download. The HTML remains readable after expiry.
Deleting a local receipt also cannot revoke external copies. Hosted deletion, access controls,
retention enforcement, and revocation require a separate implementation.

No command selects the repository's `site/` directory, pushes to GitHub, uploads artifacts, changes
repository permissions, or contacts a hosting provider. Keep locally generated ZIPs, receipts, and
prepared evidence directories under the ignored `reports/` directory until you deliberately move
only the four public files into a publishing repository. If you choose another output path,
configure its ignore rules yourself. Do not attach raw source reports alongside the package.

## Exit behavior

- `0`: package/site preparation, structural inspection, acknowledgement creation, or verification
  succeeded.
- `2`: invalid input, unsafe archive, wrong fingerprint, missing acknowledgement, expired/invalid
  receipt, or output failure.

There is no code `1` reliability verdict. Keep `scan`, `evaluate`, and `guard` as the actual CI
gates. Successful package verification says nothing about whether its recorded checks passed.

## Testing and CI

The test suite covers all six CLI commands, privacy sentinels, deterministic packages, exact
fingerprint binding, expiry boundaries, unsafe/malformed archives and static directories, output
preservation and cleanup, and network-denied execution. Unit tests generate acknowledgements for
synthetic fixtures only; these are not real user consent records.

Repository CI prepares and inspects one committed fixture package. It deliberately does not
approve or publish it. Automatic approvals of arbitrary PR-produced reports are not a human
review workflow. This repository's GitHub Pages deployment remains the project website, not an
automatic report-upload destination.
