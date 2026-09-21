"""Explicit review and acknowledgement for local sharing packages."""

from pathlib import Path
from typing import Annotated

import typer

from mendpact.evidence import EvidenceExportError
from mendpact.publication import (
    PublicationError,
    inspect_publication_site,
    prepare_publication_site,
)
from mendpact.sharing import (
    DISCLOSURE,
    PackageInspection,
    SharingError,
    approve_package,
    inspect_package,
    prepare_package,
    verify_approval,
)

app = typer.Typer(
    help="Prepare and approve evidence for sharing; never uploads.", no_args_is_help=True
)


def _show(inspection: PackageInspection) -> None:
    typer.echo(f"Package SHA-256: {inspection.package_sha256}")
    typer.echo(f"Source SHA-256: {inspection.summary.source_sha256}")
    typer.echo(f"Recorded result: {inspection.summary.recorded_status.value}")
    typer.echo(f"Source captured: {inspection.summary.source_generated_at.isoformat()}")
    for section in inspection.summary.sections:
        typer.echo(f"{section.title}: {section.status}")
    typer.echo(inspection.summary.notice)
    typer.echo(inspection.summary.privacy)


def _error(exc: ValueError) -> None:
    typer.echo(str(exc), err=True)
    raise typer.Exit(code=2) from exc


@app.command("prepare")
def prepare(
    source: Annotated[Path, typer.Argument(help="Original saved scan, behavior, or guard JSON")],
    output: Annotated[Path, typer.Option("--output", help="New local ZIP file")],
) -> None:
    """Create a deterministic ZIP with minimized HTML, JSON and an integrity manifest."""

    try:
        inspection = prepare_package(source, output)
    except (SharingError, EvidenceExportError) as exc:
        _error(exc)
        return
    _show(inspection)
    typer.echo("Prepared locally, not approved or published. Review index.html inside the ZIP.")


@app.command("inspect")
def inspect(package: Annotated[Path, typer.Argument(help="Prepared sharing ZIP")]) -> None:
    """Check exact package contents and print the fingerprint to review."""

    try:
        inspection = inspect_package(package)
    except SharingError as exc:
        _error(exc)
        return
    _show(inspection)
    typer.echo("Package integrity checked; no sharing approval or identity is verified.")


@app.command("approve")
def approve(
    package: Annotated[Path, typer.Argument(help="Exact sharing ZIP you reviewed")],
    accept_sha256: Annotated[
        str, typer.Option("--accept-sha256", help="Reviewed package fingerprint")
    ],
    output: Annotated[Path, typer.Option("--output", help="New local approval JSON receipt")],
    acknowledge_public: Annotated[
        bool,
        typer.Option("--acknowledge-public", help="Acknowledge public sharing of this package"),
    ] = False,
    valid_for_days: Annotated[int, typer.Option(min=1, max=14)] = 7,
) -> None:
    """Record acknowledgement, bound to exact ZIP bytes, for at most 14 days."""

    try:
        receipt = approve_package(
            package,
            output,
            accepted_sha256=accept_sha256,
            acknowledge_public=acknowledge_public,
            valid_for_days=valid_for_days,
        )
    except (SharingError, EvidenceExportError) as exc:
        _error(exc)
        return
    typer.echo(DISCLOSURE)
    typer.echo(f"Local acknowledgement recorded; expires {receipt.expires_at.isoformat()}.")
    typer.echo("Nothing was uploaded. This is an unsigned receipt, not a safety certificate.")


@app.command("verify")
def verify(
    package: Annotated[
        Path, typer.Argument(help="Sharing ZIP to verify immediately before sharing")
    ],
    approval: Annotated[Path, typer.Option("--approval", help="Local approval JSON receipt")],
) -> None:
    """Check exact bytes and unexpired acknowledgement; does not publish."""

    try:
        receipt = verify_approval(package, approval)
    except SharingError as exc:
        _error(exc)
        return
    typer.echo(
        f"Exact package has a current acknowledgement until {receipt.expires_at.isoformat()}."
    )
    typer.echo("No identity, live call, or safety claim verified. No files uploaded.")


@app.command("prepare-site")
def prepare_site(
    package: Annotated[Path, typer.Argument(help="Exact sharing ZIP you reviewed")],
    approval: Annotated[Path, typer.Option("--approval", help="Local approval JSON receipt")],
    output: Annotated[Path, typer.Option("--output", help="New static output directory")],
) -> None:
    """Prepare an acknowledged package as static files; never uploads."""

    try:
        inspection = prepare_publication_site(package, approval, output)
    except (SharingError, PublicationError) as exc:
        _error(exc)
        return
    typer.echo(
        "Static evidence site prepared from the exact acknowledged package "
        f"until {inspection.manifest.approval_expires_at.isoformat()}."
    )
    typer.echo("Nothing was uploaded. Verify again immediately before a separate publish step.")


@app.command("verify-site")
def verify_site(
    directory: Annotated[Path, typer.Argument(help="Prepared static evidence directory")],
    package: Annotated[Path, typer.Option("--package", help="Exact reviewed sharing ZIP")],
    approval: Annotated[Path, typer.Option("--approval", help="Local approval JSON receipt")],
) -> None:
    """Verify static files, package bytes, and acknowledgement before publishing."""

    try:
        inspection = inspect_publication_site(directory, package, approval)
    except (SharingError, PublicationError) as exc:
        _error(exc)
        return
    typer.echo(
        "Static evidence site matches the acknowledged package; acknowledgement expires "
        f"{inspection.manifest.approval_expires_at.isoformat()}."
    )
    typer.echo("No identity, live call, safety claim, or remote publication was verified.")
