"""CLI for explicitly authorized, bounded real-world MCP validation sessions."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Annotated

import anyio
import typer
from rich.console import Console

from mendpact.domain import ScanStatus
from mendpact.reporting import render_report
from mendpact.validation_session import (
    SESSION_MANIFEST_NAME,
    SESSION_SUMMARY_NAME,
    ValidationSessionError,
    inspect_validation_session,
    run_validation_session,
    write_validation_session_summary,
)

app = typer.Typer(
    help="Preflight and run explicitly authorized MCP validation sessions.",
    no_args_is_help=True,
)
console = Console()


def _error(exc: ValueError) -> None:
    console.print(f"[red]Validation session blocked:[/] {exc}")
    raise typer.Exit(code=2) from exc


@app.command("preflight")
def preflight(
    workspace: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            readable=True,
            help="Private reports/validation workspace prepared for one target",
        ),
    ],
) -> None:
    """Check approval, retention, policy, checkout, and fresh outputs without network access."""

    try:
        plan = inspect_validation_session(workspace)
    except ValidationSessionError as exc:
        _error(exc)
        return
    authorization = plan.authorization
    if authorization.expires_at is None:
        _error(ValidationSessionError("Authorization record is incomplete."))
        return
    console.print("MendPact validation preflight: [bold green]READY[/]")
    console.print(f"Target alias: {authorization.target_alias}")
    console.print(f"Target profile: {authorization.target_kind}")
    console.print(f"Strict policy: {plan.policy.name} ({plan.policy.source_sha256})")
    console.print(f"Discovery scan budget: {authorization.max_discovery_scans}")
    console.print(f"Authorization expires: {authorization.expires_at.isoformat()}")
    console.print("No network request, credential lookup, MCP tool, or provider call was made.")


@app.command("run")
def run(
    workspace: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            readable=True,
            help="Preflighted private reports/validation workspace",
        ),
    ],
    acknowledge_authorized: Annotated[
        bool,
        typer.Option(
            "--acknowledge-authorized",
            help="Confirm permission and scope immediately before network discovery",
        ),
    ] = False,
) -> None:
    """Perform the approved sequential discovery scans, without retries or tool calls."""

    if not acknowledge_authorized:
        _error(
            ValidationSessionError(
                "Run preflight, review authorization.json, then pass --acknowledge-authorized."
            )
        )
        return
    try:
        result = anyio.run(partial(run_validation_session, workspace))
    except ValueError as exc:
        _error(exc)
        return
    for report in result.reports:
        render_report(report, console)
    manifest = result.manifest
    console.print(
        f"Validation session: [bold]{manifest.status.value.upper()}[/] | "
        f"Completed scans: {manifest.completed_scan_count}/{manifest.planned_scan_count}"
    )
    console.print(f"Session manifest: {workspace / SESSION_MANIFEST_NAME}")
    console.print(
        "No automatic retry, credential, MCP tool execution, model provider call, or upload."
    )
    if manifest.status == ScanStatus.ERROR:
        raise typer.Exit(code=2)
    if manifest.status == ScanStatus.FAILED:
        raise typer.Exit(code=1)


@app.command("summarize")
def summarize(
    workspace: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            readable=True,
            help="Completed private reports/validation workspace",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=f"New summary file (default: workspace/{SESSION_SUMMARY_NAME})",
        ),
    ] = None,
) -> None:
    """Verify completed evidence and write an offline privacy-minimized summary."""

    try:
        summary, destination = write_validation_session_summary(workspace, output)
    except ValueError as exc:
        _error(exc)
        return
    console.print("MendPact validation summary: [bold green]EXPORTED[/]")
    console.print(f"Recorded session status: {summary.recorded_status.value.upper()}")
    console.print(
        f"Verified scans: {summary.completed_scan_count}/{summary.planned_scan_count} | "
        f"Repeat-capture contract: {summary.comparison.result.upper()}"
    )
    console.print(f"Summary: {destination}")
    console.print(
        "No network request, credential lookup, MCP tool, provider call, or upload was made."
    )
    console.print("Export success does not mean the recorded session passed policy.")
