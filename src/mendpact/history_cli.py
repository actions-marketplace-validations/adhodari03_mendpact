"""CLI for local history; inspection does not become a reliability gate."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from mendpact.evidence import EvidenceExportError, write_new_evidence_file
from mendpact.history import (
    RETENTION_DAYS,
    HistoryError,
    add_history,
    compare_history,
    list_history,
    prune_history,
)

app = typer.Typer(
    help="Import, inspect, and compare local minimized evidence.", no_args_is_help=True
)
console = Console(markup=False)
DatabaseOption = Annotated[
    Path, typer.Option("--database", help="Local history SQLite file; parent directory must exist")
]
DEFAULT_DATABASE = Path("reports/history.sqlite")


def _error(exc: ValueError) -> None:
    typer.echo(str(exc), err=True)
    raise typer.Exit(code=2) from exc


@app.command("add")
def add(
    source: Annotated[Path, typer.Argument(help="Original saved scan, behavior, or guard report")],
    database: DatabaseOption = DEFAULT_DATABASE,
) -> None:
    """Store minimized evidence once per exact source digest. No raw report is copied."""

    try:
        entry, added = add_history(source, database)
    except (HistoryError, EvidenceExportError) as exc:
        _error(exc)
        return
    action = "Imported" if added else "Already stored"
    typer.echo(
        f"{action}: history ID {entry.id}; recorded status {entry.record.evidence.recorded_status}."
    )
    typer.echo("Local import success is not a passing reliability check. No files were uploaded.")


@app.command("list")
def list_runs(
    database: DatabaseOption = DEFAULT_DATABASE,
    limit: Annotated[int, typer.Option(min=1, max=100)] = 20,
    before_id: Annotated[
        int | None, typer.Option(min=1, help="Page older than this import ID")
    ] = None,
) -> None:
    """List newest imports first; capture timestamps need not follow import order."""

    try:
        entries = list_history(database, limit=limit, before_id=before_id)
    except HistoryError as exc:
        _error(exc)
        return
    if not entries:
        typer.echo("No history entries in this page.")
        return
    table = Table("ID", "Report", "Status", "Source captured", "Imported (UTC)")
    for entry in entries:
        summary = entry.record.evidence
        table.add_row(
            str(entry.id),
            summary.source_schema,
            summary.recorded_status,
            summary.source_generated_at.isoformat(),
            entry.record.imported_at.isoformat(),
        )
    console.print(table)
    typer.echo(
        f"Retention: run history prune to preview entries imported {RETENTION_DAYS}+ days ago."
    )
    typer.echo(f"For the next page, use --before-id {entries[-1].id}.")


@app.command("compare")
def compare(
    reference_id: Annotated[int, typer.Argument(min=1)],
    candidate_id: Annotated[int, typer.Argument(min=1)],
    database: DatabaseOption = DEFAULT_DATABASE,
    output: Annotated[Path | None, typer.Option(help="Optional new comparison JSON file")] = None,
) -> None:
    """Show descriptive metric changes; not an automated regression verdict."""

    try:
        report = compare_history(database, reference_id, candidate_id)
        if output:
            write_new_evidence_file(output, report.model_dump_json(indent=2))
    except (HistoryError, EvidenceExportError) as exc:
        _error(exc)
        return
    console.print(
        f"History {reference_id} -> {candidate_id}: "
        f"{report.reference_status} -> {report.candidate_status}"
    )
    console.print(report.notice)
    for warning in report.warnings:
        console.print(f"Warning: {warning}")
    for stage in report.stages:
        console.print(f"\n{stage.title}: {stage.reference_status} -> {stage.candidate_status}")
        if not stage.comparable:
            console.print(
                "Numeric deltas withheld: missing, incomplete, or changed comparison setup."
            )
        table = Table("Metric", "Reference", "Candidate", "Delta")
        for metric in stage.metrics:
            table.add_row(
                metric.label,
                str(metric.reference) if metric.reference is not None else "Not recorded",
                str(metric.candidate) if metric.candidate is not None else "Not recorded",
                f"{metric.delta:+d}" if metric.delta is not None else "—",
            )
        console.print(table)


@app.command("prune")
def prune(
    database: DatabaseOption = DEFAULT_DATABASE,
    apply: Annotated[
        bool, typer.Option("--apply", help="Delete eligible history rows locally")
    ] = False,
) -> None:
    """Preview 14-day cleanup by default. --apply deletes rows, never original source files."""

    try:
        count = prune_history(database, apply=apply)
    except HistoryError as exc:
        _error(exc)
        return
    if apply:
        typer.echo(f"Deleted {count} history entries. Original reports are unchanged.")
        typer.echo("Deleted entries have no history undo; reimport retained originals if needed.")
    else:
        typer.echo(f"Dry run: {count} entries imported {RETENTION_DAYS}+ days ago are eligible.")
        typer.echo("No changes made. Add --apply to delete these history entries.")
