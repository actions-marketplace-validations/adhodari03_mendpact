"""Terminal rendering for non-executable MCP registry metadata."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from mendpact.registry import RegistryDiscoveryReport, RegistryRecord, registry_identity


def _text(value: object | None) -> Text:
    return Text(str(value) if value not in {None, ""} else "—")


def render_registry_discovery(
    report: RegistryDiscoveryReport,
    console: Console,
) -> None:
    """Render ranked official-registry candidates without implying a safety verdict."""

    console.print("MendPact MCP registry discovery")
    console.print(f"Registry: {report.registry}")
    console.print(f"Query probes: {', '.join(report.registry_queries)}")
    if not report.results:
        console.print("[yellow]No matching registered servers were found.[/]")
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Server", overflow="fold")
        table.add_column("Purpose", overflow="fold")
        table.add_column("Version / status", width=12)
        table.add_column("Delivery", overflow="fold")
        table.add_column("Registry identity", overflow="fold")
        table.add_column("Required secrets", overflow="fold")
        for candidate in report.results:
            purpose = candidate.title or candidate.description or "—"
            table.add_row(
                _text(candidate.name),
                _text(purpose),
                _text(f"{candidate.version}\n{candidate.status}"),
                _text(", ".join(candidate.delivery) or "not advertised"),
                _text(candidate.identity),
                _text(", ".join(candidate.required_secret_names) or "none advertised"),
            )
        console.print(table)
    console.print(
        "[yellow]Registry verification proves publisher namespace/package ownership, "
        "not server safety.[/]"
    )
    console.print(report.execution_boundary)


def render_registry_inspection(record: RegistryRecord, console: Console) -> None:
    """Render one exact registry record while omitting environment-variable values."""

    server = record.server
    official = record.official
    console.print("MendPact MCP registry inspection")
    identity = Table.grid(padding=(0, 1))
    identity.add_column(style="bold")
    identity.add_column(overflow="fold")
    identity.add_row("Name", _text(server.name))
    identity.add_row("Title", _text(server.title))
    identity.add_row("Version", _text(server.version))
    identity.add_row("Status", _text(official.status))
    identity.add_row("Identity", _text(registry_identity(server.name)))
    identity.add_row("Description", _text(server.description))
    if server.repository:
        identity.add_row("Repository", _text(server.repository.url))
    if official.published_at:
        identity.add_row("Published", _text(official.published_at))
    if official.updated_at:
        identity.add_row("Updated", _text(official.updated_at))
    console.print(identity)

    if server.remotes:
        remotes = Table("Remote transport", "Public endpoint", show_header=True)
        for remote in server.remotes:
            remotes.add_row(_text(remote.type), _text(remote.url))
        console.print(remotes)
    else:
        console.print("Remote endpoints: none advertised")

    if server.packages:
        packages = Table(
            "Package registry",
            "Identifier",
            "Runtime",
            "Transport",
            "Required secret names",
            show_header=True,
        )
        for package in server.packages:
            secret_names = sorted(
                variable.name
                for variable in package.environment_variables
                if variable.is_required and variable.is_secret
            )
            packages.add_row(
                _text(package.registry_type),
                _text(package.identifier),
                _text(package.runtime_hint or "not advertised"),
                _text(package.transport.get("type", "not advertised")),
                _text(", ".join(secret_names) or "none advertised"),
            )
        console.print(packages)
    else:
        console.print("Packages: none advertised")

    console.print(
        "[yellow]Metadata only:[/] this command did not contact the MCP endpoint, install a "
        "package, load a credential, or run server code. Registry identity is not a safety "
        "certification."
    )
