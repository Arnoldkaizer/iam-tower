#!/usr/bin/env python3
"""AWS IAM Security Tower CLI - local rule-based threat detection and monitoring."""

from __future__ import annotations

import sys

import typer

from aws_tower.tower import theme
from aws_tower.tower.cli import tower_app

app = typer.Typer(
    name="aws-tower",
    help="AWS IAM Security Tower - local rule-based threat detection and posture monitoring",
    invoke_without_command=True,
)


def _show_banner_on_help() -> None:
    if sys.argv[1:] == ["--help"]:
        theme.print_banner()


@app.callback()
def main(
    ctx: typer.Context,
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI color output (also auto-disabled when not a TTY).",
        envvar="AWS_TOWER_NO_COLOR",
    ),
) -> None:
    """AWS IAM Security Tower - zero-configuration local monitoring."""
    if no_color:
        theme.set_color(False)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


app.add_typer(tower_app, name="")


def main_entry() -> None:
    """Run the CLI and show the banner only for the root help command."""
    _show_banner_on_help()
    app()


if __name__ == "__main__":
    main_entry()
