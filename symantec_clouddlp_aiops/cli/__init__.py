"""CLI delegates to governed Cloud DLP MCP tools."""

from __future__ import annotations

import json

import typer

from symantec_clouddlp_aiops.governance import BudgetExceeded
from symantec_clouddlp_aiops.mcp_server.tools import clouddlp

app = typer.Typer(name="symantec-clouddlp-aiops", no_args_is_help=True)


def governed(result: dict) -> dict:
    if result.get("outcomeUnknown"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(2)
    if result.get("error"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(1)
    return result


def _emit(result: dict) -> None:
    typer.echo(json.dumps(governed(result), ensure_ascii=False, indent=2))


@app.command("profiles")
def profiles(query: str = "") -> None:
    _emit(clouddlp.clouddlp_profiles(query))


@app.command("profile")
def profile(profile_id: str) -> None:
    _emit(clouddlp.clouddlp_profile(profile_id))


@app.command("profile-history")
def profile_history(profile_id: str) -> None:
    _emit(clouddlp.clouddlp_profile_history(profile_id))


@app.command("custom-groups")
def custom_groups() -> None:
    _emit(clouddlp.clouddlp_custom_groups())


@app.command("custom-group")
def custom_group(group_id: str) -> None:
    _emit(clouddlp.clouddlp_custom_group(group_id))


@app.command("data-identifiers")
def data_identifiers() -> None:
    _emit(clouddlp.clouddlp_data_identifiers())


@app.command("data-identifier")
def data_identifier(identifier_id: str) -> None:
    _emit(clouddlp.clouddlp_data_identifier(identifier_id))


@app.command("validators")
def validators() -> None:
    _emit(clouddlp.clouddlp_validators())


@app.command("incidents")
def incidents(start_date: str, end_date: str, limit: int = 100, cursor_json: str = "") -> None:
    _emit(clouddlp.clouddlp_incidents(start_date, end_date, limit, cursor_json))


def main() -> None:
    try:
        app()
    except BudgetExceeded as exc:
        typer.echo(f"Budget stopped the operation: {exc}", err=True)
        raise typer.Exit(1) from exc


@app.command("reusable-patterns")
def reusable_patterns(query: str = "") -> None:
    _emit(clouddlp.clouddlp_reusable_patterns(query))


@app.command("reusable-pattern")
def reusable_pattern(pattern_id: str, version: int = 0) -> None:
    _emit(clouddlp.clouddlp_reusable_pattern(pattern_id, version))


@app.command("indices")
def indices(index_type: str = "", limit: int = 100) -> None:
    _emit(clouddlp.clouddlp_indices(index_type, limit))


@app.command("index")
def index(index_id: int) -> None:
    _emit(clouddlp.clouddlp_index(index_id))


@app.command("incident-matches")
def incident_matches(incident_id: int, limit: int = 100) -> None:
    _emit(clouddlp.clouddlp_incident_matches(incident_id, limit))
