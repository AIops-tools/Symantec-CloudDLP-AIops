"""Governed Cloud DLP read tools."""

from symantec_clouddlp_aiops import ops
from symantec_clouddlp_aiops.connection import get_connection
from symantec_clouddlp_aiops.governance import governed_tool
from symantec_clouddlp_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query"])
@tool_errors()
def clouddlp_profiles(query: str = "") -> dict:
    """[READ] List DLP profiles."""
    return ops.profiles(get_connection(), query)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_profile(profile_id: str) -> dict:
    """[READ] Read a DLP profile."""
    return ops.profile(get_connection(), profile_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_profile_history(profile_id: str) -> dict:
    """[READ] Read DLP profile history."""
    return ops.profile_history(get_connection(), profile_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_custom_groups() -> dict:
    """[READ] List custom groups."""
    return ops.custom_groups(get_connection())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_custom_group(group_id: str) -> dict:
    """[READ] Read one custom group."""
    return ops.custom_group(get_connection(), group_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_data_identifiers() -> dict:
    """[READ] List data identifiers."""
    return ops.data_identifiers(get_connection())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_data_identifier(identifier_id: str) -> dict:
    """[READ] Read one data identifier."""
    return ops.data_identifier(get_connection(), identifier_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_validators() -> dict:
    """[READ] List data identifier validators."""
    return ops.validators(get_connection())


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["cursor_json"])
@tool_errors()
def clouddlp_incidents(
    start_date: str, end_date: str, limit: int = 100, cursor_json: str = ""
) -> dict:
    """[READ] Search bounded DLP incidents."""
    return ops.incidents(get_connection(), start_date, end_date, limit, cursor_json)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query"])
@tool_errors()
def clouddlp_reusable_patterns(query: str = "") -> dict:
    """[READ] List reusable DLP patterns."""
    return ops.reusable_patterns(get_connection(), query)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_reusable_pattern(pattern_id: str, version: int = 0) -> dict:
    """[READ] Read a reusable DLP pattern version."""
    return ops.reusable_pattern(get_connection(), pattern_id, version)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_indices(index_type: str = "", limit: int = 100) -> dict:
    """[READ] List DLP index health and versions."""
    return ops.indices(get_connection(), index_type, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_index(index_id: int) -> dict:
    """[READ] Read DLP index details."""
    return ops.index(get_connection(), index_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_incident_matches(incident_id: int, limit: int = 100) -> dict:
    """[READ] Read violating components for an incident."""
    return ops.incident_matches(get_connection(), incident_id, limit)
