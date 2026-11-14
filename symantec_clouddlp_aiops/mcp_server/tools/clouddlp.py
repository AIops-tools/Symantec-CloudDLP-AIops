"""Governed Cloud DLP read tools."""

from typing import Annotated

from pydantic import Field

from symantec_clouddlp_aiops import ops
from symantec_clouddlp_aiops.connection import get_connection
from symantec_clouddlp_aiops.governance import governed_tool
from symantec_clouddlp_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query"])
@tool_errors()
def clouddlp_profiles(
    query: Annotated[
        str, Field(description=("Optional profile or pattern search text, at most 200 characters."))
    ] = "",
) -> dict:
    """[READ] List DLP profiles.

    Use to discover IDs before calling clouddlp_profile for a single resource.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
    return ops.profiles(get_connection(), query)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_profile(
    profile_id: Annotated[str, Field(description="DLP profile ID from the profile listing.")],
) -> dict:
    """[READ] Read a DLP profile.

    Use for one known resource; call clouddlp_profiles to discover IDs.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
    return ops.profile(get_connection(), profile_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_profile_history(
    profile_id: Annotated[str, Field(description="DLP profile ID from the profile listing.")],
) -> dict:
    """[READ] Read DLP profile history.

    Use for one profile’s change history; use clouddlp_profile for current profile data.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
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
def clouddlp_custom_group(
    group_id: Annotated[str, Field(description="Group ID from the corresponding listing.")],
) -> dict:
    """[READ] Read one custom group.

    Use for one known resource; call clouddlp_custom_groups to discover IDs.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
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
def clouddlp_data_identifier(
    identifier_id: Annotated[str, Field(description="Data-identifier ID from the listing.")],
) -> dict:
    """[READ] Read one data identifier.

    Use for one known resource; call clouddlp_data_identifiers to discover IDs.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
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
    start_date: Annotated[
        str,
        Field(description=("ISO 8601 local date-time at the start of the incident search window.")),
    ],
    end_date: Annotated[
        str,
        Field(
            description=(
                "ISO 8601 local date-time at the end of the incident "
                "search window (at most 30 days)."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); incident search has an opaque continuation cursor."
            )
        ),
    ] = 100,
    cursor_json: Annotated[
        str,
        Field(
            description=(
                "JSON array from the previous incident page "
                "searchAfterValue; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search bounded DLP incidents.

    Use for time-bounded incident discovery; use clouddlp_incident_matches after obtaining an
    incident ID.

    Result: items and nextCursor; completionKnown is false and truncated is null because
    upstream completion cannot be proven.
    """
    return ops.incidents(get_connection(), start_date, end_date, limit, cursor_json)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query"])
@tool_errors()
def clouddlp_reusable_patterns(
    query: Annotated[
        str, Field(description=("Optional profile or pattern search text, at most 200 characters."))
    ] = "",
) -> dict:
    """[READ] List reusable DLP patterns.

    Use to discover IDs before calling clouddlp_reusable_pattern for a single resource.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
    return ops.reusable_patterns(get_connection(), query)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_reusable_pattern(
    pattern_id: Annotated[str, Field(description="Reusable-pattern ID from the pattern listing.")],
    version: Annotated[
        int, Field(description=("Nonnegative pattern version; zero uses the upstream default."))
    ] = 0,
) -> dict:
    """[READ] Read a reusable DLP pattern version.

    Use for one known resource; call clouddlp_reusable_patterns to discover IDs.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
    return ops.reusable_pattern(get_connection(), pattern_id, version)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_indices(
    index_type: Annotated[str, Field(description="Optional bounded DLP index-type filter.")] = "",
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); incident search has an opaque continuation cursor."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List DLP index health and versions.

    Result: items, returned, limit and measured truncated.
    """
    return ops.indices(get_connection(), index_type, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_index(
    index_id: Annotated[int, Field(description="Positive DLP index ID from the index listing.")],
) -> dict:
    """[READ] Read DLP index details.

    Result: data with shapeVerified false; the upstream response shape is not live-verified.
    """
    return ops.index(get_connection(), index_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def clouddlp_incident_matches(
    incident_id: Annotated[
        int, Field(description="Positive incident ID from the incident search.")
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); incident search has an opaque continuation cursor."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] Read violating components for an incident.

    Use for violating components of one known incident; use clouddlp_incidents to find incident
    IDs.

    Result: items, returned, limit and measured truncated.
    """
    return ops.incident_matches(get_connection(), incident_id, limit)
