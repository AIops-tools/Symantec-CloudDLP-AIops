"""Documented Symantec Cloud DLP incident and profile read operations."""

from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import quote

from symantec_clouddlp_aiops.connection import ClouddlpConnection, ClouddlpError


def _id(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError("resource ID must be a non-empty bounded string")
    return quote(value, safe="")


def _data(conn: ClouddlpConnection, path: str, params: dict | None = None) -> dict:
    data = conn.get(path, params=params)
    if data is None or data == "":
        raise ClouddlpError(f"Cloud DLP returned an unexpected empty response for {path}")
    return {"data": data, "shapeVerified": False}


def profiles(conn: ClouddlpConnection, query: str = "") -> dict:
    if len(query) > 200:
        raise ValueError("query must be at most 200 characters")
    return _data(conn, "/public/profile", {"query": query} if query else None)


def profile(conn: ClouddlpConnection, profile_id: str) -> dict:
    return _data(conn, f"/public/profile/{_id(profile_id)}")


def profile_history(conn: ClouddlpConnection, profile_id: str) -> dict:
    return _data(conn, f"/public/profile/{_id(profile_id)}/history")


def custom_groups(conn: ClouddlpConnection) -> dict:
    return _data(conn, "/public/profile/custom-groups")


def custom_group(conn: ClouddlpConnection, group_id: str) -> dict:
    return _data(conn, f"/public/profile/custom-groups/{_id(group_id)}")


def data_identifiers(conn: ClouddlpConnection) -> dict:
    return _data(conn, "/public/profile/di")


def data_identifier(conn: ClouddlpConnection, identifier_id: str) -> dict:
    return _data(conn, f"/public/profile/di/{_id(identifier_id)}")


def validators(conn: ClouddlpConnection) -> dict:
    return _data(conn, "/public/profile/di/validators")


def incidents(
    conn: ClouddlpConnection,
    start_date: str,
    end_date: str,
    limit: int = 100,
    cursor_json: str = "",
) -> dict:
    try:
        start, end = datetime.fromisoformat(start_date), datetime.fromisoformat(end_date)
    except ValueError as exc:
        raise ValueError("Dates must be ISO 8601 local date-times") from exc
    if start.tzinfo != end.tzinfo or not 0 < (end - start).total_seconds() <= 30 * 86400:
        raise ValueError("Incident range must be ascending and at most 30 days")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be 1–100")
    if len(cursor_json) > 4096:
        raise ValueError("cursor_json exceeds bound")
    body = {
        "select": [
            {"name": "incidentId"},
            {"name": "policyName"},
            {"name": "severityId"},
            {"name": "creationDate"},
        ],
        "filter": {
            "filterType": "booleanLogic",
            "booleanOperator": "AND",
            "filters": [
                {
                    "filterType": "localDateTime",
                    "operandOne": {"name": "creationDate"},
                    "operator": "GTE",
                    "operandTwoValues": [start_date],
                },
                {
                    "filterType": "localDateTime",
                    "operandOne": {"name": "creationDate"},
                    "operator": "LT",
                    "operandTwoValues": [end_date],
                },
            ],
        },
        "orderBy": [{"field": {"name": "creationDate"}, "order": "ASC"}],
        "limit": limit,
    }
    if cursor_json:
        try:
            cursor = json.loads(cursor_json)
        except ValueError as exc:
            raise ValueError("cursor_json must be a JSON array") from exc
        if not isinstance(cursor, list) or not cursor or len(cursor) > 10:
            raise ValueError("cursor_json must be a short non-empty JSON array")
        body["page"] = {"type": "search_after", "value": cursor}
    data = conn.query("/api/clouddlp/v2/incidents", body)
    if not isinstance(data, dict) or not isinstance(data.get("incidents"), list):
        raise ClouddlpError("Cloud DLP returned an unexpected incident page")
    rows = data["incidents"]
    if any(not isinstance(row, dict) for row in rows) or len(rows) > limit:
        raise ClouddlpError("Cloud DLP returned invalid incident rows")
    cursor = data.get("searchAfterValue")
    if cursor is not None and not isinstance(cursor, list):
        raise ClouddlpError("Cloud DLP returned an invalid search cursor")
    return {
        "items": rows,
        "returned": len(rows),
        "limit": limit,
        "nextCursor": cursor,
        "cursorAvailable": bool(cursor),
        "truncated": None,
        "completionKnown": False,
    }
