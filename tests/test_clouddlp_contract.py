"""CloudSOC token and Cloud DLP incident query contracts."""

import httpx
import pytest

from symantec_clouddlp_aiops import ops
from symantec_clouddlp_aiops.connection import ClouddlpConnection, ClouddlpError


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SYMANTEC_CLOUDDLP_URL", "https://app.elastica.net")
    monkeypatch.setenv("SYMANTEC_CLOUDDLP_KEY_ID", "key")
    monkeypatch.setenv("SYMANTEC_CLOUDDLP_KEY_SECRET", "secret")
    monkeypatch.setenv("SYMANTEC_CLOUDDLP_TENANT", "example")


def test_token_and_incident_cursor():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/common/token":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(
            200, json={"incidents": [{"incidentId": 1}], "searchAfterValue": [2, 3]}
        )

    conn = ClouddlpConnection(
        httpx.Client(base_url="https://app.elastica.net", transport=httpx.MockTransport(handler))
    )
    data = ops.incidents(conn, "2026-01-01T00:00:00", "2026-01-02T00:00:00", 5)
    assert data["cursorAvailable"] and data["truncated"] is None
    assert data["nextCursor"] == [2, 3]
    assert seen[0].headers["tenant"] == "example"
    assert seen[0].headers["authorization"].startswith("Basic ")
    assert seen[1].headers["authorization"] == "Bearer t"
    assert seen[1].url.path == "/api/clouddlp/v2/incidents"


def test_missing_shape_is_error_and_write_route_rejected():
    def handler(request):
        if request.url.path == "/common/token":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(200, json={"wrong": []})

    conn = ClouddlpConnection(
        httpx.Client(base_url="https://app.elastica.net", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(ClouddlpError, match="unexpected incident"):
        ops.incidents(conn, "2026-01-01T00:00:00", "2026-01-02T00:00:00")
    with pytest.raises(ValueError, match="read operations"):
        conn.query("/public/profile", {"name": "bad"})


def test_index_inventory_and_incident_matches_are_bounded():
    seen = []

    def handler(request):
        if request.url.path == "/common/token":
            return httpx.Response(200, json={"token": "t"})
        seen.append(request.url.path)
        if request.url.path == "/indices":
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
        return httpx.Response(200, json=[{"messageComponentId": 1}, {"messageComponentId": 2}])

    conn = ClouddlpConnection(
        httpx.Client(base_url="https://app.elastica.net", transport=httpx.MockTransport(handler))
    )
    assert ops.indices(conn, limit=1)["truncated"] is True
    assert ops.incident_matches(conn, 9, limit=1)["returned"] == 1
    assert seen == ["/indices", "/api/clouddlp/v2/incidents/9/components/matches"]
