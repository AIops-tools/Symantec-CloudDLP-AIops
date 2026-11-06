"""Bounded, tenant-scoped CloudDLP transport. Only documented read requests are exposed."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class ClouddlpError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ClouddlpConnection:
    def __init__(self, client: httpx.Client | None = None) -> None:
        url = os.environ.get("SYMANTEC_CLOUDDLP_URL", "").rstrip("/")
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise ClouddlpError("Set SYMANTEC_CLOUDDLP_URL to the API HTTPS origin")
        try:
            timeout = float(os.environ.get("SYMANTEC_CLOUDDLP_TIMEOUT", "30"))
        except ValueError as exc:
            raise ClouddlpError("SYMANTEC_CLOUDDLP_TIMEOUT must be positive") from exc
        if timeout <= 0:
            raise ClouddlpError("SYMANTEC_CLOUDDLP_TIMEOUT must be positive")
        key_id = os.environ.get("SYMANTEC_CLOUDDLP_KEY_ID", "")
        key_secret = os.environ.get("SYMANTEC_CLOUDDLP_KEY_SECRET", "")
        tenant = os.environ.get("SYMANTEC_CLOUDDLP_TENANT", "")
        if not key_id or not key_secret or not tenant:
            raise ClouddlpError("Set Cloud DLP key ID, key secret and tenant environment variables")
        self._credentials = (key_id, key_secret)
        self._tenant = tenant
        verify = os.environ.get("SYMANTEC_CLOUDDLP_CA_BUNDLE") or True
        self._client = client or httpx.Client(base_url=url, timeout=timeout, verify=verify)
        self._token: str | None = None
        self._expires_at = 0.0
        self._auth_retry_at = 0.0
        self._lock = threading.RLock()

    def close(self) -> None:
        self._client.close()

    def _bounded_request(self, method: str, path: str, **kwargs: Any) -> tuple[int, bytearray]:
        with self._client.stream(method, path, **kwargs) as response:
            status = response.status_code
            if status >= 400:
                return status, bytearray()
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=64 * 1024):
                if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                    raise ClouddlpError("CloudDLP response exceeds 16 MiB; narrow the query")
                body.extend(chunk)
            return status, body

    def _authenticate(self) -> None:
        if time.monotonic() < self._auth_retry_at:
            raise ClouddlpError(
                "CloudDLP login was rejected recently; wait before retrying credentials"
            )
        try:
            status, body = self._bounded_request(
                "GET",
                "/common/token",
                auth=self._credentials,
                headers={
                    "Accept": "application/json",
                    "tenant": self._tenant,
                    "X-Elastica-Dbname-Resolved": "True",
                },
            )
        except httpx.TimeoutException as exc:
            raise ClouddlpError("CloudDLP login timed out; check URL and timeout") from exc
        except httpx.HTTPError as exc:
            raise ClouddlpError("Cannot reach CloudDLP login; check URL and TLS") from exc
        if status in (400, 401, 403):
            self._auth_retry_at = time.monotonic() + 30
            raise ClouddlpError("CloudDLP rejected credentials or client privileges")
        if status >= 400:
            raise ClouddlpError(f"CloudDLP login returned HTTP {status}")
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise ClouddlpError("CloudDLP login returned non-JSON data") from exc
        if not isinstance(data, dict):
            raise ClouddlpError("CloudDLP login returned an unexpected response")
        token = data.get("token")
        raw_expiry = 900
        if not isinstance(token, str) or not token:
            raise ClouddlpError("CloudDLP login response has no token")
        if isinstance(raw_expiry, bool) or not isinstance(raw_expiry, (int, str)):
            raise ClouddlpError("CloudDLP login response has invalid expires_in")
        try:
            expiry = int(raw_expiry)
        except ValueError as exc:
            raise ClouddlpError("CloudDLP login response has invalid expires_in") from exc
        if expiry <= 0:
            raise ClouddlpError("CloudDLP login response has invalid expires_in")
        self._token = token
        self._expires_at = time.monotonic() + max(1, expiry - 60)
        self._auth_retry_at = 0.0

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if path.startswith("//") or not (
            path.startswith("/public/profile/")
            or path == "/public/profile"
            or path.startswith("/api/clouddlp/v2/")
            or path == "/indices"
            or path.startswith("/indices/")
        ):
            raise ValueError("Undocumented CloudDLP resource path")
        if method != "GET" and (method != "POST" or not (path == "/api/clouddlp/v2/incidents")):
            raise ValueError("CloudDLP transport only exposes documented read operations")
        if method == "POST" and not isinstance(payload, dict):
            raise ValueError("Query body must be an object")
        with self._lock:
            if self._token is None or time.monotonic() >= self._expires_at:
                self._authenticate()
            for attempt in range(2):
                try:
                    status, body = self._bounded_request(
                        method,
                        path,
                        params=params,
                        json=payload,
                        headers={
                            "Authorization": f"Bearer {self._token}",
                            "Accept": "application/json",
                        },
                    )
                except httpx.TimeoutException as exc:
                    raise ClouddlpError(f"CloudDLP timed out on {path}") from exc
                except httpx.HTTPError as exc:
                    raise ClouddlpError(
                        f"Cannot reach CloudDLP on {path}; check URL and TLS"
                    ) from exc
                if status == 401 and attempt == 0:
                    self._token = None
                    self._authenticate()
                    continue
                if status >= 400:
                    hint = "Check client privilege and resource ID."
                    if status == 429:
                        hint = "API quota exceeded; retry after the server limit resets."
                    elif status >= 500:
                        hint = "Check service health before retrying."
                    raise ClouddlpError(
                        f"CloudDLP returned HTTP {status} for {path}. {hint}",
                        status_code=status,
                    )
                if not body:
                    raise ClouddlpError(f"CloudDLP returned an empty response for {path}")
                try:
                    return json.loads(body)
                except ValueError as exc:
                    raise ClouddlpError(f"CloudDLP returned non-JSON data for {path}") from exc
            raise ClouddlpError("CloudDLP authentication retry failed")

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def query(self, path: str, payload: dict[str, Any]) -> Any:
        return self._request("POST", path, payload=payload)


_connection: ClouddlpConnection | None = None
_connection_lock = threading.Lock()


def get_connection() -> ClouddlpConnection:
    global _connection
    with _connection_lock:
        if _connection is None:
            _connection = ClouddlpConnection()
        return _connection
