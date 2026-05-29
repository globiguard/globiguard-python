from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .credentials import Credential, Environment, LocalCredential
from .errors import GlobiguardConfigError, GlobiguardHttpError

QueryValue = str | int | float | bool | None
TransportCallable = Any

_RESERVED_HEADERS = {
    "x-globiguard-client",
    "x-globiguard-environment",
    "x-globiguard-project-id",
    "x-globiguard-publishable-key",
    "x-globiguard-secret-key",
    "x-globiguard-local-mode",
    "x-globiguard-local-token",
}
_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")


def assert_service_url(
    service_name: str,
    service_url: str,
    environment: Environment,
    *,
    require_local_host: bool = False,
) -> None:
    parsed = urlsplit(service_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise GlobiguardConfigError(f"{service_name} service URL must be a valid URL.")
    if environment != "local" and parsed.scheme != "https":
        raise GlobiguardConfigError(
            f"{service_name} service URL must use HTTPS outside the local environment."
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise GlobiguardConfigError(
            f"{service_name} service URL must be a service origin, not a versioned API path."
        )
    if require_local_host and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        hostname = parsed.hostname or ""
        if not hostname.endswith(".localhost"):
            raise GlobiguardConfigError(
                f"{service_name} service URL must use a localhost or loopback host with local credentials."
            )


def encode_path_segment(value: str) -> str:
    return quote(value, safe="")


def join_url(base_url: str, path: str) -> str:
    if "://" in path or path.startswith("//"):
        raise GlobiguardConfigError(
            "Request paths must be relative to the configured GlobiGuard service."
        )
    if not path.startswith("/"):
        raise GlobiguardConfigError("Request paths must start with '/'.")
    if "?" in path or "#" in path:
        raise GlobiguardConfigError(
            "Request paths must not include query strings or fragments."
        )
    if "\\" in path:
        raise GlobiguardConfigError("Request paths must not contain backslashes.")

    base = urlsplit(base_url if base_url.endswith("/") else f"{base_url}/")
    segments = [segment for segment in path.lstrip("/").split("/") if segment]
    for segment in segments:
        if _INVALID_PERCENT_ENCODING.search(segment):
            raise GlobiguardConfigError(
                "Request paths must contain valid percent-encoding."
            )
        decoded = unquote(segment)
        if decoded in {".", ".."}:
            raise GlobiguardConfigError("Request paths must not contain dot segments.")

    resolved_path = "/" + "/".join(segments)
    return urlunsplit((base.scheme, base.netloc, resolved_path, "", ""))


def _apply_query(url: str, query: Mapping[str, QueryValue] | None) -> str:
    if not query:
        return url
    filtered = {
        key: str(value).lower() if isinstance(value, bool) else str(value)
        for key, value in query.items()
        if value is not None
    }
    if not filtered:
        return url
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(filtered), parts.fragment)
    )


def _credential_headers(credential: Credential) -> dict[str, str]:
    headers: dict[str, str] = {}
    if credential.project_id:
        headers["x-globiguard-project-id"] = credential.project_id

    if credential.kind == "publishable":
        headers["x-globiguard-publishable-key"] = credential.token
    elif credential.kind == "secret":
        headers["x-globiguard-secret-key"] = credential.token
    elif isinstance(credential, LocalCredential):
        headers["x-globiguard-local-mode"] = "true"
        if credential.token:
            headers["x-globiguard-local-token"] = credential.token
    else:
        raise GlobiguardConfigError("Unrecognized GlobiGuard credential kind.")
    return headers


class Transport:
    def __init__(
        self,
        *,
        base_url: str,
        client_name: str,
        credential: Credential,
        environment: Environment,
        timeout: float,
        opener: TransportCallable | None = None,
    ) -> None:
        self._base_url = base_url
        self._client_name = client_name
        self._credential = credential
        self._environment = environment
        self._timeout = timeout
        self._opener = opener or urlopen

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        query: Mapping[str, QueryValue] | None = None,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        url = _apply_query(join_url(self._base_url, path), query)
        request_headers = self._build_headers(headers)
        data = self._encode_body(body, request_headers)
        request = Request(url, data=data, headers=request_headers, method=method)

        try:
            with self._opener(request, timeout=self._timeout) as response:
                return _decode_response(response.status, response.headers, response.read())
        except HTTPError as exc:
            body_value = _decode_response(exc.code, exc.headers, exc.read())
            raise GlobiguardHttpError(
                f"GlobiGuard request failed with status {exc.code}.",
                exc.code,
                body_value,
            ) from exc

    def _build_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        result = _credential_headers(self._credential)
        if headers:
            for key, value in headers.items():
                if key.lower() not in _RESERVED_HEADERS:
                    result[key] = value
        result["x-globiguard-client"] = self._client_name
        result["x-globiguard-environment"] = self._environment
        return result

    @staticmethod
    def _encode_body(body: Any, headers: dict[str, str]) -> bytes | None:
        if body is None:
            return None
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            return body.encode("utf-8")
        has_content_type = any(key.lower() == "content-type" for key in headers)
        if not has_content_type:
            headers["content-type"] = "application/json"
        return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _decode_response(status: int, headers: Mapping[str, str], body: bytes) -> Any:
    if status in {204, 205} or not body:
        return None
    content_type = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            content_type = value
            break
    text = body.decode("utf-8")
    if "application/json" in content_type:
        return json.loads(text)
    return text
