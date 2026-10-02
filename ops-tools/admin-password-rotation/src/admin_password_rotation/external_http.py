"""Small secret-safe HTTP boundary for external credential systems."""
from __future__ import annotations

import math
import json
import ssl
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

import httpx

from .errors import ReadError, SafeError
from .model import SecretValue
from .validation import object_mapping


DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0
MAX_JSON_RESPONSE_BYTES = 2 * 1024 * 1024


class ExternalErrorCode(Enum):
    CREDENTIAL_REJECTED = "credential_rejected"
    AUTHORIZATION_FAILURE = "authorization_failure"
    DEPENDENCY_FAILURE = "dependency_failure"
    MALFORMED_RESPONSE = "malformed_response"
    UNEXPECTED_RESPONSE = "unexpected_response"
    RECORD_MISMATCH = "record_mismatch"
    NOT_FOUND = "not_found"
    MUTATION_AMBIGUOUS = "mutation_ambiguous"


_ERROR_MESSAGES: dict[ExternalErrorCode, str] = {
    ExternalErrorCode.CREDENTIAL_REJECTED: "The external service rejected the supplied credential.",
    ExternalErrorCode.AUTHORIZATION_FAILURE: "The external service denied the requested operation.",
    ExternalErrorCode.DEPENDENCY_FAILURE: "The external service request failed; response details withheld.",
    ExternalErrorCode.MALFORMED_RESPONSE: "The external service returned an invalid response; content withheld.",
    ExternalErrorCode.UNEXPECTED_RESPONSE: "The external service returned an unexpected response; content withheld.",
    ExternalErrorCode.RECORD_MISMATCH: "The external service returned a different record than requested.",
    ExternalErrorCode.NOT_FOUND: "The requested external object does not exist.",
    ExternalErrorCode.MUTATION_AMBIGUOUS: "The external mutation outcome is ambiguous; reobserve before deciding.",
}


class ExternalClientError(SafeError):
    def __init__(self, kind: ExternalErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class HttpTransportErrorCode(Enum):
    FAILURE = "failure"
    MUTATION_AMBIGUOUS = "mutation_ambiguous"


class HttpTransportError(Exception):
    def __init__(self, kind: HttpTransportErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value)


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes | None = field(default=None, repr=False)
    mutation: bool = False


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    content: bytes = field(default=b"", repr=False)

    def header(self, name: str) -> str | None:
        wanted = name.casefold()
        return next((value for key, value in self.headers if key.casefold() == wanted), None)


class HttpTransport(Protocol):
    def send(self, request: HttpRequest) -> HttpResponse: ...


@dataclass(frozen=True)
class HttpClientSettings:
    base_url: str
    trusted_ca: Path | None = None
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not self.base_url or any(ord(char) < 32 for char in self.base_url):
            raise ValueError("HTTP base URL must be nonempty and contain no control characters.")
        values = (self.connect_timeout_seconds, self.request_timeout_seconds)
        if any(not math.isfinite(value) or value <= 0 for value in values):
            raise ValueError("HTTP timeout values must be finite and positive.")


class HttpxTransport:
    """Bounded direct HTTP transport with no automatic mutation retries."""

    def __init__(self, settings: HttpClientSettings) -> None:
        try:
            url = httpx.URL(settings.base_url)
            if url.scheme not in ("http", "https") or not url.host:
                raise ValueError("Invalid HTTP base URL.")
            verify: bool | ssl.SSLContext = True
            if settings.trusted_ca is not None:
                verify = ssl.create_default_context(cafile=str(settings.trusted_ca))
            timeout = httpx.Timeout(
                settings.request_timeout_seconds,
                connect=settings.connect_timeout_seconds,
            )
            self._client = httpx.Client(base_url=url, verify=verify, timeout=timeout)
        except (OSError, ValueError, ssl.SSLError):
            raise ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE) from None

    def send(self, request: HttpRequest) -> HttpResponse:
        try:
            response = self._client.request(
                request.method,
                request.path,
                headers=dict(request.headers),
                content=request.body,
            )
        except httpx.TransportError:
            kind = (
                HttpTransportErrorCode.MUTATION_AMBIGUOUS
                if request.mutation else HttpTransportErrorCode.FAILURE
            )
            raise HttpTransportError(kind) from None
        return HttpResponse(
            response.status_code,
            tuple(response.headers.multi_items()),
            response.content,
        )

    def close(self) -> None:
        self._client.close()


class FakeHttpTransport:
    """FIFO behavioral transport used by service-adapter tests."""

    def __init__(self) -> None:
        self.requests: list[HttpRequest] = []
        self._results: list[HttpResponse | HttpTransportError] = []

    def queue_response(self, response: HttpResponse) -> None:
        self._results.append(response)

    def queue_error(self, kind: HttpTransportErrorCode) -> None:
        self._results.append(HttpTransportError(kind))

    def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self._results:
            raise AssertionError("Fake HTTP transport has no queued result.")
        result = self._results.pop(0)
        if isinstance(result, HttpTransportError):
            raise result
        return result


def json_request_body(value: object) -> bytes:
    """Encode an explicitly constructed request; callers control its allow-list."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def json_response_object(response: HttpResponse) -> dict[str, object]:
    if len(response.content) > MAX_JSON_RESPONSE_BYTES:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
    try:
        value: object = json.loads(response.content, object_pairs_hook=_json_pairs)
        return object_mapping(value)
    except (UnicodeError, ValueError, RecursionError, ReadError):
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None


def secret_text(value: SecretValue) -> str:
    """Reveal only while constructing a service request at the HTTP boundary."""
    try:
        text = value.reveal().decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("External-service secret values must be valid UTF-8.") from None
    if not text:
        raise ValueError("External-service secret values must be nonempty UTF-8.")
    return text
