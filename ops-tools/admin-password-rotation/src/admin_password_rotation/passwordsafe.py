"""Rackspace Identity and PasswordSafe direct-HTTP client boundaries."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import quote

from .external_http import (
    ExternalClientError, ExternalErrorCode, HttpRequest, HttpResponse, HttpTransport,
    HttpTransportError, json_request_body, json_response_object, secret_text,
)
from .errors import ReadError
from .model import SecretValue
from .validation import nonempty_string, object_mapping


@dataclass(frozen=True)
class IdentityAccess:
    expires_at: datetime
    token: SecretValue = field(repr=False)


@dataclass(frozen=True)
class PasswordSafeCredential:
    project_id: int
    credential_id: int
    username: str
    version: int
    password: SecretValue = field(repr=False)


class RackspaceIdentityClient(Protocol):
    def authenticate(self, *, username: str, password: SecretValue) -> IdentityAccess: ...


class PasswordSafeClient(Protocol):
    def get_current(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        expected_username: str | None = None,
    ) -> PasswordSafeCredential: ...

    def update_password(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        new_password: SecretValue,
    ) -> None: ...


def _timestamp(value: object) -> datetime:
    text = _string(value)
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + ("+00:00" if text.endswith("Z") else ""))
    except ValueError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
    return parsed.astimezone(timezone.utc)


def _mapping(value: object) -> dict[str, object]:
    try:
        return object_mapping(value)
    except ReadError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None


def _string(value: object) -> str:
    try:
        return nonempty_string(value)
    except ReadError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None


def _positive_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
    return value


def _path_id(value: int, label: str) -> str:
    if isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer.")
    return str(value)


def _service_error(response: HttpResponse) -> ExternalClientError:
    if response.status_code == 401:
        return ExternalClientError(ExternalErrorCode.CREDENTIAL_REJECTED)
    if response.status_code == 403:
        return ExternalClientError(ExternalErrorCode.AUTHORIZATION_FAILURE)
    if response.status_code == 404:
        return ExternalClientError(ExternalErrorCode.NOT_FOUND)
    if response.status_code == 429 or response.status_code >= 500:
        return ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE)
    return ExternalClientError(ExternalErrorCode.UNEXPECTED_RESPONSE)


def _mutation_response_error(response: HttpResponse) -> ExternalClientError:
    if 200 <= response.status_code < 300 or 500 <= response.status_code < 600:
        return ExternalClientError(ExternalErrorCode.MUTATION_AMBIGUOUS)
    return _service_error(response)


def _passwordsafe_path(project_id: int, credential_id: int) -> str:
    project = quote(_path_id(project_id, "PasswordSafe project ID"), safe="")
    credential = quote(_path_id(credential_id, "PasswordSafe credential ID"), safe="")
    return f"/projects/{project}/credentials/{credential}"


def _passwordsafe_headers(
    access: IdentityAccess, *, accept: str, mutation: bool = False,
) -> tuple[tuple[str, str], ...]:
    headers = [("Accept", accept), ("X-Auth-Token", secret_text(access.token))]
    if mutation:
        headers.append(("Content-Type", "application/json"))
    return tuple(headers)


class HttpRackspaceIdentityClient:
    def __init__(
        self, transport: HttpTransport, *, token_path: str = "/v2.0/tokens",
        domain_name: str = "Rackspace",
    ) -> None:
        if not token_path.startswith("/") or not domain_name:
            raise ValueError("Identity token path and domain name must be nonempty.")
        self._transport = transport
        self._token_path = token_path
        self._domain_name = domain_name

    def authenticate(self, *, username: str, password: SecretValue) -> IdentityAccess:
        if not username:
            raise ValueError("Identity username must be nonempty.")
        body = {"auth": {
            "RAX-AUTH:domain": {"name": self._domain_name},
            "passwordCredentials": {
                "password": secret_text(password),
                "username": username,
            },
        }}
        try:
            response = self._transport.send(HttpRequest(
                "POST", self._token_path,
                (("Accept", "application/json"), ("Content-Type", "application/json")),
                json_request_body(body),
            ))
        except HttpTransportError:
            raise ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE) from None
        if response.status_code not in (200, 203):
            raise _service_error(response)
        root = json_response_object(response)
        access = _mapping(root.get("access"))
        token = _mapping(access.get("token"))
        return IdentityAccess(
            _timestamp(token.get("expires")),
            SecretValue(_string(token.get("id")).encode("utf-8")),
        )


class HttpPasswordSafeClient:
    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    def get_current(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        expected_username: str | None = None,
    ) -> PasswordSafeCredential:
        try:
            response = self._transport.send(HttpRequest(
                "GET", _passwordsafe_path(project_id, credential_id),
                _passwordsafe_headers(access, accept="application/json"),
            ))
        except HttpTransportError:
            raise ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE) from None
        if response.status_code != 200:
            raise _service_error(response)
        root = json_response_object(response)
        record_value = root.get("credential", root)
        record = _mapping(record_value)
        observed = PasswordSafeCredential(
            _positive_integer(record.get("project_id")),
            _positive_integer(record.get("id")),
            _string(record.get("username")),
            _positive_integer(record.get("version")),
            SecretValue(_string(record.get("password")).encode("utf-8")),
        )
        if observed.project_id != project_id or observed.credential_id != credential_id:
            raise ExternalClientError(ExternalErrorCode.RECORD_MISMATCH)
        if expected_username is not None and observed.username != expected_username:
            raise ExternalClientError(ExternalErrorCode.RECORD_MISMATCH)
        return observed

    def update_password(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        new_password: SecretValue,
    ) -> None:
        try:
            response = self._transport.send(HttpRequest(
                "PATCH", _passwordsafe_path(project_id, credential_id),
                _passwordsafe_headers(access, accept="application/json", mutation=True),
                json_request_body({"credential": {"password": secret_text(new_password)}}),
                mutation=True,
            ))
        except HttpTransportError:
            raise ExternalClientError(ExternalErrorCode.MUTATION_AMBIGUOUS) from None
        if response.status_code != 204:
            raise _mutation_response_error(response)


class FakeRackspaceIdentityClient:
    def __init__(self, username: str, password: SecretValue, access: IdentityAccess) -> None:
        self._username = username
        self._password = password
        self._access = access
        self.failure: ExternalErrorCode | None = None

    def authenticate(self, *, username: str, password: SecretValue) -> IdentityAccess:
        if self.failure is not None:
            raise ExternalClientError(self.failure)
        if username != self._username or password != self._password:
            raise ExternalClientError(ExternalErrorCode.CREDENTIAL_REJECTED)
        return self._access


class FakePasswordSafeClient:
    """Behavioral current-credential store for future runner tests."""

    def __init__(self) -> None:
        self._records: dict[tuple[int, int], PasswordSafeCredential] = {}
        self.next_update_error: ExternalErrorCode | None = None
        self.ambiguous_next_update_apply: bool | None = None
        self.get_calls: list[tuple[int, int]] = []
        self.update_calls: list[tuple[int, int]] = []

    def add(self, credential: PasswordSafeCredential) -> None:
        key = (credential.project_id, credential.credential_id)
        self._records[key] = credential

    def get_current(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        expected_username: str | None = None,
    ) -> PasswordSafeCredential:
        del access
        self.get_calls.append((project_id, credential_id))
        key = (project_id, credential_id)
        if key not in self._records:
            raise ExternalClientError(ExternalErrorCode.NOT_FOUND)
        record = self._records[key]
        if expected_username is not None and record.username != expected_username:
            raise ExternalClientError(ExternalErrorCode.RECORD_MISMATCH)
        return record

    def update_password(
        self, *, access: IdentityAccess, project_id: int, credential_id: int,
        new_password: SecretValue,
    ) -> None:
        del access
        self.update_calls.append((project_id, credential_id))
        if self.next_update_error is not None:
            kind = self.next_update_error
            self.next_update_error = None
            raise ExternalClientError(kind)
        key = (project_id, credential_id)
        if key not in self._records:
            raise ExternalClientError(ExternalErrorCode.NOT_FOUND)
        old = self._records[key]
        apply = self.ambiguous_next_update_apply
        if apply is None or apply:
            self._records[key] = PasswordSafeCredential(
                project_id, credential_id, old.username, old.version + 1, new_password,
            )
        if apply is not None:
            self.ambiguous_next_update_apply = None
            raise ExternalClientError(ExternalErrorCode.MUTATION_AMBIGUOUS)
