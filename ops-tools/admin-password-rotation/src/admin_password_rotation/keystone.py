"""Typed direct-HTTP Keystone v3 client boundary."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, TypeAlias
from urllib.parse import quote

from .external_http import (
    ExternalClientError, ExternalErrorCode, HttpRequest, HttpResponse, HttpTransport,
    HttpTransportError, HttpTransportErrorCode, json_request_body, json_response_object,
    secret_text,
)
from .errors import ReadError
from .model import SecretValue
from .validation import nonempty_string, object_list, object_mapping


class KeystoneAuthenticationStatus(Enum):
    SUCCESS = "success"
    CREDENTIAL_REJECTED = "credential_rejected"
    INDETERMINATE = "indeterminate"


class KeystoneIndeterminateReason(Enum):
    DEPENDENCY_FAILURE = "dependency_failure"
    AUTHORIZATION_OR_POLICY = "authorization_or_policy"
    MALFORMED_RESPONSE = "malformed_response"
    UNEXPECTED_RESPONSE = "unexpected_response"


@dataclass(frozen=True)
class KeystoneRole:
    role_id: str
    name: str


@dataclass(frozen=True)
class KeystoneAuthObservation:
    user_id: str
    user_name: str
    user_domain_id: str
    project_id: str
    project_name: str
    project_domain_id: str
    roles: tuple[KeystoneRole, ...]
    expires_at: datetime


@dataclass(frozen=True)
class KeystoneAuthSuccess:
    observation: KeystoneAuthObservation
    token: SecretValue = field(repr=False)
    status: KeystoneAuthenticationStatus = field(
        default=KeystoneAuthenticationStatus.SUCCESS, init=False,
    )


@dataclass(frozen=True)
class KeystoneAuthRejected:
    status: KeystoneAuthenticationStatus = field(
        default=KeystoneAuthenticationStatus.CREDENTIAL_REJECTED, init=False,
    )


@dataclass(frozen=True)
class KeystoneAuthIndeterminate:
    reason: KeystoneIndeterminateReason
    status: KeystoneAuthenticationStatus = field(
        default=KeystoneAuthenticationStatus.INDETERMINATE, init=False,
    )


KeystoneAuthenticationResult: TypeAlias = (
    KeystoneAuthSuccess | KeystoneAuthRejected | KeystoneAuthIndeterminate
)


@dataclass(frozen=True)
class KeystonePasswordAuthRequest:
    username: str
    user_domain_id: str
    project_id: str
    password: SecretValue = field(repr=False)

    def __post_init__(self) -> None:
        if not self.username or not self.user_domain_id or not self.project_id:
            raise ValueError("Keystone authentication identifiers must be nonempty.")


@dataclass(frozen=True)
class KeystoneUserObservation:
    user_id: str
    name: str
    domain_id: str
    enabled: bool
    default_project_id: str | None
    ignore_lockout_failure_attempts: bool


class KeystoneClient(Protocol):
    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult: ...

    def set_user_password(
        self, *, user_id: str, new_password: SecretValue,
        management_token: SecretValue,
    ) -> None: ...

    def get_user(
        self, *, user_id: str, management_token: SecretValue,
    ) -> KeystoneUserObservation: ...

    def set_ignore_lockout_failure_attempts(
        self, *, user_id: str, value: bool, management_token: SecretValue,
    ) -> None: ...


def _timestamp(value: object) -> datetime:
    text = nonempty_string(value)
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + ("+00:00" if text.endswith("Z") else ""))
    except ValueError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
    return parsed.astimezone(timezone.utc)


def _string(value: object) -> str:
    try:
        return nonempty_string(value)
    except ReadError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None


def _mapping(value: object) -> dict[str, object]:
    try:
        return object_mapping(value)
    except ReadError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None


def _list(value: object) -> list[object]:
    try:
        return object_list(value)
    except ReadError:
        raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE) from None


def _auth_indeterminate(response: HttpResponse) -> KeystoneAuthIndeterminate:
    if response.status_code in (403, 406):
        reason = KeystoneIndeterminateReason.AUTHORIZATION_OR_POLICY
    elif response.status_code == 429 or response.status_code >= 500:
        reason = KeystoneIndeterminateReason.DEPENDENCY_FAILURE
    else:
        reason = KeystoneIndeterminateReason.UNEXPECTED_RESPONSE
    return KeystoneAuthIndeterminate(reason)


def _service_error(response: HttpResponse) -> ExternalClientError:
    if response.status_code in (401, 403):
        return ExternalClientError(ExternalErrorCode.AUTHORIZATION_FAILURE)
    if response.status_code == 404:
        return ExternalClientError(ExternalErrorCode.NOT_FOUND)
    if response.status_code == 429 or response.status_code >= 500:
        return ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE)
    return ExternalClientError(ExternalErrorCode.UNEXPECTED_RESPONSE)


def _management_headers(
    token: SecretValue, *, mutation: bool = False,
) -> tuple[tuple[str, str], ...]:
    headers = [("Accept", "application/json"), ("X-Auth-Token", secret_text(token))]
    if mutation:
        headers.append(("Content-Type", "application/json"))
    return tuple(headers)


def _user_path(user_id: str) -> str:
    if not user_id:
        raise ValueError("Keystone user ID must be nonempty.")
    return f"/v3/users/{quote(user_id, safe='')}"


class HttpKeystoneClient:
    def __init__(self, transport: HttpTransport) -> None:
        self._transport = transport

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        body = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {"user": {
                        "domain": {"id": request.user_domain_id},
                        "name": request.username,
                        "password": secret_text(request.password),
                    }},
                },
                "scope": {"project": {"id": request.project_id}},
            },
        }
        try:
            response = self._transport.send(HttpRequest(
                "POST", "/v3/auth/tokens",
                (("Accept", "application/json"), ("Content-Type", "application/json")),
                json_request_body(body),
            ))
        except HttpTransportError:
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)
        # Keystone uses an auth-receipt header when more authentication methods
        # are required. That is a policy/MFA result, not proof of a bad password.
        if response.status_code == 401 and response.header("Openstack-Auth-Receipt") is None:
            return KeystoneAuthRejected()
        if response.status_code == 401:
            return KeystoneAuthIndeterminate(
                KeystoneIndeterminateReason.AUTHORIZATION_OR_POLICY,
            )
        if response.status_code != 201:
            return _auth_indeterminate(response)
        try:
            token_text = response.header("X-Subject-Token")
            if token_text is None or not token_text:
                raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
            root = json_response_object(response)
            token_data = _mapping(root.get("token"))
            user = _mapping(token_data.get("user"))
            user_domain = _mapping(user.get("domain"))
            project = _mapping(token_data.get("project"))
            project_domain = _mapping(project.get("domain"))
            roles = tuple(
                KeystoneRole(_string(role.get("id")), _string(role.get("name")))
                for item in _list(token_data.get("roles"))
                for role in (_mapping(item),)
            )
            if not roles:
                raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
            observation = KeystoneAuthObservation(
                user_id=_string(user.get("id")),
                user_name=_string(user.get("name")),
                user_domain_id=_string(user_domain.get("id")),
                project_id=_string(project.get("id")),
                project_name=_string(project.get("name")),
                project_domain_id=_string(project_domain.get("id")),
                roles=roles,
                expires_at=_timestamp(token_data.get("expires_at")),
            )
            return KeystoneAuthSuccess(observation, SecretValue(token_text.encode("utf-8")))
        except ExternalClientError:
            return KeystoneAuthIndeterminate(KeystoneIndeterminateReason.MALFORMED_RESPONSE)

    def set_user_password(
        self, *, user_id: str, new_password: SecretValue,
        management_token: SecretValue,
    ) -> None:
        self._mutation(
            _user_path(user_id),
            {"user": {"password": secret_text(new_password)}},
            management_token,
        )

    def get_user(
        self, *, user_id: str, management_token: SecretValue,
    ) -> KeystoneUserObservation:
        try:
            response = self._transport.send(HttpRequest(
                "GET", _user_path(user_id), _management_headers(management_token),
            ))
        except HttpTransportError:
            raise ExternalClientError(ExternalErrorCode.DEPENDENCY_FAILURE) from None
        if response.status_code != 200:
            raise _service_error(response)
        root = json_response_object(response)
        user = _mapping(root.get("user"))
        returned_id = _string(user.get("id"))
        if returned_id != user_id:
            raise ExternalClientError(ExternalErrorCode.RECORD_MISMATCH)
        enabled = user.get("enabled")
        if not isinstance(enabled, bool):
            raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
        default_project_value = user.get("default_project_id")
        if default_project_value is not None and not isinstance(default_project_value, str):
            raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
        if default_project_value == "":
            raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
        options = _mapping(user.get("options"))
        ignore = options.get("ignore_lockout_failure_attempts")
        if not isinstance(ignore, bool):
            raise ExternalClientError(ExternalErrorCode.MALFORMED_RESPONSE)
        return KeystoneUserObservation(
            returned_id,
            _string(user.get("name")),
            _string(user.get("domain_id")),
            enabled,
            default_project_value,
            ignore,
        )

    def set_ignore_lockout_failure_attempts(
        self, *, user_id: str, value: bool, management_token: SecretValue,
    ) -> None:
        self._mutation(
            _user_path(user_id),
            {"user": {"options": {"ignore_lockout_failure_attempts": value}}},
            management_token,
        )

    def _mutation(
        self, path: str, body: object, management_token: SecretValue,
    ) -> None:
        try:
            response = self._transport.send(HttpRequest(
                "PATCH", path, _management_headers(management_token, mutation=True),
                json_request_body(body), mutation=True,
            ))
        except HttpTransportError as exc:
            kind = (
                ExternalErrorCode.MUTATION_AMBIGUOUS
                if exc.kind is HttpTransportErrorCode.MUTATION_AMBIGUOUS
                else ExternalErrorCode.DEPENDENCY_FAILURE
            )
            raise ExternalClientError(kind) from None
        if response.status_code != 204:
            raise _service_error(response)


@dataclass
class _FakeKeystoneUser:
    observation: KeystoneUserObservation
    password: SecretValue = field(repr=False)


class FakeKeystoneClient:
    """Small behavioral fake for future runner tests."""

    def __init__(self, *, project_id: str, project_name: str, project_domain_id: str) -> None:
        self._project_id = project_id
        self._project_name = project_name
        self._project_domain_id = project_domain_id
        self._users: dict[str, _FakeKeystoneUser] = {}
        self.next_auth_indeterminate: KeystoneIndeterminateReason | None = None
        self.next_mutation_error: ExternalErrorCode | None = None

    def add_user(self, observation: KeystoneUserObservation, password: SecretValue) -> None:
        self._users[observation.user_id] = _FakeKeystoneUser(observation, password)

    def authenticate_password(
        self, request: KeystonePasswordAuthRequest,
    ) -> KeystoneAuthenticationResult:
        if self.next_auth_indeterminate is not None:
            reason = self.next_auth_indeterminate
            self.next_auth_indeterminate = None
            return KeystoneAuthIndeterminate(reason)
        match = next((
            user for user in self._users.values()
            if user.observation.name == request.username
            and user.observation.domain_id == request.user_domain_id
            and user.password == request.password
        ), None)
        if match is None:
            return KeystoneAuthRejected()
        observation = KeystoneAuthObservation(
            match.observation.user_id,
            match.observation.name,
            match.observation.domain_id,
            self._project_id,
            self._project_name,
            self._project_domain_id,
            (KeystoneRole("admin-role", "admin"),),
            datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        return KeystoneAuthSuccess(observation, SecretValue(b"FAKE_REDACTED_TOKEN"))

    def _maybe_fail_mutation(self) -> None:
        if self.next_mutation_error is not None:
            kind = self.next_mutation_error
            self.next_mutation_error = None
            raise ExternalClientError(kind)

    def set_user_password(
        self, *, user_id: str, new_password: SecretValue,
        management_token: SecretValue,
    ) -> None:
        del management_token
        self._maybe_fail_mutation()
        if user_id not in self._users:
            raise ExternalClientError(ExternalErrorCode.NOT_FOUND)
        self._users[user_id].password = new_password

    def get_user(
        self, *, user_id: str, management_token: SecretValue,
    ) -> KeystoneUserObservation:
        del management_token
        if user_id not in self._users:
            raise ExternalClientError(ExternalErrorCode.NOT_FOUND)
        return self._users[user_id].observation

    def set_ignore_lockout_failure_attempts(
        self, *, user_id: str, value: bool, management_token: SecretValue,
    ) -> None:
        del management_token
        self._maybe_fail_mutation()
        if user_id not in self._users:
            raise ExternalClientError(ExternalErrorCode.NOT_FOUND)
        current = self._users[user_id]
        old = current.observation
        current.observation = KeystoneUserObservation(
            old.user_id, old.name, old.domain_id, old.enabled,
            old.default_project_id, value,
        )
