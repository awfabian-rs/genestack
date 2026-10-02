from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from admin_password_rotation.external_http import (
    ExternalClientError,
    ExternalErrorCode,
    FakeHttpTransport,
    HttpResponse,
    HttpTransportErrorCode,
)
from admin_password_rotation.model import SecretValue
from admin_password_rotation.passwordsafe import (
    FakePasswordSafeClient,
    HttpPasswordSafeClient,
    HttpRackspaceIdentityClient,
    IdentityAccess,
    PasswordSafeCredential,
)

IDENTITY_PASSWORD = "IDENTITY_PASSWORD_SENTINEL"
IDENTITY_TOKEN = "IDENTITY_TOKEN_SENTINEL"
PASSWORDSAFE_TOKEN = "PASSWORDSAFE_TOKEN_SENTINEL"
CURRENT_PASSWORD = "ADMIN_SECRET_SENTINEL"
NEW_PASSWORD = "BREAKGLASS_SECRET_SENTINEL"


def response(status: int, value: object | None = None) -> HttpResponse:
    content = b"" if value is None else json.dumps(value).encode("utf-8")
    return HttpResponse(status, (), content)


def decoded_body(body: bytes | None) -> object:
    assert body is not None
    return json.loads(body)


def access() -> IdentityAccess:
    return IdentityAccess(
        datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        SecretValue(PASSWORDSAFE_TOKEN.encode()),
    )


def current_document(
    *, project_id: int = 101, credential_id: int = 202,
    username: str = "admin", version: object = 9,
    password: str = CURRENT_PASSWORD,
) -> dict[str, object]:
    return {"credential": {
        "project_id": project_id,
        "id": credential_id,
        "username": username,
        "version": version,
        "password": password,
    }}


def header(request_headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    return next((value for key, value in request_headers if key == name), None)


def test_identity_auth_request_shape_and_redacted_success() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, {"access": {"token": {
        "id": IDENTITY_TOKEN,
        "expires": "2030-01-02T03:04:05Z",
    }}}))
    result = HttpRackspaceIdentityClient(transport).authenticate(
        username="svc-rotation", password=SecretValue(IDENTITY_PASSWORD.encode()),
    )

    assert result.expires_at == datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    request = transport.requests[0]
    assert request.method == "POST"
    assert request.path == "/v2.0/tokens"
    assert decoded_body(request.body) == {"auth": {
        "RAX-AUTH:domain": {"name": "Rackspace"},
        "passwordCredentials": {
            "username": "svc-rotation",
            "password": IDENTITY_PASSWORD,
        },
    }}
    visible = repr(result) + str(result) + repr(request)
    assert IDENTITY_PASSWORD not in visible
    assert IDENTITY_TOKEN not in visible


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (401, ExternalErrorCode.CREDENTIAL_REJECTED),
        (403, ExternalErrorCode.AUTHORIZATION_FAILURE),
        (500, ExternalErrorCode.DEPENDENCY_FAILURE),
    ],
)
def test_identity_auth_failures_are_typed_and_secret_safe(
    status: int, kind: ExternalErrorCode,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(status, {"secret": IDENTITY_PASSWORD}))
    with pytest.raises(ExternalClientError) as raised:
        HttpRackspaceIdentityClient(transport).authenticate(
            username="svc-rotation", password=SecretValue(IDENTITY_PASSWORD.encode()),
        )
    assert raised.value.kind is kind
    assert IDENTITY_PASSWORD not in str(raised.value) + repr(raised.value)


def test_identity_transport_failure_is_dependency_failure() -> None:
    transport = FakeHttpTransport()
    transport.queue_error(HttpTransportErrorCode.FAILURE)
    with pytest.raises(ExternalClientError) as raised:
        HttpRackspaceIdentityClient(transport).authenticate(
            username="svc-rotation", password=SecretValue(IDENTITY_PASSWORD.encode()),
        )
    assert raised.value.kind is ExternalErrorCode.DEPENDENCY_FAILURE


def test_get_current_validates_record_and_keeps_password_redacted() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, current_document()))
    result = HttpPasswordSafeClient(transport).get_current(
        access=access(), project_id=101, credential_id=202,
        expected_username="admin",
    )
    assert result.project_id == 101
    assert result.credential_id == 202
    assert result.username == "admin"
    assert result.version == 9
    assert result.password == SecretValue(CURRENT_PASSWORD.encode())
    request = transport.requests[0]
    assert request.method == "GET"
    assert request.path == "/projects/101/credentials/202"
    assert header(request.headers, "Accept") == "application/json"
    assert header(request.headers, "X-Auth-Token") == PASSWORDSAFE_TOKEN
    visible = repr(result) + str(result) + repr(request)
    assert CURRENT_PASSWORD not in visible
    assert PASSWORDSAFE_TOKEN not in visible


@pytest.mark.parametrize(
    ("document", "kind"),
    [
        (current_document(project_id=999), ExternalErrorCode.RECORD_MISMATCH),
        (current_document(credential_id=999), ExternalErrorCode.RECORD_MISMATCH),
        (current_document(username="other"), ExternalErrorCode.RECORD_MISMATCH),
        (current_document(version=0), ExternalErrorCode.MALFORMED_RESPONSE),
        (current_document(version="9"), ExternalErrorCode.MALFORMED_RESPONSE),
    ],
)
def test_get_current_rejects_record_mismatches_and_malformed_versions(
    document: dict[str, object], kind: ExternalErrorCode,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, document))
    with pytest.raises(ExternalClientError) as raised:
        HttpPasswordSafeClient(transport).get_current(
            access=access(), project_id=101, credential_id=202,
            expected_username="admin",
        )
    assert raised.value.kind is kind
    assert CURRENT_PASSWORD not in str(raised.value) + repr(raised.value)


def test_password_update_is_exact_password_only_patch_and_not_verified_result() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(204))
    result = HttpPasswordSafeClient(transport).update_password(
        access=access(), project_id=101, credential_id=202,
        new_password=SecretValue(NEW_PASSWORD.encode()),
    )
    assert result is None
    request = transport.requests[0]
    assert request.method == "PATCH"
    assert request.path == "/projects/101/credentials/202"
    assert request.mutation is True
    assert decoded_body(request.body) == {"credential": {"password": NEW_PASSWORD}}
    assert NEW_PASSWORD not in repr(request)
    assert PASSWORDSAFE_TOKEN not in repr(request)


def test_separate_get_after_patch_can_confirm_value_and_version() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(204))
    transport.queue_response(response(200, current_document(
        version=10, password=NEW_PASSWORD,
    )))
    client = HttpPasswordSafeClient(transport)
    client.update_password(
        access=access(), project_id=101, credential_id=202,
        new_password=SecretValue(NEW_PASSWORD.encode()),
    )
    observed = client.get_current(
        access=access(), project_id=101, credential_id=202,
        expected_username="admin",
    )
    assert observed.version == 10
    assert observed.password == SecretValue(NEW_PASSWORD.encode())


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (400, ExternalErrorCode.UNEXPECTED_RESPONSE),
        (401, ExternalErrorCode.CREDENTIAL_REJECTED),
        (403, ExternalErrorCode.AUTHORIZATION_FAILURE),
        (404, ExternalErrorCode.NOT_FOUND),
    ],
)
def test_password_update_definite_rejections_remain_non_ambiguous(
    status: int, kind: ExternalErrorCode,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(status))
    with pytest.raises(ExternalClientError) as raised:
        HttpPasswordSafeClient(transport).update_password(
            access=access(), project_id=101, credential_id=202,
            new_password=SecretValue(NEW_PASSWORD.encode()),
        )
    assert raised.value.kind is kind
    assert raised.value.kind is not ExternalErrorCode.MUTATION_AMBIGUOUS


@pytest.mark.parametrize("status", [200, 202, 500, 503])
def test_password_update_unexpected_2xx_and_5xx_are_ambiguous(status: int) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(status, {
        "password": NEW_PASSWORD,
        "token": PASSWORDSAFE_TOKEN,
    }))
    with pytest.raises(ExternalClientError) as raised:
        HttpPasswordSafeClient(transport).update_password(
            access=access(), project_id=101, credential_id=202,
            new_password=SecretValue(NEW_PASSWORD.encode()),
        )
    assert raised.value.kind is ExternalErrorCode.MUTATION_AMBIGUOUS
    visible = str(raised.value) + repr(raised.value)
    assert NEW_PASSWORD not in visible
    assert PASSWORDSAFE_TOKEN not in visible


@pytest.mark.parametrize("transport_error", list(HttpTransportErrorCode))
def test_password_update_transport_failure_is_ambiguous_and_secret_safe(
    transport_error: HttpTransportErrorCode,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_error(transport_error)
    with pytest.raises(ExternalClientError) as raised:
        HttpPasswordSafeClient(transport).update_password(
            access=access(), project_id=101, credential_id=202,
            new_password=SecretValue(NEW_PASSWORD.encode()),
        )
    assert raised.value.kind is ExternalErrorCode.MUTATION_AMBIGUOUS
    visible = str(raised.value) + repr(raised.value)
    assert NEW_PASSWORD not in visible
    assert PASSWORDSAFE_TOKEN not in visible


def test_external_http_error_does_not_echo_response_content() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(500, {
        "password": CURRENT_PASSWORD,
        "token": PASSWORDSAFE_TOKEN,
    }))
    with pytest.raises(ExternalClientError) as raised:
        HttpPasswordSafeClient(transport).get_current(
            access=access(), project_id=101, credential_id=202,
        )
    visible = str(raised.value) + repr(raised.value)
    assert CURRENT_PASSWORD not in visible
    assert PASSWORDSAFE_TOKEN not in visible


def test_behavioral_fake_supports_version_advancement_and_ambiguous_apply() -> None:
    fake = FakePasswordSafeClient()
    fake.add(PasswordSafeCredential(
        101, 202, "admin", 9, SecretValue(CURRENT_PASSWORD.encode()),
    ))
    fake.ambiguous_next_update_apply = True
    with pytest.raises(ExternalClientError) as raised:
        fake.update_password(
            access=access(), project_id=101, credential_id=202,
            new_password=SecretValue(NEW_PASSWORD.encode()),
        )
    assert raised.value.kind is ExternalErrorCode.MUTATION_AMBIGUOUS
    current = fake.get_current(access=access(), project_id=101, credential_id=202)
    assert current.version == 10
    assert current.password == SecretValue(NEW_PASSWORD.encode())


def test_behavioral_fake_supports_definite_rejection_without_applying() -> None:
    fake = FakePasswordSafeClient()
    fake.add(PasswordSafeCredential(
        101, 202, "admin", 9, SecretValue(CURRENT_PASSWORD.encode()),
    ))
    fake.next_update_error = ExternalErrorCode.AUTHORIZATION_FAILURE
    with pytest.raises(ExternalClientError) as raised:
        fake.update_password(
            access=access(), project_id=101, credential_id=202,
            new_password=SecretValue(NEW_PASSWORD.encode()),
        )
    assert raised.value.kind is ExternalErrorCode.AUTHORIZATION_FAILURE
    current = fake.get_current(access=access(), project_id=101, credential_id=202)
    assert current.version == 9
    assert current.password == SecretValue(CURRENT_PASSWORD.encode())
