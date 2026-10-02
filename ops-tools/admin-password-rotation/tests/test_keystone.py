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
from admin_password_rotation.keystone import (
    FakeKeystoneClient,
    HttpKeystoneClient,
    KeystoneAuthenticationStatus,
    KeystoneAuthIndeterminate,
    KeystoneAuthRejected,
    KeystoneAuthSuccess,
    KeystoneIndeterminateReason,
    KeystonePasswordAuthRequest,
    KeystoneUserObservation,
)
from admin_password_rotation.model import SecretValue

PASSWORD = "ADMIN_SECRET_SENTINEL"
TOKEN = "KEYSTONE_TOKEN_SENTINEL"
MANAGEMENT_TOKEN = SecretValue(b"MANAGEMENT_TOKEN_SENTINEL")


def response(
    status: int, value: object | None = None, *, token: str | None = None,
) -> HttpResponse:
    headers = () if token is None else (("X-Subject-Token", token),)
    content = b"" if value is None else json.dumps(value).encode("utf-8")
    return HttpResponse(status, headers, content)


def auth_document(*, user_id: str = "admin-user") -> dict[str, object]:
    return {
        "token": {
            "expires_at": "2030-01-02T03:04:05Z",
            "user": {
                "id": user_id,
                "name": "admin",
                "domain": {"id": "default-domain"},
            },
            "project": {
                "id": "admin-project",
                "name": "admin-project-name",
                "domain": {"id": "default-domain"},
            },
            "roles": [
                {"id": "admin-role-id", "name": "admin"},
                {"id": "member-role-id", "name": "member"},
            ],
        },
    }


def user_update_document(user_id: object = "admin-user") -> dict[str, object]:
    return {"user": {"id": user_id}}


def auth_request() -> KeystonePasswordAuthRequest:
    return KeystonePasswordAuthRequest(
        "admin", "default-domain", "admin-project", SecretValue(PASSWORD.encode()),
    )


def decoded_body(body: bytes | None) -> object:
    assert body is not None
    return json.loads(body)


def test_password_auth_success_exposes_identity_scope_and_roles() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(201, auth_document(), token=TOKEN))

    result = HttpKeystoneClient(transport).authenticate_password(auth_request())

    assert isinstance(result, KeystoneAuthSuccess)
    assert result.status is KeystoneAuthenticationStatus.SUCCESS
    assert result.observation.user_id == "admin-user"
    assert result.observation.project_id == "admin-project"
    assert [(role.role_id, role.name) for role in result.observation.roles] == [
        ("admin-role-id", "admin"),
        ("member-role-id", "member"),
    ]
    assert result.observation.expires_at == datetime(
        2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc,
    )
    request = transport.requests[0]
    assert request.method == "POST"
    assert request.path == "/v3/auth/tokens"
    assert decoded_body(request.body) == {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {
                    "domain": {"id": "default-domain"},
                    "name": "admin",
                    "password": PASSWORD,
                }},
            },
            "scope": {"project": {"id": "admin-project"}},
        },
    }


def test_successful_auth_for_different_user_remains_success_observation() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(201, auth_document(user_id="replacement-user"), token=TOKEN))
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert isinstance(result, KeystoneAuthSuccess)
    assert result.observation.user_id == "replacement-user"


def test_only_unambiguous_credential_rejection_is_rejected() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(401, {"error": PASSWORD}))
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert isinstance(result, KeystoneAuthRejected)
    assert result.status is KeystoneAuthenticationStatus.CREDENTIAL_REJECTED


def test_mfa_auth_receipt_is_indeterminate_not_credential_rejection() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(HttpResponse(
        401,
        (("Openstack-Auth-Receipt", "AUTH_RECEIPT_SENTINEL"),),
        json.dumps({"receipt": {"methods": ["password"]}}).encode(),
    ))
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert result == KeystoneAuthIndeterminate(
        KeystoneIndeterminateReason.AUTHORIZATION_OR_POLICY,
    )
    assert "AUTH_RECEIPT_SENTINEL" not in repr(result) + str(result)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (403, KeystoneIndeterminateReason.AUTHORIZATION_OR_POLICY),
        (429, KeystoneIndeterminateReason.DEPENDENCY_FAILURE),
        (500, KeystoneIndeterminateReason.DEPENDENCY_FAILURE),
        (418, KeystoneIndeterminateReason.UNEXPECTED_RESPONSE),
    ],
)
def test_non_rejection_auth_responses_are_indeterminate(
    status: int, reason: KeystoneIndeterminateReason,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(status, {"secret": PASSWORD}))
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert result == KeystoneAuthIndeterminate(reason)


@pytest.mark.parametrize("transport_error", list(HttpTransportErrorCode))
def test_auth_transport_failures_are_indeterminate(
    transport_error: HttpTransportErrorCode,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_error(transport_error)
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert result == KeystoneAuthIndeterminate(KeystoneIndeterminateReason.DEPENDENCY_FAILURE)


@pytest.mark.parametrize(
    "bad_response",
    [
        HttpResponse(201, (("X-Subject-Token", TOKEN),), b"not-json"),
        response(201, {"token": {}}, token=TOKEN),
        response(201, auth_document(), token=None),
    ],
)
def test_malformed_auth_success_is_indeterminate(bad_response: HttpResponse) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(bad_response)
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert result == KeystoneAuthIndeterminate(KeystoneIndeterminateReason.MALFORMED_RESPONSE)


def test_auth_secrets_are_redacted_from_models_and_request_repr() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(201, auth_document(), token=TOKEN))
    result = HttpKeystoneClient(transport).authenticate_password(auth_request())
    assert isinstance(result, KeystoneAuthSuccess)
    visible = repr(result) + str(result) + repr(auth_request()) + repr(transport.requests[0])
    assert PASSWORD not in visible
    assert TOKEN not in visible


def test_administrative_password_reset_targets_exact_user_id() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, user_update_document("user/id")))
    client = HttpKeystoneClient(transport)
    client.set_user_password(
        user_id="user/id", new_password=SecretValue(PASSWORD.encode()),
        management_token=MANAGEMENT_TOKEN,
    )

    request = transport.requests[0]
    assert request.method == "PATCH"
    assert request.path == "/v3/users/user%2Fid"
    assert "password" not in request.path
    assert decoded_body(request.body) == {"user": {"password": PASSWORD}}
    assert request.mutation is True
    assert PASSWORD not in repr(request)
    assert "MANAGEMENT_TOKEN_SENTINEL" not in repr(request)


def test_get_user_parses_exact_lockout_option_and_metadata() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, {"user": {
        "id": "admin-user",
        "name": "admin",
        "domain_id": "default-domain",
        "enabled": True,
        "default_project_id": "admin-project",
        "options": {"ignore_lockout_failure_attempts": False},
    }}))
    observed = HttpKeystoneClient(transport).get_user(
        user_id="admin-user", management_token=MANAGEMENT_TOKEN,
    )
    assert observed == KeystoneUserObservation(
        "admin-user", "admin", "default-domain", True, "admin-project", False,
    )


@pytest.mark.parametrize("bad_option", [None, 0, "false", {}])
def test_get_user_rejects_malformed_lockout_option(bad_option: object) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, {"user": {
        "id": "admin-user", "name": "admin", "domain_id": "default-domain",
        "enabled": True, "default_project_id": None,
        "options": {"ignore_lockout_failure_attempts": bad_option},
    }}))
    with pytest.raises(ExternalClientError) as raised:
        HttpKeystoneClient(transport).get_user(
            user_id="admin-user", management_token=MANAGEMENT_TOKEN,
        )
    assert raised.value.kind is ExternalErrorCode.MALFORMED_RESPONSE


def test_lockout_patch_changes_only_requested_option() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(200, user_update_document()))
    HttpKeystoneClient(transport).set_ignore_lockout_failure_attempts(
        user_id="admin-user", value=True, management_token=MANAGEMENT_TOKEN,
    )
    request = transport.requests[0]
    assert request.path == "/v3/users/admin-user"
    assert decoded_body(request.body) == {
        "user": {"options": {"ignore_lockout_failure_attempts": True}},
    }


@pytest.mark.parametrize(
    ("mutation_response", "kind"),
    [
        (
            response(200, user_update_document("different-user")),
            ExternalErrorCode.RECORD_MISMATCH,
        ),
        (response(200, {}), ExternalErrorCode.MALFORMED_RESPONSE),
        (response(200, user_update_document(None)), ExternalErrorCode.MALFORMED_RESPONSE),
        (response(200, user_update_document("")), ExternalErrorCode.MALFORMED_RESPONSE),
        (response(204), ExternalErrorCode.UNEXPECTED_RESPONSE),
        (response(403), ExternalErrorCode.AUTHORIZATION_FAILURE),
        (response(500), ExternalErrorCode.DEPENDENCY_FAILURE),
    ],
)
def test_password_mutation_rejects_invalid_or_unsuccessful_responses(
    mutation_response: HttpResponse, kind: ExternalErrorCode,
) -> None:
    transport = FakeHttpTransport()
    transport.queue_response(mutation_response)
    with pytest.raises(ExternalClientError) as raised:
        HttpKeystoneClient(transport).set_user_password(
            user_id="admin-user", new_password=SecretValue(PASSWORD.encode()),
            management_token=MANAGEMENT_TOKEN,
        )
    assert raised.value.kind is kind


def test_lockout_mutation_rejects_204_as_unexpected() -> None:
    transport = FakeHttpTransport()
    transport.queue_response(response(204))
    with pytest.raises(ExternalClientError) as raised:
        HttpKeystoneClient(transport).set_ignore_lockout_failure_attempts(
            user_id="admin-user", value=True, management_token=MANAGEMENT_TOKEN,
        )
    assert raised.value.kind is ExternalErrorCode.UNEXPECTED_RESPONSE


def test_mutation_timeout_is_ambiguous_and_secret_safe() -> None:
    transport = FakeHttpTransport()
    transport.queue_error(HttpTransportErrorCode.MUTATION_AMBIGUOUS)
    with pytest.raises(ExternalClientError) as raised:
        HttpKeystoneClient(transport).set_user_password(
            user_id="admin-user", new_password=SecretValue(PASSWORD.encode()),
            management_token=MANAGEMENT_TOKEN,
        )
    assert raised.value.kind is ExternalErrorCode.MUTATION_AMBIGUOUS
    visible = str(raised.value) + repr(raised.value)
    assert PASSWORD not in visible
    assert "MANAGEMENT_TOKEN_SENTINEL" not in visible


def test_lockout_mutation_timeout_is_ambiguous() -> None:
    transport = FakeHttpTransport()
    transport.queue_error(HttpTransportErrorCode.MUTATION_AMBIGUOUS)
    with pytest.raises(ExternalClientError) as raised:
        HttpKeystoneClient(transport).set_ignore_lockout_failure_attempts(
            user_id="admin-user", value=True, management_token=MANAGEMENT_TOKEN,
        )
    assert raised.value.kind is ExternalErrorCode.MUTATION_AMBIGUOUS


def test_behavioral_fake_changes_accepted_password_and_lockout_option() -> None:
    fake = FakeKeystoneClient(
        project_id="admin-project", project_name="admin-project-name",
        project_domain_id="default-domain",
    )
    fake.add_user(
        KeystoneUserObservation(
            "admin-user", "admin", "default-domain", True, "admin-project", False,
        ),
        SecretValue(b"old-password"),
    )
    fake.set_user_password(
        user_id="admin-user", new_password=SecretValue(b"new-password"),
        management_token=MANAGEMENT_TOKEN,
    )
    result = fake.authenticate_password(KeystonePasswordAuthRequest(
        "admin", "default-domain", "admin-project", SecretValue(b"new-password"),
    ))
    assert isinstance(result, KeystoneAuthSuccess)
    fake.set_ignore_lockout_failure_attempts(
        user_id="admin-user", value=True, management_token=MANAGEMENT_TOKEN,
    )
    assert fake.get_user(
        user_id="admin-user", management_token=MANAGEMENT_TOKEN,
    ).ignore_lockout_failure_attempts is True
