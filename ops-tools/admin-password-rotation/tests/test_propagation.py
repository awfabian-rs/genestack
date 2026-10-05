from __future__ import annotations

import base64
from dataclasses import replace

import pytest

from admin_password_rotation.errors import SafeError
from admin_password_rotation.model import (
    CredentialLocation, FieldsRepresentation, Identity, IdentityBinding,
    IniRepresentation, LocationRole, ReferenceCredentials, SecretField,
    SecretSnapshot, SecretValue, WorkloadKind, WorkloadRef, YamlRepresentation,
)
from admin_password_rotation.propagation import (
    ClassifiedCredentialLocation, CredentialMutationDisposition, CredentialMutationError,
    CredentialMutationErrorCode, CredentialMutationResult, DesiredCredential,
    CredentialSecretClientError, CredentialSecretClientErrorCode,
    FakeCredentialSecretClient,
    KubernetesApiCredentialSecretClient, classify_credential_location,
    mutate_credential_location,
)
from admin_password_rotation.representations import read_credential
from .helpers import secret


ADMIN = SecretValue(b"Synthetic-Admin-4A")
BREAKGLASS = SecretValue(b"Synthetic-Breakglass-4A")
RESTART = (WorkloadRef(WorkloadKind.DEPLOYMENT, "consumer"),)
REFERENCES = ReferenceCredentials(ADMIN, BREAKGLASS)


class Ownership:
    def __init__(self, *, fail: bool = False) -> None:
        self.assertions = 0
        self.fail = fail

    def assert_owned(self) -> None:
        self.assertions += 1
        if self.fail:
            raise SafeError("test_ownership_lost", "Ownership was lost.")

    @property
    def requires_recovery_gate(self) -> bool:
        return False


def location(
    representation: FieldsRepresentation | IniRepresentation | YamlRepresentation,
    *, identity: IdentityBinding = IdentityBinding.ACTIVE,
    role: LocationRole = LocationRole.PROPAGATED,
) -> CredentialLocation:
    return CredentialLocation(
        "consumer-location", "consumer", identity, role, representation, RESTART,
    )


def classified(
    configured: CredentialLocation, snapshot: SecretSnapshot,
) -> ClassifiedCredentialLocation:
    return classify_credential_location(configured, snapshot, REFERENCES)


def mutate(
    configured: CredentialLocation, snapshot: SecretSnapshot,
    target: DesiredCredential, *, allowed: frozenset[Identity] | None = None,
) -> tuple[FakeCredentialSecretClient, Ownership, CredentialMutationResult]:
    client = FakeCredentialSecretClient(snapshot)
    owner = Ownership()
    result = mutate_credential_location(
        client, owner, observed=classified(configured, snapshot), desired=target,
        allowed_observed_identities=(
            frozenset({Identity.ADMIN, Identity.BREAKGLASS})
            if allowed is None else allowed
        ),
    )
    return client, owner, result


def test_fields_admin_to_breakglass_is_structural_and_verified() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    original = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(),
        "OS_USERNAME": b"admin",
        "unrelated": b"preserve-byte-for-byte",
    })

    client, owner, result = mutate(
        configured, original, DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
    )

    assert result.disposition is CredentialMutationDisposition.CHANGED
    assert result.identity is Identity.BREAKGLASS
    assert result.restart_dependencies == RESTART
    assert result.required_restart_dependencies == RESTART
    assert client.snapshot.get("unrelated") == original.get("unrelated")
    observed = read_credential(client.snapshot, configured.representation)
    assert observed.username == "breakglass"
    assert observed.password == BREAKGLASS
    assert client.replace_calls == 1
    assert client.read_calls == 1
    assert owner.assertions == 1


def test_fields_breakglass_to_admin() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    original = secret("consumer", {
        "OS_PASSWORD": BREAKGLASS.reveal(), "OS_USERNAME": b"breakglass",
    })

    client, _owner, result = mutate(
        configured, original, DesiredCredential(Identity.ADMIN, ADMIN),
    )

    assert result.changed
    observed = read_credential(client.snapshot, configured.representation)
    assert observed.username == "admin"
    assert observed.password == ADMIN


def test_ini_mutation_preserves_every_unrelated_byte() -> None:
    representation = IniRepresentation(
        "service.conf", "service_auth", "password", "username",
    )
    configured = location(representation)
    before = (
        b"# retained comment\n[service_auth]\nusername = admin\n"
        b"password = Synthetic-Admin-4A\nregion = DFW\n\n"
        b"[database]\npassword = unrelated-db-password\n"
    )
    original = secret("consumer", {"service.conf": before, "opaque": b"unchanged"})

    client, _owner, _result = mutate(
        configured, original, DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
    )

    expected = before.replace(b"username = admin", b"username = breakglass").replace(
        b"password = Synthetic-Admin-4A",
        b"password = Synthetic-Breakglass-4A",
    )
    assert client.snapshot.get("service.conf") == SecretValue(expected)
    assert client.snapshot.get("opaque") == original.get("opaque")


def test_direct_yaml_mutation_preserves_unrelated_content() -> None:
    representation = YamlRepresentation(
        "clouds.yaml", ("clouds", "admin", "auth", "password"),
        ("clouds", "admin", "auth", "username"),
    )
    configured = location(representation)
    before = (
        b"clouds:\n  admin:\n    auth:\n      username: admin\n"
        b"      password: Synthetic-Admin-4A\n    region_name: DFW\n"
        b"# retained comment\nother: unchanged\n"
    )
    original = secret("consumer", {"clouds.yaml": before})

    client, _owner, _result = mutate(
        configured, original, DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
    )

    mutated = client.snapshot.get("clouds.yaml")
    assert mutated is not None
    assert b"region_name: DFW\n# retained comment\nother: unchanged" in mutated.reveal()
    observed = read_credential(client.snapshot, representation)
    assert observed.username == "breakglass"
    assert observed.password == BREAKGLASS


def test_nested_yaml_document_path_mutation() -> None:
    representation = YamlRepresentation(
        "generated", ("auth", "password"), ("auth", "username"),
        ("clouds.yaml",),
    )
    configured = location(representation)
    before = (
        b"clouds.yaml: |-\n  auth:\n    username: admin\n"
        b"    password: Synthetic-Admin-4A\n  verify: true\n"
        b"outer: unchanged\n"
    )

    client, _owner, _result = mutate(
        configured, secret("consumer", {"generated": before}),
        DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
    )

    raw = client.snapshot.get("generated")
    assert raw is not None
    assert b"outer: unchanged" in raw.reveal()
    observed = read_credential(client.snapshot, representation)
    assert observed.username == "breakglass"
    assert observed.password == BREAKGLASS


def test_already_at_exact_target_is_noop_without_write_or_restart_debt() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": BREAKGLASS.reveal(), "OS_USERNAME": b"breakglass",
    })

    client, owner, result = mutate(
        configured, snapshot, DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
    )

    assert result.disposition is CredentialMutationDisposition.UNCHANGED
    assert not result.changed
    assert result.restart_dependencies == RESTART
    assert result.required_restart_dependencies == ()
    assert client.replace_calls == 0
    assert client.read_calls == 1
    assert owner.assertions == 1


def test_noop_does_not_trust_stale_classified_target_snapshot() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    classified_target = secret("consumer", {
        "OS_PASSWORD": BREAKGLASS.reveal(), "OS_USERNAME": b"breakglass",
    })
    changed_live = replace(
        classified_target,
        resource_version="124",
        data=(
            SecretField("OS_PASSWORD", ADMIN),
            SecretField("OS_USERNAME", SecretValue(b"admin")),
        ),
    )
    client = FakeCredentialSecretClient(changed_live)
    owner = Ownership()

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, owner,
            observed=classified(configured, classified_target),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.BREAKGLASS}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.CONFLICT
    assert client.read_calls == 1
    assert client.replace_calls == 0
    assert owner.assertions == 1


def test_noop_rejects_recreated_secret_even_when_target_still_matches() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    classified_target = secret("consumer", {
        "OS_PASSWORD": BREAKGLASS.reveal(), "OS_USERNAME": b"breakglass",
    })
    client = FakeCredentialSecretClient(replace(
        classified_target, uid="replacement-uid", resource_version="1",
    ))

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(),
            observed=classified(configured, classified_target),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.BREAKGLASS}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.CONFLICT
    assert client.read_calls == 1
    assert client.replace_calls == 0


def test_fixed_admin_location_cannot_be_switched_to_breakglass() -> None:
    configured = location(
        FieldsRepresentation("password"), identity=IdentityBinding.ADMIN,
    )
    snapshot = secret("consumer", {"password": ADMIN.reveal()})
    client = FakeCredentialSecretClient(snapshot)

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.IDENTITY_NOT_ALLOWED
    assert client.replace_calls == 0


def test_canonical_source_is_not_a_generic_propagation_target() -> None:
    configured = CredentialLocation(
        "keystone-admin-source", "keystone-admin", IdentityBinding.ADMIN,
        LocationRole.SOURCE, FieldsRepresentation("password"), (),
    )
    snapshot = secret("keystone-admin", {"password": ADMIN.reveal()})
    client = FakeCredentialSecretClient(snapshot)

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.ADMIN, SecretValue(b"new-admin")),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.SOURCE_LOCATION
    assert client.replace_calls == 0


def test_unknown_observed_credential_is_not_a_mutation_candidate() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": b"unrecognized", "OS_USERNAME": b"admin",
    })

    with pytest.raises(CredentialMutationError) as raised:
        classify_credential_location(configured, snapshot, REFERENCES)

    assert raised.value.kind is CredentialMutationErrorCode.UNSAFE_OBSERVED_STATE


def test_disallowed_recognized_observed_identity_is_not_overwritten() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.BREAKGLASS}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.UNSAFE_OBSERVED_STATE
    assert client.replace_calls == 0


@pytest.mark.parametrize(
    "snapshot",
    [
        secret("consumer", {"OS_USERNAME": b"admin"}),
        secret("consumer", {"OS_USERNAME": b"admin", "OS_PASSWORD": b"bad\n"}),
    ],
)
def test_malformed_or_unresolvable_observation_fails_closed(
    snapshot: SecretSnapshot,
) -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    with pytest.raises(CredentialMutationError) as raised:
        classify_credential_location(configured, snapshot, REFERENCES)
    assert raised.value.kind is CredentialMutationErrorCode.REPRESENTATION_INVALID


def test_resource_version_conflict_is_explicit_and_not_retried() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)
    client.before_replace = lambda fake: setattr(
        fake, "snapshot", replace(fake.snapshot, resource_version="124"),
    )

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.CONFLICT
    assert client.replace_calls == 1
    assert client.read_calls == 0


def test_ownership_is_rechecked_immediately_before_write() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)
    owner = Ownership(fail=True)

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, owner, observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.OWNERSHIP_LOST
    assert owner.assertions == 1
    assert client.replace_calls == 0


@pytest.mark.parametrize(
    ("transport_error", "mutation_error"),
    [
        (
            CredentialSecretClientErrorCode.OUTCOME_AMBIGUOUS,
            CredentialMutationErrorCode.WRITE_AMBIGUOUS,
        ),
        (
            CredentialSecretClientErrorCode.FAILURE,
            CredentialMutationErrorCode.KUBERNETES_FAILURE,
        ),
    ],
)
def test_write_failures_are_typed_without_hidden_retry(
    transport_error: CredentialSecretClientErrorCode,
    mutation_error: CredentialMutationErrorCode,
) -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)
    client.next_replace_error = transport_error

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is mutation_error
    assert client.replace_calls == 1
    assert client.read_calls == 0


def test_post_write_wrong_credential_is_verification_failure() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)

    def tamper(fake: FakeCredentialSecretClient) -> None:
        data = tuple(
            SecretField(item.key, SecretValue(b"unexpected"))
            if item.key == "OS_PASSWORD" else item
            for item in fake.snapshot.data
        )
        fake.snapshot = replace(fake.snapshot, data=data)

    client.after_replace = tamper
    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.POST_WRITE_VERIFICATION_FAILED
    assert client.read_calls == 1


def test_post_write_unresolvable_representation_is_verification_failure() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)
    client.after_replace = lambda fake: setattr(
        fake, "snapshot", replace(
            fake.snapshot,
            data=tuple(item for item in fake.snapshot.data if item.key != "OS_PASSWORD"),
        ),
    )

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.POST_WRITE_VERIFICATION_FAILED


def test_post_write_recreated_secret_is_verification_failure() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    client = FakeCredentialSecretClient(snapshot)
    client.after_replace = lambda fake: setattr(
        fake, "snapshot", replace(fake.snapshot, uid="replacement-uid"),
    )

    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            client, Ownership(), observed=classified(configured, snapshot),
            desired=DesiredCredential(Identity.BREAKGLASS, BREAKGLASS),
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )

    assert raised.value.kind is CredentialMutationErrorCode.POST_WRITE_VERIFICATION_FAILED


def test_result_and_expected_error_paths_do_not_disclose_credentials() -> None:
    configured = location(FieldsRepresentation("OS_PASSWORD", "OS_USERNAME"))
    snapshot = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    desired = DesiredCredential(Identity.BREAKGLASS, BREAKGLASS)
    _client, _owner, result = mutate(configured, snapshot, desired)
    diagnostic = repr(desired) + str(desired) + repr(result) + str(result)
    assert ADMIN.reveal().decode() not in diagnostic
    assert BREAKGLASS.reveal().decode() not in diagnostic

    # Re-observe admin so this second operation reaches the conditional write.
    second = secret("consumer", {
        "OS_PASSWORD": ADMIN.reveal(), "OS_USERNAME": b"admin",
    })
    conflict_client = FakeCredentialSecretClient(second)
    conflict_client.before_replace = lambda fake: setattr(
        fake, "snapshot", replace(fake.snapshot, resource_version="different"),
    )
    with pytest.raises(CredentialMutationError) as raised:
        mutate_credential_location(
            conflict_client, Ownership(), observed=classified(configured, second),
            desired=desired,
            allowed_observed_identities=frozenset({Identity.ADMIN}),
        )
    error_diagnostic = str(raised.value) + repr(raised.value)
    assert ADMIN.reveal().decode() not in error_diagnostic
    assert BREAKGLASS.reveal().decode() not in error_diagnostic


class Serializer:
    def sanitize_for_serialization(self, value: object) -> object:
        return value


class ApiStatusError(Exception):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__("Kubernetes API request failed; response withheld.")


class Api:
    def __init__(self) -> None:
        self.resource: dict[str, object] = {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {
                "namespace": "openstack", "name": "consumer",
                "uid": "consumer-uid", "resourceVersion": "42",
            },
            "data": {
                "OS_USERNAME": base64.b64encode(b"admin").decode(),
                "OS_PASSWORD": base64.b64encode(ADMIN.reveal()).decode(),
                "unrelated": base64.b64encode(b"preserved").decode(),
            },
        }
        self.patch: list[dict[str, object]] | None = None
        self.patch_status: int | None = None

    def read_namespaced_secret(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object:
        assert (namespace, name) == ("openstack", "consumer")
        return self.resource

    def patch_namespaced_secret(
        self, name: str, namespace: str, body: list[dict[str, object]],
        **kwargs: object,
    ) -> object:
        assert (namespace, name) == ("openstack", "consumer")
        assert kwargs["_content_type"] == "application/json-patch+json"
        self.patch = body
        if self.patch_status is not None:
            raise ApiStatusError(self.patch_status)
        return {}


def test_kubernetes_patch_is_uid_resource_version_conditional_and_narrow() -> None:
    api = Api()
    client = KubernetesApiCredentialSecretClient(api, Serializer())
    observed = client.read("openstack", "consumer")
    replacements = (
        SecretField("OS_USERNAME", SecretValue(b"breakglass")),
        SecretField("OS_PASSWORD", BREAKGLASS),
    )

    client.conditional_replace(observed, replacements)

    assert api.patch is not None
    assert api.patch[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": "consumer-uid"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "42"},
    ]
    paths = {str(item["path"]) for item in api.patch[2:]}
    assert paths == {"/data/OS_USERNAME", "/data/OS_PASSWORD"}
    assert "/data/unrelated" not in paths


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (409, CredentialSecretClientErrorCode.CONDITIONAL_REJECTED),
        (412, CredentialSecretClientErrorCode.CONDITIONAL_REJECTED),
        (422, CredentialSecretClientErrorCode.FAILURE),
    ],
)
def test_kubernetes_patch_does_not_treat_every_422_as_conflict(
    status: int, expected: CredentialSecretClientErrorCode,
) -> None:
    api = Api()
    api.patch_status = status
    client = KubernetesApiCredentialSecretClient(api, Serializer())
    observed = client.read("openstack", "consumer")

    with pytest.raises(CredentialSecretClientError) as raised:
        client.conditional_replace(observed, (
            SecretField("OS_PASSWORD", BREAKGLASS),
        ))

    assert raised.value.kind is expected
