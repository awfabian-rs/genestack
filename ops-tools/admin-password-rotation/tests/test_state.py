from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import cast
from uuid import UUID

import pytest

from admin_password_rotation.errors import ReadError
from admin_password_rotation.model import (
    STATE_SCHEMA_VERSION, CompletedOutcome, CompletedRequest, ConfigurationDigest,
    CredentialGeneration, CredentialMutationIntent, CredentialMutationStep,
    EnvironmentIdentity, ExecutionIdentity, IntentEffectState, KubernetesMutationTarget,
    LockoutChangeState, LockoutState, PasswordSafeState, PersistentState, PodIdentity,
    PropagationState, PropagationWave, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, RuntimeActionProgress, RuntimeActionState, SecretValue,
    TransactionStatus, VerificationResult, VerificationStatus,
)
from admin_password_rotation.state import parse_state_json, serialize_state_json, state_document
from admin_password_rotation.validation import object_list, object_mapping

CREATED = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
UPDATED = datetime(2026, 10, 1, 12, 5, 30, 123456, tzinfo=timezone.utc)
TRANSACTION_ID = UUID("11111111-1111-4111-8111-111111111111")
REQUEST_ID = UUID("22222222-2222-4222-8222-222222222222")
EXECUTION_ID = UUID("33333333-3333-4333-8333-333333333333")
GENERATION_A = CredentialGeneration("sha256:" + "a" * 64)
GENERATION_B = CredentialGeneration("sha256:" + "b" * 64)


def realistic_state() -> PersistentState:
    to_b_actions = (
        RuntimeActionProgress("octavia-api-restart", RuntimeActionState.PENDING),
        RuntimeActionProgress("admin-client", RuntimeActionState.RUNNING),
    )
    to_a_actions = (
        RuntimeActionProgress("admin-client", RuntimeActionState.COMPLETE),
    )
    transaction = RotationTransaction(
        transaction_id=TRANSACTION_ID,
        request_id=REQUEST_ID,
        execution=ExecutionIdentity(EXECUTION_ID, PodIdentity("openstack", "rotation-job-abc", "pod-uid-1")),
        configuration_digest=ConfigurationDigest("sha256:" + "c" * 64),
        keystone=ResolvedKeystoneIdentities(
            admin_user_id="admin-user-id", breakglass_user_id="breakglass-user-id",
            user_domain_id="user-domain-id", project_id="project-id",
            project_domain_id="project-domain-id", role_id="admin-role-id",
        ),
        created_at=CREATED,
        updated_at=UPDATED,
        phase=RotationPhase.SWITCH_TO_B,
        status=TransactionStatus.ACTIVE,
        last_error=None,
        new_a_sha256=GENERATION_A,
        new_b_sha256=GENERATION_B,
        passwordsafe=PasswordSafeState(
            configured_a_record_id=101, configured_b_record_id=202,
            observed_a_record_id=101, observed_b_record_id=202,
            original_a_version=7, observed_a_version=8, observed_b_version=3,
        ),
        credential_mutation_intent=CredentialMutationIntent(
            step=CredentialMutationStep.PROPAGATE_TO_B,
            target=KubernetesMutationTarget("openstack", "octavia-etc", "secret-uid-1", "456"),
            affected_location_ids=("octavia-service-auth-etc",),
            intended_generation=GENERATION_B,
            effect_state=IntentEffectState.UNKNOWN,
            effect_observed_at=None,
            resulting_resource_version=None,
        ),
        propagation=PropagationState(
            to_b=PropagationWave(("barbican-keystone-admin",), to_b_actions),
            to_a=PropagationWave(("keystone-admin",), to_a_actions),
        ),
        lockout=LockoutState(
            initial_ignore_lockout_failure_attempts=False,
            suppression=LockoutChangeState.INTENT_PERSISTED,
            restoration=LockoutChangeState.NOT_INTENDED,
            latest_ignore_lockout_failure_attempts=False,
            restore_required=True,
        ),
        verifications=(VerificationResult(
            check_id="breakglass-auth", phase=RotationPhase.VERIFY_B,
            status=VerificationStatus.SUCCESS, checked_at=UPDATED,
            detail_code="authentication-succeeded", target_uid="secret-uid-1",
            credential_generation=GENERATION_B,
        ),),
    )
    return PersistentState(
        schema_version=STATE_SCHEMA_VERSION,
        environment=EnvironmentIdentity("dfw-dev", "cluster.local"),
        current_transaction=transaction,
        completed_requests=(),
    )


def document() -> dict[str, object]:
    return state_document(realistic_state())


def transaction(document_value: dict[str, object]) -> dict[str, object]:
    return mutable_mapping(document_value["current_transaction"])


def mutable_mapping(value: object) -> dict[str, object]:
    # Keep the original test document mutable after validating its JSON shape.
    object_mapping(value)
    return cast(dict[str, object], value)


def encoded(document_value: dict[str, object]) -> str:
    return json.dumps(document_value)


def test_schema_v2_active_transaction_round_trip_is_deterministic() -> None:
    state = realistic_state()
    serialized = serialize_state_json(state)
    assert parse_state_json(serialized) == state
    assert serialize_state_json(parse_state_json(serialized)) == serialized
    assert '"current_transaction": {' in serialized


def test_no_active_transaction_and_completed_request_round_trip() -> None:
    completed = CompletedRequest(
        request_id=REQUEST_ID, transaction_id=TRANSACTION_ID,
        completed_at=UPDATED, outcome=CompletedOutcome.SUCCEEDED,
    )
    state = PersistentState(
        STATE_SCHEMA_VERSION, EnvironmentIdentity("prod", "cluster.local"), None, (completed,),
    )
    serialized = serialize_state_json(state)
    assert '"current_transaction": null' in serialized
    assert parse_state_json(serialized) == state


def test_credential_generation_hashes_exact_utf8_bytes_and_is_redacted() -> None:
    sentinel = "password"
    generation = CredentialGeneration.from_secret(SecretValue(sentinel.encode("utf-8")))
    assert generation.value == "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    assert sentinel not in str(generation) + repr(generation)


def test_state_contains_intent_before_effect_or_progress() -> None:
    state = realistic_state()
    assert state.current_transaction is not None
    intent = state.current_transaction.credential_mutation_intent
    assert intent is not None and intent.effect_state is IntentEffectState.UNKNOWN
    assert intent.effect_observed_at is None and intent.resulting_resource_version is None
    state = replace(
        state,
        current_transaction=replace(
            state.current_transaction,
            propagation=PropagationState(PropagationWave((), ()), PropagationWave((), ())),
        ),
    )
    assert parse_state_json(serialize_state_json(state)) == state


@pytest.mark.parametrize(("step", "generation", "target", "locations"), [
    (CredentialMutationStep.STAGE_B_PASSWORDSAFE, GENERATION_B, None, ()),
    (CredentialMutationStep.RESET_B_KEYSTONE, GENERATION_B, None, ()),
    (
        CredentialMutationStep.PROPAGATE_TO_B,
        GENERATION_B,
        KubernetesMutationTarget("openstack", "octavia-etc", "secret-uid-1", "456"),
        ("octavia-service-auth-etc",),
    ),
    (
        CredentialMutationStep.STAGE_A_BREEDER,
        GENERATION_A,
        KubernetesMutationTarget("openstack", "keystone-admin", "breeder-uid", "123"),
        (),
    ),
    (CredentialMutationStep.RESET_A_KEYSTONE, GENERATION_A, None, ()),
    (CredentialMutationStep.UPDATE_A_PASSWORDSAFE, GENERATION_A, None, ()),
    (
        CredentialMutationStep.PROPAGATE_TO_A,
        GENERATION_A,
        KubernetesMutationTarget("openstack", "octavia-etc", "secret-uid-1", "456"),
        ("octavia-service-auth-etc",),
    ),
])
def test_effect_specific_intents_round_trip_exact_step(
    step: CredentialMutationStep,
    generation: CredentialGeneration,
    target: KubernetesMutationTarget | None,
    locations: tuple[str, ...],
) -> None:
    state = realistic_state()
    assert state.current_transaction is not None
    intent = CredentialMutationIntent(
        step=step,
        target=target,
        affected_location_ids=locations,
        intended_generation=generation,
        effect_state=IntentEffectState.OBSERVED,
        effect_observed_at=UPDATED,
        resulting_resource_version=None if target is None else "124",
    )
    state = replace(
        state,
        current_transaction=replace(
            state.current_transaction,
            credential_mutation_intent=intent,
        ),
    )
    serialized = serialize_state_json(state)
    parsed = parse_state_json(serialized)
    assert parsed == state
    assert parsed.current_transaction is not None
    assert parsed.current_transaction.credential_mutation_intent is not None
    assert parsed.current_transaction.credential_mutation_intent.step is step
    assert f'"step": "{step.value}"' in serialized


def test_propagation_waves_and_at_least_once_action_states_are_independent() -> None:
    state = parse_state_json(serialize_state_json(realistic_state()))
    assert state.current_transaction is not None
    propagation = state.current_transaction.propagation
    assert propagation.to_b.applied_location_ids == ("barbican-keystone-admin",)
    assert propagation.to_a.applied_location_ids == ("keystone-admin",)
    assert tuple(action.action_id for action in propagation.to_b.runtime_actions) == (
        "octavia-api-restart", "admin-client",
    )
    assert tuple(action.state for action in propagation.to_b.runtime_actions) == (
        RuntimeActionState.PENDING, RuntimeActionState.RUNNING,
    )
    assert propagation.to_a.runtime_actions[0].action_id == "admin-client"
    assert propagation.to_a.runtime_actions[0].state is RuntimeActionState.COMPLETE


def test_runtime_actions_serialize_as_configured_action_ids() -> None:
    # These representative IDs can resolve to rollout_restart and recreate_pod
    # definitions; durable state carries only their stable normalized IDs.
    serialized = serialize_state_json(realistic_state())
    assert '"action_id": "octavia-api-restart"' in serialized
    assert '"action_id": "admin-client"' in serialized
    assert '"workload"' not in serialized


@pytest.mark.parametrize("schema_version", [1, 3, "2", True])
def test_unsupported_schema_version_rejected(schema_version: object) -> None:
    value = document()
    value["schema_version"] = schema_version
    with pytest.raises(ReadError, match="unsupported_state_schema"):
        parse_state_json(encoded(value))


def test_missing_and_unknown_fields_rejected() -> None:
    value = document()
    del transaction(value)["request_id"]
    with pytest.raises(ReadError, match="missing_state_field"):
        parse_state_json(encoded(value))
    value = document()
    transaction(value)["password"] = "SECRET_SENTINEL"
    with pytest.raises(ReadError, match="unknown_state_field") as error:
        parse_state_json(encoded(value))
    assert "SECRET_SENTINEL" not in str(error.value)


@pytest.mark.parametrize(("field", "bad_value", "error_code"), [
    ("transaction_id", "not-a-uuid", "invalid_state_uuid"),
    ("created_at", "2026-10-01 12:00:00", "invalid_state_timestamp"),
    ("configuration_digest", "sha256:short", "invalid_configuration_digest"),
    ("new_a_sha256", "sha256:" + "A" * 64, "invalid_credential_generation"),
    ("new_b_sha256", "sha256:" + "b" * 63, "invalid_credential_generation"),
    ("phase", "UNKNOWN_PHASE", "invalid_state_enum"),
    ("status", "waiting", "invalid_state_enum"),
])
def test_malformed_transaction_values_rejected(field: str, bad_value: object, error_code: str) -> None:
    value = document()
    transaction(value)[field] = bad_value
    with pytest.raises(ReadError, match=error_code):
        parse_state_json(encoded(value))


def test_invalid_runtime_action_state_rejected() -> None:
    value = document()
    propagation = mutable_mapping(transaction(value)["propagation"])
    to_b = mutable_mapping(propagation["to_b"])
    actions = object_list(to_b["runtime_actions"])
    mutable_mapping(actions[0])["state"] = "queued"
    with pytest.raises(ReadError, match="invalid_state_enum"):
        parse_state_json(encoded(value))


def test_invalid_propagation_wave_structure_rejected() -> None:
    value = document()
    propagation = mutable_mapping(transaction(value)["propagation"])
    propagation["to_b"] = {"applied_location_ids": "not-a-list", "runtime_actions": []}
    with pytest.raises(ReadError, match="invalid_list"):
        parse_state_json(encoded(value))


def test_observed_mutation_requires_observation_metadata() -> None:
    value = document()
    intent = mutable_mapping(transaction(value)["credential_mutation_intent"])
    intent["effect_state"] = "effect_observed"
    with pytest.raises(ReadError, match="invalid_mutation_intent"):
        parse_state_json(encoded(value))


@pytest.mark.parametrize(
    ("step", "target", "locations"),
    [
        (
            "stage_b_passwordsafe",
            {
                "namespace": "openstack",
                "name": "example",
                "uid": "uid",
                "observed_resource_version": "1",
            },
            [],
        ),
        ("stage_a_breeder", None, []),
        (
            "propagate_to_b",
            {
                "namespace": "openstack",
                "name": "example",
                "uid": "uid",
                "observed_resource_version": "1",
            },
            [],
        ),
        ("reset_a_keystone", None, ["keystone-admin"]),
    ],
)
def test_incoherent_mutation_intent_shapes_rejected(
    step: str, target: object, locations: list[str],
) -> None:
    value = document()
    intent = mutable_mapping(transaction(value)["credential_mutation_intent"])
    intent["step"] = step
    intent["target"] = target
    intent["affected_location_ids"] = locations
    with pytest.raises(ReadError, match="invalid_mutation_intent"):
        parse_state_json(encoded(value))


def test_mutation_intent_generation_must_match_its_exact_step() -> None:
    value = document()
    intent = mutable_mapping(transaction(value)["credential_mutation_intent"])
    intent["intended_generation"] = GENERATION_A.value
    with pytest.raises(ReadError, match="invalid_mutation_intent"):
        parse_state_json(encoded(value))


def test_duplicate_runtime_action_ids_rejected_within_one_wave() -> None:
    value = document()
    propagation = mutable_mapping(transaction(value)["propagation"])
    to_b = mutable_mapping(propagation["to_b"])
    actions = object_list(to_b["runtime_actions"])
    duplicate = dict(mutable_mapping(actions[0]))
    actions.append(duplicate)
    with pytest.raises(ReadError, match="duplicate_runtime_action"):
        parse_state_json(encoded(value))


def test_lockout_wire_fields_name_the_keystone_option_explicitly() -> None:
    value = document()
    lockout = mutable_mapping(transaction(value)["lockout"])
    assert lockout["initial_ignore_lockout_failure_attempts"] is False
    assert lockout["latest_ignore_lockout_failure_attempts"] is False
    assert "initial_normal_value" not in lockout
    assert "latest_observed_value" not in lockout

    lockout["initial_ignore_lockout_failure_attempts"] = True
    lockout["latest_ignore_lockout_failure_attempts"] = True
    parsed = parse_state_json(encoded(value))
    assert parsed.current_transaction is not None
    assert parsed.current_transaction.lockout.initial_ignore_lockout_failure_attempts is True
    assert parsed.current_transaction.lockout.latest_ignore_lockout_failure_attempts is True


def test_current_transaction_cannot_also_be_completed() -> None:
    value = document()
    value["completed_requests"] = [{
        "request_id": str(REQUEST_ID), "transaction_id": str(TRANSACTION_ID),
        "completed_at": "2026-10-01T12:10:00Z", "outcome": "succeeded",
    }]
    with pytest.raises(ReadError, match="inconsistent_request_state"):
        parse_state_json(encoded(value))


def test_completed_request_records_are_bounded() -> None:
    completed = tuple(
        CompletedRequest(
            request_id=UUID(int=index + 1), transaction_id=UUID(int=index + 1000),
            completed_at=UPDATED, outcome=CompletedOutcome.SUCCEEDED,
        )
        for index in range(129)
    )
    state = PersistentState(
        STATE_SCHEMA_VERSION, EnvironmentIdentity("prod", "cluster.local"), None, completed,
    )
    with pytest.raises(ReadError, match="too_many_completed_requests"):
        serialize_state_json(state)


def test_latest_verification_results_are_bounded() -> None:
    state = realistic_state()
    assert state.current_transaction is not None
    results = tuple(
        VerificationResult(
            check_id=f"probe-{index}", phase=RotationPhase.VERIFY_B,
            status=VerificationStatus.SUCCESS, checked_at=UPDATED,
            detail_code=None, target_uid=None, credential_generation=GENERATION_B,
        )
        for index in range(33)
    )
    state = replace(state, current_transaction=replace(state.current_transaction, verifications=results))
    with pytest.raises(ReadError, match="too_many_verifications"):
        serialize_state_json(state)


def test_secret_values_do_not_appear_in_state_or_validation_errors() -> None:
    sentinel = "DO_NOT_PERSIST_THIS_CREDENTIAL"
    generated = CredentialGeneration.from_secret(SecretValue(sentinel.encode("utf-8")))
    state = realistic_state()
    assert state.current_transaction is not None
    state = replace(state, current_transaction=replace(state.current_transaction, new_a_sha256=generated))
    output = serialize_state_json(state)
    assert sentinel not in output + repr(state) + repr(generated) + str(generated)

    value = document()
    transaction(value)["new_a_sha256"] = sentinel
    with pytest.raises(ReadError) as error:
        parse_state_json(encoded(value))
    assert sentinel not in str(error.value)


def test_non_utf8_generation_input_error_is_value_free() -> None:
    with pytest.raises(ValueError) as error:
        CredentialGeneration.from_secret(SecretValue(b"SECRET_SENTINEL\xff"))
    assert "SECRET_SENTINEL" not in str(error.value)
