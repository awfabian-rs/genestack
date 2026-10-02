"""Strict JSON boundary for durable transaction state schema version 2.

The projection below is deliberately explicit. Persistent state contains no
credential values and must never be serialized with a generic dataclass walker.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import TypeVar
from uuid import UUID

from .errors import ReadError
from .model import (
    STATE_SCHEMA_VERSION, CompletedOutcome, CompletedRequest, ConfigurationDigest,
    CredentialGeneration, CredentialMutationIntent, CredentialMutationStep,
    EnvironmentIdentity, ExecutionIdentity, IntentEffectState, KubernetesMutationTarget,
    LockoutChangeState, LockoutState, PasswordSafeState, PersistentState, PodIdentity,
    PropagationState, PropagationWave, ResolvedKeystoneIdentities, RotationPhase,
    RotationTransaction, RuntimeActionProgress, RuntimeActionState, SafeErrorInfo,
    TransactionStatus, VerificationResult, VerificationStatus,
)
from .validation import is_identifier, is_object_name, nonempty_string, object_list, object_mapping

MAX_STATE_BYTES = 1024 * 1024
MAX_COMPLETED_REQUESTS = 128
MAX_VERIFICATION_RESULTS = 32
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_EnumType = TypeVar("_EnumType", bound=Enum)
_B_GENERATION_STEPS = frozenset(
    {
        CredentialMutationStep.STAGE_B_PASSWORDSAFE,
        CredentialMutationStep.RESET_B_KEYSTONE,
        CredentialMutationStep.PROPAGATE_TO_B,
    }
)
_A_GENERATION_STEPS = frozenset(
    {
        CredentialMutationStep.STAGE_A_BREEDER,
        CredentialMutationStep.RESET_A_KEYSTONE,
        CredentialMutationStep.UPDATE_A_PASSWORDSAFE,
        CredentialMutationStep.PROPAGATE_TO_A,
    }
)
_PROPAGATION_STEPS = frozenset(
    {
        CredentialMutationStep.PROPAGATE_TO_B,
        CredentialMutationStep.PROPAGATE_TO_A,
    }
)
_KUBERNETES_STEPS = _PROPAGATION_STEPS | {CredentialMutationStep.STAGE_A_BREEDER}


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReadError("duplicate_state_field", "Persistent state contains a duplicate object field.")
        result[key] = value
    return result


def _fields(value: object, required: set[str]) -> dict[str, object]:
    result = object_mapping(value)
    actual = set(result)
    if not required <= actual:
        raise ReadError("missing_state_field", "Persistent state is missing a required field.")
    if actual - required:
        raise ReadError("unknown_state_field", "Persistent state contains an unsupported field.")
    return result


def _identifier(value: object) -> str:
    result = nonempty_string(value)
    if not is_identifier(result):
        raise ReadError("invalid_state_identifier", "Persistent state contains an invalid identifier.")
    return result


def _object_name(value: object) -> str:
    result = nonempty_string(value)
    if not is_object_name(result):
        raise ReadError("invalid_state_object_name", "Persistent state contains an invalid Kubernetes object name.")
    return result


def _optional_string(value: object) -> str | None:
    return None if value is None else nonempty_string(value)


def _integer(value: object, *, positive: bool) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < (1 if positive else 0):
        raise ReadError("invalid_state_integer", "Persistent state contains an invalid integer.")
    return value


def _optional_integer(value: object, *, positive: bool) -> int | None:
    return None if value is None else _integer(value, positive=positive)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ReadError("invalid_state_boolean", "Persistent state contains an invalid boolean.")
    return value


def _optional_boolean(value: object) -> bool | None:
    return None if value is None else _boolean(value)


def _uuid(value: object) -> UUID:
    text = nonempty_string(value)
    try:
        result = UUID(text)
    except (ValueError, AttributeError):
        raise ReadError("invalid_state_uuid", "Persistent state contains an invalid UUID.") from None
    if str(result) != text:
        raise ReadError("invalid_state_uuid", "Persistent state UUIDs must use canonical lowercase form.")
    return result


def _timestamp(value: object) -> datetime:
    text = nonempty_string(value)
    if _TIMESTAMP.fullmatch(text) is None:
        raise ReadError("invalid_state_timestamp", "Persistent state contains an invalid UTC timestamp.")
    try:
        return datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError:
        raise ReadError("invalid_state_timestamp", "Persistent state contains an invalid UTC timestamp.") from None


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError("Persistent state timestamps must be timezone-aware UTC values.")
    return value.astimezone(timezone.utc).isoformat(timespec="auto").replace("+00:00", "Z")


def _enum(value: object, enum_type: type[_EnumType]) -> _EnumType:
    text = nonempty_string(value)
    try:
        return enum_type(text)
    except ValueError:
        raise ReadError("invalid_state_enum", "Persistent state contains an unsupported enum value.") from None


def _generation(value: object) -> CredentialGeneration:
    try:
        return CredentialGeneration(nonempty_string(value))
    except ValueError:
        raise ReadError("invalid_credential_generation", "Credential generation must be sha256 plus 64 lowercase hexadecimal characters.") from None


def _optional_generation(value: object) -> CredentialGeneration | None:
    return None if value is None else _generation(value)


def _configuration_digest(value: object) -> ConfigurationDigest:
    try:
        return ConfigurationDigest(nonempty_string(value))
    except ValueError:
        raise ReadError("invalid_configuration_digest", "Configuration digest must be sha256 plus 64 lowercase hexadecimal characters.") from None


def _identifiers(value: object) -> tuple[str, ...]:
    result = tuple(_identifier(item) for item in object_list(value))
    if len(set(result)) != len(result):
        raise ReadError("duplicate_state_identifier", "Persistent state contains a duplicate identifier.")
    return result


def _environment(value: object) -> EnvironmentIdentity:
    data = _fields(value, {"environment_id", "cluster_id"})
    return EnvironmentIdentity(_identifier(data["environment_id"]), _identifier(data["cluster_id"]))


def _pod(value: object) -> PodIdentity:
    data = _fields(value, {"namespace", "name", "uid"})
    return PodIdentity(_object_name(data["namespace"]), _object_name(data["name"]), nonempty_string(data["uid"]))


def _execution(value: object) -> ExecutionIdentity:
    data = _fields(value, {"execution_id", "pod"})
    pod_value = data["pod"]
    return ExecutionIdentity(_uuid(data["execution_id"]), None if pod_value is None else _pod(pod_value))


def _keystone(value: object) -> ResolvedKeystoneIdentities:
    names = {
        "admin_user_id", "breakglass_user_id", "user_domain_id", "project_id",
        "project_domain_id", "role_id",
    }
    data = _fields(value, names)
    result = ResolvedKeystoneIdentities(
        admin_user_id=_identifier(data["admin_user_id"]),
        breakglass_user_id=_identifier(data["breakglass_user_id"]),
        user_domain_id=_identifier(data["user_domain_id"]),
        project_id=_identifier(data["project_id"]),
        project_domain_id=_identifier(data["project_domain_id"]),
        role_id=_identifier(data["role_id"]),
    )
    if result.admin_user_id == result.breakglass_user_id:
        raise ReadError("invalid_keystone_identity", "Admin and breakglass must resolve to different user IDs.")
    return result


def _last_error(value: object) -> SafeErrorInfo:
    data = _fields(value, {"code", "recorded_at"})
    return SafeErrorInfo(_identifier(data["code"]), _timestamp(data["recorded_at"]))


def _passwordsafe(value: object) -> PasswordSafeState:
    names = {
        "configured_a_record_id", "configured_b_record_id", "observed_a_record_id",
        "observed_b_record_id", "original_a_version", "observed_a_version", "observed_b_version",
    }
    data = _fields(value, names)
    result = PasswordSafeState(
        configured_a_record_id=_integer(data["configured_a_record_id"], positive=True),
        configured_b_record_id=_integer(data["configured_b_record_id"], positive=True),
        observed_a_record_id=_optional_integer(data["observed_a_record_id"], positive=True),
        observed_b_record_id=_optional_integer(data["observed_b_record_id"], positive=True),
        original_a_version=_optional_integer(data["original_a_version"], positive=False),
        observed_a_version=_optional_integer(data["observed_a_version"], positive=False),
        observed_b_version=_optional_integer(data["observed_b_version"], positive=False),
    )
    if result.configured_a_record_id == result.configured_b_record_id:
        raise ReadError("invalid_passwordsafe_state", "Admin and breakglass PasswordSafe records must differ.")
    return result


def _mutation_target(value: object) -> KubernetesMutationTarget:
    data = _fields(value, {"namespace", "name", "uid", "observed_resource_version"})
    return KubernetesMutationTarget(
        namespace=_object_name(data["namespace"]), name=_object_name(data["name"]),
        uid=nonempty_string(data["uid"]),
        observed_resource_version=nonempty_string(data["observed_resource_version"]),
    )


def _mutation_intent(value: object) -> CredentialMutationIntent:
    names = {
        "step", "target", "affected_location_ids", "intended_generation",
        "effect_state", "effect_observed_at", "resulting_resource_version",
    }
    data = _fields(value, names)
    target_value = data["target"]
    observed_at_value = data["effect_observed_at"]
    result = CredentialMutationIntent(
        step=_enum(data["step"], CredentialMutationStep),
        target=None if target_value is None else _mutation_target(target_value),
        affected_location_ids=_identifiers(data["affected_location_ids"]),
        intended_generation=_generation(data["intended_generation"]),
        effect_state=_enum(data["effect_state"], IntentEffectState),
        effect_observed_at=None if observed_at_value is None else _timestamp(observed_at_value),
        resulting_resource_version=_optional_string(data["resulting_resource_version"]),
    )
    if result.step in _KUBERNETES_STEPS and result.target is None:
        raise ReadError("invalid_mutation_intent", "This mutation step requires a Kubernetes target.")
    if result.step not in _KUBERNETES_STEPS and result.target is not None:
        raise ReadError("invalid_mutation_intent", "This mutation step cannot have a Kubernetes target.")
    if result.step in _PROPAGATION_STEPS and not result.affected_location_ids:
        raise ReadError("invalid_mutation_intent", "A propagation step requires affected credential locations.")
    if result.step not in _PROPAGATION_STEPS and result.affected_location_ids:
        raise ReadError("invalid_mutation_intent", "Only a propagation step can have affected credential locations.")
    if result.effect_state is IntentEffectState.UNKNOWN and (
        result.effect_observed_at is not None or result.resulting_resource_version is not None
    ):
        raise ReadError("invalid_mutation_intent", "Mutation observation fields do not match the effect state.")
    if result.effect_state is IntentEffectState.OBSERVED and result.effect_observed_at is None:
        raise ReadError("invalid_mutation_intent", "Mutation observation fields do not match the effect state.")
    if result.effect_state is IntentEffectState.OBSERVED and (
        (result.target is None) != (result.resulting_resource_version is None)
    ):
        raise ReadError("invalid_mutation_intent", "Mutation observation fields do not match the target type.")
    return result


def _runtime_action(value: object) -> RuntimeActionProgress:
    data = _fields(value, {"action_id", "state"})
    return RuntimeActionProgress(_identifier(data["action_id"]), _enum(data["state"], RuntimeActionState))


def _wave(value: object) -> PropagationWave:
    data = _fields(value, {"applied_location_ids", "runtime_actions"})
    actions = tuple(_runtime_action(item) for item in object_list(data["runtime_actions"]))
    if len({action.action_id for action in actions}) != len(actions):
        raise ReadError("duplicate_runtime_action", "A propagation wave contains a duplicate runtime action.")
    return PropagationWave(_identifiers(data["applied_location_ids"]), actions)


def _propagation(value: object) -> PropagationState:
    data = _fields(value, {"to_b", "to_a"})
    return PropagationState(_wave(data["to_b"]), _wave(data["to_a"]))


def _lockout(value: object) -> LockoutState:
    data = _fields(value, {
        "initial_ignore_lockout_failure_attempts", "suppression", "restoration",
        "latest_ignore_lockout_failure_attempts", "restore_required",
    })
    return LockoutState(
        initial_ignore_lockout_failure_attempts=_boolean(
            data["initial_ignore_lockout_failure_attempts"]
        ),
        suppression=_enum(data["suppression"], LockoutChangeState),
        restoration=_enum(data["restoration"], LockoutChangeState),
        latest_ignore_lockout_failure_attempts=_optional_boolean(
            data["latest_ignore_lockout_failure_attempts"]
        ),
        restore_required=_boolean(data["restore_required"]),
    )


def _verification(value: object) -> VerificationResult:
    data = _fields(value, {
        "check_id", "phase", "status", "checked_at", "detail_code", "target_uid",
        "credential_generation",
    })
    detail_value = data["detail_code"]
    return VerificationResult(
        check_id=_identifier(data["check_id"]),
        phase=_enum(data["phase"], RotationPhase),
        status=_enum(data["status"], VerificationStatus),
        checked_at=_timestamp(data["checked_at"]),
        detail_code=None if detail_value is None else _identifier(detail_value),
        target_uid=_optional_string(data["target_uid"]),
        credential_generation=_optional_generation(data["credential_generation"]),
    )


def _transaction(value: object) -> RotationTransaction:
    names = {
        "transaction_id", "request_id", "execution", "configuration_digest", "keystone",
        "created_at", "updated_at", "phase", "status", "last_error", "new_a_sha256",
        "new_b_sha256", "passwordsafe", "credential_mutation_intent", "propagation",
        "lockout", "verifications",
    }
    data = _fields(value, names)
    last_error_value = data["last_error"]
    intent_value = data["credential_mutation_intent"]
    verifications = tuple(_verification(item) for item in object_list(data["verifications"]))
    if len(verifications) > MAX_VERIFICATION_RESULTS:
        raise ReadError("too_many_verifications", "Persistent state exceeds the verification-result limit.")
    if len({(item.check_id, item.phase) for item in verifications}) != len(verifications):
        raise ReadError("duplicate_verification", "Persistent state contains duplicate latest verification results.")
    result = RotationTransaction(
        transaction_id=_uuid(data["transaction_id"]),
        request_id=_uuid(data["request_id"]),
        execution=_execution(data["execution"]),
        configuration_digest=_configuration_digest(data["configuration_digest"]),
        keystone=_keystone(data["keystone"]),
        created_at=_timestamp(data["created_at"]),
        updated_at=_timestamp(data["updated_at"]),
        phase=_enum(data["phase"], RotationPhase),
        status=_enum(data["status"], TransactionStatus),
        last_error=None if last_error_value is None else _last_error(last_error_value),
        new_a_sha256=_optional_generation(data["new_a_sha256"]),
        new_b_sha256=_optional_generation(data["new_b_sha256"]),
        passwordsafe=_passwordsafe(data["passwordsafe"]),
        credential_mutation_intent=None if intent_value is None else _mutation_intent(intent_value),
        propagation=_propagation(data["propagation"]),
        lockout=_lockout(data["lockout"]),
        verifications=verifications,
    )
    if result.status is TransactionStatus.COMPLETED:
        raise ReadError("invalid_current_transaction", "The current transaction must be unfinished.")
    if result.status is TransactionStatus.BLOCKED and result.last_error is None:
        raise ReadError("invalid_current_transaction", "A blocked transaction requires safe last-error information.")
    if result.updated_at < result.created_at:
        raise ReadError("invalid_transaction_time", "Transaction update time precedes its creation time.")
    if result.new_a_sha256 is not None and result.new_a_sha256 == result.new_b_sha256:
        raise ReadError("invalid_credential_generations", "Admin and breakglass credential generations must differ.")
    if result.credential_mutation_intent is not None:
        if result.credential_mutation_intent.step in _B_GENERATION_STEPS:
            expected_generation = result.new_b_sha256
        elif result.credential_mutation_intent.step in _A_GENERATION_STEPS:
            expected_generation = result.new_a_sha256
        else:
            raise ReadError("invalid_mutation_intent", "Mutation intent contains an unsupported step.")
        if result.credential_mutation_intent.intended_generation != expected_generation:
            raise ReadError(
                "invalid_mutation_intent",
                "Mutation intent does not identify the transaction's corresponding credential generation.",
            )
    return result


def _completed_request(value: object) -> CompletedRequest:
    data = _fields(value, {"request_id", "transaction_id", "completed_at", "outcome"})
    return CompletedRequest(
        request_id=_uuid(data["request_id"]), transaction_id=_uuid(data["transaction_id"]),
        completed_at=_timestamp(data["completed_at"]),
        outcome=_enum(data["outcome"], CompletedOutcome),
    )


def parse_state_json(raw: str | bytes) -> PersistentState:
    """Parse untrusted state.json into the trusted schema-v2 model."""
    size = len(raw.encode("utf-8")) if isinstance(raw, str) else len(raw)
    if size > MAX_STATE_BYTES:
        raise ReadError("state_too_large", "Persistent state exceeds the input limit.")
    try:
        value: object = json.loads(raw, object_pairs_hook=_json_pairs)
    except ReadError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise ReadError("invalid_state_json", "Persistent state is not valid JSON; input withheld.") from None
    data = _fields(value, {"schema_version", "environment", "current_transaction", "completed_requests"})
    schema_version = data["schema_version"]
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version != STATE_SCHEMA_VERSION:
        raise ReadError("unsupported_state_schema", "Only persistent state schema version 2 is supported.")
    current_value = data["current_transaction"]
    completed = tuple(_completed_request(item) for item in object_list(data["completed_requests"]))
    if len(completed) > MAX_COMPLETED_REQUESTS:
        raise ReadError("too_many_completed_requests", "Persistent state exceeds the completed-request limit.")
    if len({item.request_id for item in completed}) != len(completed):
        raise ReadError("duplicate_completed_request", "Persistent state repeats a completed request ID.")
    if len({item.transaction_id for item in completed}) != len(completed):
        raise ReadError("duplicate_completed_transaction", "Persistent state repeats a completed transaction ID.")
    current = None if current_value is None else _transaction(current_value)
    if current is not None and any(
        item.request_id == current.request_id or item.transaction_id == current.transaction_id
        for item in completed
    ):
        raise ReadError("inconsistent_request_state", "A request cannot be both current and completed.")
    return PersistentState(schema_version, _environment(data["environment"]), current, completed)


def _environment_json(value: EnvironmentIdentity) -> dict[str, object]:
    return {"environment_id": value.environment_id, "cluster_id": value.cluster_id}


def _pod_json(value: PodIdentity) -> dict[str, object]:
    return {"namespace": value.namespace, "name": value.name, "uid": value.uid}


def _execution_json(value: ExecutionIdentity) -> dict[str, object]:
    return {"execution_id": str(value.execution_id), "pod": None if value.pod is None else _pod_json(value.pod)}


def _keystone_json(value: ResolvedKeystoneIdentities) -> dict[str, object]:
    return {
        "admin_user_id": value.admin_user_id,
        "breakglass_user_id": value.breakglass_user_id,
        "user_domain_id": value.user_domain_id,
        "project_id": value.project_id,
        "project_domain_id": value.project_domain_id,
        "role_id": value.role_id,
    }


def _last_error_json(value: SafeErrorInfo) -> dict[str, object]:
    return {"code": value.code, "recorded_at": _timestamp_text(value.recorded_at)}


def _passwordsafe_json(value: PasswordSafeState) -> dict[str, object]:
    return {
        "configured_a_record_id": value.configured_a_record_id,
        "configured_b_record_id": value.configured_b_record_id,
        "observed_a_record_id": value.observed_a_record_id,
        "observed_b_record_id": value.observed_b_record_id,
        "original_a_version": value.original_a_version,
        "observed_a_version": value.observed_a_version,
        "observed_b_version": value.observed_b_version,
    }


def _target_json(value: KubernetesMutationTarget) -> dict[str, object]:
    return {
        "namespace": value.namespace, "name": value.name, "uid": value.uid,
        "observed_resource_version": value.observed_resource_version,
    }


def _intent_json(value: CredentialMutationIntent) -> dict[str, object]:
    return {
        "step": value.step.value,
        "target": None if value.target is None else _target_json(value.target),
        "affected_location_ids": list(value.affected_location_ids),
        "intended_generation": value.intended_generation.value,
        "effect_state": value.effect_state.value,
        "effect_observed_at": None if value.effect_observed_at is None else _timestamp_text(value.effect_observed_at),
        "resulting_resource_version": value.resulting_resource_version,
    }


def _action_json(value: RuntimeActionProgress) -> dict[str, object]:
    return {"action_id": value.action_id, "state": value.state.value}


def _wave_json(value: PropagationWave) -> dict[str, object]:
    return {
        "applied_location_ids": list(value.applied_location_ids),
        "runtime_actions": [_action_json(item) for item in value.runtime_actions],
    }


def _propagation_json(value: PropagationState) -> dict[str, object]:
    return {"to_b": _wave_json(value.to_b), "to_a": _wave_json(value.to_a)}


def _lockout_json(value: LockoutState) -> dict[str, object]:
    return {
        "initial_ignore_lockout_failure_attempts": value.initial_ignore_lockout_failure_attempts,
        "suppression": value.suppression.value,
        "restoration": value.restoration.value,
        "latest_ignore_lockout_failure_attempts": value.latest_ignore_lockout_failure_attempts,
        "restore_required": value.restore_required,
    }


def _verification_json(value: VerificationResult) -> dict[str, object]:
    return {
        "check_id": value.check_id,
        "phase": value.phase.value,
        "status": value.status.value,
        "checked_at": _timestamp_text(value.checked_at),
        "detail_code": value.detail_code,
        "target_uid": value.target_uid,
        "credential_generation": None if value.credential_generation is None else value.credential_generation.value,
    }


def _transaction_json(value: RotationTransaction) -> dict[str, object]:
    return {
        "transaction_id": str(value.transaction_id),
        "request_id": str(value.request_id),
        "execution": _execution_json(value.execution),
        "configuration_digest": value.configuration_digest.value,
        "keystone": _keystone_json(value.keystone),
        "created_at": _timestamp_text(value.created_at),
        "updated_at": _timestamp_text(value.updated_at),
        "phase": value.phase.value,
        "status": value.status.value,
        "last_error": None if value.last_error is None else _last_error_json(value.last_error),
        "new_a_sha256": None if value.new_a_sha256 is None else value.new_a_sha256.value,
        "new_b_sha256": None if value.new_b_sha256 is None else value.new_b_sha256.value,
        "passwordsafe": _passwordsafe_json(value.passwordsafe),
        "credential_mutation_intent": None if value.credential_mutation_intent is None else _intent_json(value.credential_mutation_intent),
        "propagation": _propagation_json(value.propagation),
        "lockout": _lockout_json(value.lockout),
        "verifications": [_verification_json(item) for item in value.verifications],
    }


def _completed_json(value: CompletedRequest) -> dict[str, object]:
    return {
        "request_id": str(value.request_id), "transaction_id": str(value.transaction_id),
        "completed_at": _timestamp_text(value.completed_at), "outcome": value.outcome.value,
    }


def state_document(value: PersistentState) -> dict[str, object]:
    """Return the allow-listed JSON representation without generic serialization."""
    return {
        "schema_version": value.schema_version,
        "environment": _environment_json(value.environment),
        "current_transaction": None if value.current_transaction is None else _transaction_json(value.current_transaction),
        "completed_requests": [_completed_json(item) for item in value.completed_requests],
    }


def serialize_state_json(value: PersistentState) -> str:
    """Validate a typed state and emit deterministic schema-v2 JSON."""
    document = state_document(value)
    encoded = json.dumps(document, indent=2, sort_keys=True, separators=(",", ": "))
    # Typed callers can still manually construct invalid dataclasses. Reuse the
    # untrusted-input validator so invalid state is never emitted for persistence.
    parse_state_json(encoded)
    return encoded + "\n"
