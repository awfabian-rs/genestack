"""Pure propagation-wave intent planning and fresh-state reconciliation.

This module never mutates a propagated credential Secret and never executes a
restart.  Its one state-writing helper persists only immutable wave intent via
the existing ownership and transaction-state boundaries.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum

from .discovery import classify
from .errors import RepresentationError, SafeError
from .model import (
    ConfigurationDigest, CredentialContract, CredentialGeneration,
    CredentialLocation, CredentialState, FieldsRepresentation, Identity,
    IdentityBinding, IniRepresentation, LocationRole, PersistentState,
    PropagationLocationIntent, PropagationSecretGroupIntent, PropagationState,
    PropagationWave, PropagationWaveIntent, ReferenceCredentials,
    RotationTransaction, SecretInventory, SecretSnapshot, WorkloadRef,
)
from .prepare_b import OwnershipGuard
from .propagation import DesiredCredential, credential_matches_desired
from .representations import read_credential
from .state_store import PersistedState, StateStore


class PropagationWaveErrorCode(Enum):
    NAMESPACE_MISMATCH = "propagation_wave_namespace_mismatch"
    TARGET_GENERATION_MISMATCH = "propagation_wave_target_generation_mismatch"
    NO_APPLICABLE_LOCATIONS = "propagation_wave_no_applicable_locations"
    INVENTORY_INVALID = "propagation_wave_inventory_invalid"
    SECRET_MISSING = "propagation_wave_secret_missing"
    REPRESENTATION_UNPARSEABLE = "propagation_wave_representation_unparseable"
    CREDENTIAL_UNKNOWN = "propagation_wave_credential_unknown"
    LEGACY_PROGRESS_WITHOUT_INTENT = "propagation_wave_progress_without_intent"
    IMMUTABLE_INTENT_CONFLICT = "propagation_wave_immutable_intent_conflict"
    TRANSACTION_MISSING = "propagation_wave_transaction_missing"
    TRANSACTION_GENERATION_MISMATCH = (
        "propagation_wave_transaction_generation_mismatch"
    )
    OWNERSHIP_LOST = "propagation_wave_ownership_lost"


_ERROR_MESSAGES: dict[PropagationWaveErrorCode, str] = {
    PropagationWaveErrorCode.NAMESPACE_MISMATCH:
        "The credential contract and observed inventory namespaces differ.",
    PropagationWaveErrorCode.TARGET_GENERATION_MISMATCH:
        "The requested target credential does not match its generation reference.",
    PropagationWaveErrorCode.NO_APPLICABLE_LOCATIONS:
        "The requested propagation target has no applicable propagated locations.",
    PropagationWaveErrorCode.INVENTORY_INVALID:
        "The observed Secret inventory cannot identify each object unambiguously.",
    PropagationWaveErrorCode.SECRET_MISSING:
        "A required propagation Secret is absent from observed state.",
    PropagationWaveErrorCode.REPRESENTATION_UNPARSEABLE:
        "A propagated credential representation is not parseable; content withheld.",
    PropagationWaveErrorCode.CREDENTIAL_UNKNOWN:
        "A propagated credential has an unknown or unexplained state.",
    PropagationWaveErrorCode.LEGACY_PROGRESS_WITHOUT_INTENT:
        "Propagation progress exists without durable wave intent and cannot be replaced safely.",
    PropagationWaveErrorCode.IMMUTABLE_INTENT_CONFLICT:
        "Existing durable propagation intent conflicts with the requested operation.",
    PropagationWaveErrorCode.TRANSACTION_MISSING:
        "There is no active transaction in which to persist propagation intent.",
    PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH:
        "Propagation intent does not match the transaction credential generation.",
    PropagationWaveErrorCode.OWNERSHIP_LOST:
        "Current rotation execution ownership was not established before persisting intent.",
}


class PropagationWaveError(SafeError):
    """Stable credential-free planning or intent-persistence failure."""

    def __init__(self, kind: PropagationWaveErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


@dataclass(frozen=True)
class CandidatePropagationLocation:
    location: CredentialLocation
    expected_identity: Identity
    expected_target: bool


@dataclass(frozen=True)
class CandidatePropagationSecretGroup:
    namespace: str
    secret_name: str
    observed_uid: str
    observed_resource_version: str
    locations: tuple[CandidatePropagationLocation, ...]


@dataclass(frozen=True)
class CandidatePropagationWave:
    target_identity: Identity
    target_generation: CredentialGeneration
    contract_digest: ConfigurationDigest
    secret_groups: tuple[CandidatePropagationSecretGroup, ...]

    def durable_intent(self) -> PropagationWaveIntent:
        return PropagationWaveIntent(
            target_identity=self.target_identity,
            target_generation=self.target_generation,
            contract_digest=self.contract_digest,
            secret_groups=tuple(
                PropagationSecretGroupIntent(
                    namespace=group.namespace,
                    secret_name=group.secret_name,
                    observed_uid=group.observed_uid,
                    observed_resource_version=group.observed_resource_version,
                    locations=tuple(
                        PropagationLocationIntent(
                            location_id=item.location.name,
                            expected_identity=item.expected_identity,
                            expected_target=item.expected_target,
                            potential_restart_dependencies=(
                                _canonical_restart_dependencies(
                                    item.location.restart,
                                )
                            ),
                        )
                        for item in group.locations
                    ),
                )
                for group in self.secret_groups
            ),
        )


def _canonical_restart_dependencies(
    dependencies: tuple[WorkloadRef, ...],
) -> tuple[WorkloadRef, ...]:
    return tuple(sorted(dependencies, key=lambda item: item.label))


class LocationReconciliationDisposition(Enum):
    CONFIRMED_CONVERGED = "confirmed_converged"
    ALREADY_CONVERGED = "already_converged"
    REQUIRES_MUTATION = "requires_mutation"
    RECORDED_COMPLETE_NOT_CONVERGED = "recorded_complete_not_converged"
    CURRENT_STATE_CONTRADICTS_INTENT = "current_state_contradicts_intent"
    SECRET_MISSING = "secret_missing"
    SECRET_REPLACED = "secret_replaced"
    REPRESENTATION_UNPARSEABLE = "representation_unparseable"
    CREDENTIAL_UNKNOWN = "credential_unknown"


_SAFE_DISPOSITIONS = frozenset({
    LocationReconciliationDisposition.CONFIRMED_CONVERGED,
    LocationReconciliationDisposition.ALREADY_CONVERGED,
    LocationReconciliationDisposition.REQUIRES_MUTATION,
})


@dataclass(frozen=True)
class ReconciledPropagationLocation:
    location_id: str
    observed_identity: Identity | None
    disposition: LocationReconciliationDisposition
    potential_restart_dependencies: tuple[WorkloadRef, ...]

    @property
    def safe_to_continue(self) -> bool:
        return self.disposition in _SAFE_DISPOSITIONS


@dataclass(frozen=True)
class ReconciledPropagationSecretGroup:
    namespace: str
    secret_name: str
    locations: tuple[ReconciledPropagationLocation, ...]


class WaveReconciliationStatus(Enum):
    SAFE = "safe"
    CONTRACT_DRIFT = "contract_drift"
    INTENT_MISMATCH = "intent_mismatch"
    UNSAFE_OBSERVED_STATE = "unsafe_observed_state"


@dataclass(frozen=True)
class PropagationWaveReconciliation:
    intent: PropagationWaveIntent
    status: WaveReconciliationStatus
    secret_groups: tuple[ReconciledPropagationSecretGroup, ...]

    @property
    def safe_to_continue(self) -> bool:
        return self.status is WaveReconciliationStatus.SAFE

    @property
    def requires_mutation(self) -> tuple[ReconciledPropagationLocation, ...]:
        return tuple(
            location
            for group in self.secret_groups
            for location in group.locations
            if location.disposition is LocationReconciliationDisposition.REQUIRES_MUTATION
        )


@dataclass(frozen=True)
class PropagationWavePlanningResult:
    wave: PropagationWave
    reconciliation: PropagationWaveReconciliation
    intent_created: bool


def _representation_document(location: CredentialLocation) -> dict[str, object]:
    representation = location.representation
    if isinstance(representation, FieldsRepresentation):
        return {
            "type": "fields", "password": representation.password,
            "username": representation.username,
        }
    if isinstance(representation, IniRepresentation):
        return {
            "type": "ini", "key": representation.key,
            "section": representation.section, "password": representation.password,
            "username": representation.username,
        }
    return {
        "type": "yaml", "key": representation.key,
        "password_path": list(representation.password_path),
        "username_path": (
            None if representation.username_path is None
            else list(representation.username_path)
        ),
        "document_path": (
            None if representation.document_path is None
            else list(representation.document_path)
        ),
    }


def propagation_contract_digest(contract: CredentialContract) -> ConfigurationDigest:
    """Fingerprint exact validated contract semantics without credential values."""
    document = {
        "namespace": contract.namespace,
        "locations": [
            {
                "name": location.name,
                "secret": location.secret,
                "identity": location.identity.value,
                "role": location.role.value,
                "representation": _representation_document(location),
                "restart": [
                    item.label
                    for item in _canonical_restart_dependencies(location.restart)
                ],
            }
            for location in sorted(contract.locations, key=lambda item: item.name)
        ],
    }
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return ConfigurationDigest(f"sha256:{hashlib.sha256(encoded).hexdigest()}")


def _applicable(location: CredentialLocation, target: Identity) -> bool:
    if location.role is not LocationRole.PROPAGATED:
        return False
    if target is Identity.BREAKGLASS:
        return location.identity is IdentityBinding.ACTIVE
    return location.identity in (IdentityBinding.ACTIVE, IdentityBinding.ADMIN)


def _inventory_by_name(
    contract: CredentialContract, inventory: SecretInventory,
) -> dict[str, SecretSnapshot]:
    if inventory.namespace != contract.namespace:
        raise PropagationWaveError(PropagationWaveErrorCode.NAMESPACE_MISMATCH)
    result: dict[str, SecretSnapshot] = {}
    for secret in inventory.secrets:
        if secret.namespace != inventory.namespace or secret.name in result:
            raise PropagationWaveError(PropagationWaveErrorCode.INVENTORY_INVALID)
        result[secret.name] = secret
    return result


def _classify_observed(
    location: CredentialLocation, secret: SecretSnapshot,
    references: ReferenceCredentials, desired: DesiredCredential,
) -> tuple[Identity, bool]:
    try:
        observed = read_credential(secret, location.representation)
    except RepresentationError:
        raise PropagationWaveError(
            PropagationWaveErrorCode.REPRESENTATION_UNPARSEABLE,
        ) from None
    if credential_matches_desired(location, observed, desired):
        return desired.identity, True
    state = classify(location, observed, references)
    if state is CredentialState.MATCHES_ADMIN_REFERENCE:
        return Identity.ADMIN, False
    if state is CredentialState.MATCHES_BREAKGLASS_REFERENCE:
        return Identity.BREAKGLASS, False
    raise PropagationWaveError(PropagationWaveErrorCode.CREDENTIAL_UNKNOWN)


def build_candidate_propagation_wave(
    contract: CredentialContract, inventory: SecretInventory,
    references: ReferenceCredentials, desired: DesiredCredential,
    target_generation: CredentialGeneration,
) -> CandidatePropagationWave:
    """Plan the complete applicable contract set without state or Secret writes."""
    if CredentialGeneration.from_secret(desired.password) != target_generation:
        raise PropagationWaveError(PropagationWaveErrorCode.TARGET_GENERATION_MISMATCH)
    secrets = _inventory_by_name(contract, inventory)
    applicable = tuple(
        sorted(
            (item for item in contract.locations if _applicable(item, desired.identity)),
            key=lambda item: item.name,
        )
    )
    if not applicable:
        raise PropagationWaveError(PropagationWaveErrorCode.NO_APPLICABLE_LOCATIONS)

    by_secret: dict[tuple[str, str], list[CandidatePropagationLocation]] = {}
    snapshots: dict[tuple[str, str], SecretSnapshot] = {}
    for location in applicable:
        secret = secrets.get(location.secret)
        if secret is None:
            raise PropagationWaveError(PropagationWaveErrorCode.SECRET_MISSING)
        expected_identity, expected_target = _classify_observed(
            location, secret, references, desired,
        )
        key = (contract.namespace, location.secret)
        snapshots[key] = secret
        by_secret.setdefault(key, []).append(CandidatePropagationLocation(
            location=location,
            expected_identity=expected_identity,
            expected_target=expected_target,
        ))
    groups = tuple(
        CandidatePropagationSecretGroup(
            namespace=key[0], secret_name=key[1],
            observed_uid=snapshots[key].uid,
            observed_resource_version=snapshots[key].resource_version,
            locations=tuple(sorted(by_secret[key], key=lambda item: item.location.name)),
        )
        for key in sorted(by_secret)
    )
    return CandidatePropagationWave(
        target_identity=desired.identity,
        target_generation=target_generation,
        contract_digest=propagation_contract_digest(contract),
        secret_groups=groups,
    )


def _intent_membership(
    intent: PropagationWaveIntent,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    return tuple(
        (
            group.namespace, group.secret_name,
            tuple(location.location_id for location in group.locations),
        )
        for group in intent.secret_groups
    )


def _contract_membership(
    contract: CredentialContract, target: Identity,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for location in contract.locations:
        if _applicable(location, target):
            grouped.setdefault((contract.namespace, location.secret), []).append(location.name)
    return tuple(
        (key[0], key[1], tuple(sorted(grouped[key]))) for key in sorted(grouped)
    )


def _failed_reconciliation(
    intent: PropagationWaveIntent, status: WaveReconciliationStatus,
) -> PropagationWaveReconciliation:
    return PropagationWaveReconciliation(intent, status, ())


def reconcile_propagation_wave(
    contract: CredentialContract, inventory: SecretInventory,
    references: ReferenceCredentials, desired: DesiredCredential,
    wave: PropagationWave,
) -> PropagationWaveReconciliation:
    """Reconcile immutable intent and progress hints against fresh Secret reality."""
    intent = wave.intent
    if intent is None:
        raise PropagationWaveError(PropagationWaveErrorCode.IMMUTABLE_INTENT_CONFLICT)
    requested_generation = CredentialGeneration.from_secret(desired.password)
    if (
        intent.target_identity is not desired.identity
        or intent.target_generation != requested_generation
    ):
        return _failed_reconciliation(intent, WaveReconciliationStatus.INTENT_MISMATCH)
    if (
        intent.contract_digest != propagation_contract_digest(contract)
        or _intent_membership(intent) != _contract_membership(contract, desired.identity)
    ):
        return _failed_reconciliation(intent, WaveReconciliationStatus.CONTRACT_DRIFT)
    if not set(wave.applied_location_ids) <= {
        location.location_id
        for group in intent.secret_groups
        for location in group.locations
    }:
        return _failed_reconciliation(intent, WaveReconciliationStatus.INTENT_MISMATCH)

    try:
        secrets = _inventory_by_name(contract, inventory)
    except PropagationWaveError:
        return _failed_reconciliation(
            intent, WaveReconciliationStatus.UNSAFE_OBSERVED_STATE,
        )
    applied = frozenset(wave.applied_location_ids)
    contract_locations = {item.name: item for item in contract.locations}
    groups: list[ReconciledPropagationSecretGroup] = []
    unsafe = False
    for group in intent.secret_groups:
        secret = secrets.get(group.secret_name)
        reconciled: list[ReconciledPropagationLocation] = []
        for location_intent in group.locations:
            location = contract_locations[location_intent.location_id]
            observed_identity: Identity | None = None
            if secret is None:
                disposition = LocationReconciliationDisposition.SECRET_MISSING
            elif secret.uid != group.observed_uid:
                disposition = LocationReconciliationDisposition.SECRET_REPLACED
            else:
                try:
                    observed_identity, is_target = _classify_observed(
                        location, secret, references, desired,
                    )
                except PropagationWaveError as error:
                    if error.kind is PropagationWaveErrorCode.REPRESENTATION_UNPARSEABLE:
                        disposition = (
                            LocationReconciliationDisposition.REPRESENTATION_UNPARSEABLE
                        )
                    else:
                        disposition = LocationReconciliationDisposition.CREDENTIAL_UNKNOWN
                else:
                    recorded_complete = location.name in applied
                    if is_target:
                        disposition = (
                            LocationReconciliationDisposition.CONFIRMED_CONVERGED
                            if recorded_complete
                            else LocationReconciliationDisposition.ALREADY_CONVERGED
                        )
                    elif recorded_complete:
                        disposition = (
                            LocationReconciliationDisposition.RECORDED_COMPLETE_NOT_CONVERGED
                        )
                    elif (
                        location_intent.expected_target
                        or observed_identity is not location_intent.expected_identity
                    ):
                        disposition = (
                            LocationReconciliationDisposition.CURRENT_STATE_CONTRADICTS_INTENT
                        )
                    else:
                        disposition = LocationReconciliationDisposition.REQUIRES_MUTATION
            item = ReconciledPropagationLocation(
                location_id=location_intent.location_id,
                observed_identity=observed_identity,
                disposition=disposition,
                potential_restart_dependencies=(
                    location_intent.potential_restart_dependencies
                ),
            )
            unsafe = unsafe or not item.safe_to_continue
            reconciled.append(item)
        groups.append(ReconciledPropagationSecretGroup(
            namespace=group.namespace,
            secret_name=group.secret_name,
            locations=tuple(reconciled),
        ))
    return PropagationWaveReconciliation(
        intent=intent,
        status=(
            WaveReconciliationStatus.UNSAFE_OBSERVED_STATE
            if unsafe else WaveReconciliationStatus.SAFE
        ),
        secret_groups=tuple(groups),
    )


def plan_or_reconcile_propagation_wave(
    contract: CredentialContract, inventory: SecretInventory,
    references: ReferenceCredentials, desired: DesiredCredential,
    target_generation: CredentialGeneration, existing_wave: PropagationWave,
) -> PropagationWavePlanningResult:
    """Create missing intent once, otherwise retain and reconcile it exactly."""
    if CredentialGeneration.from_secret(desired.password) != target_generation:
        raise PropagationWaveError(
            PropagationWaveErrorCode.TARGET_GENERATION_MISMATCH,
        )
    if existing_wave.intent is None:
        if existing_wave.applied_location_ids or existing_wave.runtime_actions:
            raise PropagationWaveError(
                PropagationWaveErrorCode.LEGACY_PROGRESS_WITHOUT_INTENT,
            )
        candidate = build_candidate_propagation_wave(
            contract, inventory, references, desired, target_generation,
        )
        wave = replace(existing_wave, intent=candidate.durable_intent())
        created = True
    else:
        wave = existing_wave
        created = False
    reconciliation = reconcile_propagation_wave(
        contract, inventory, references, desired, wave,
    )
    return PropagationWavePlanningResult(wave, reconciliation, created)


def _transaction_wave(
    transaction: RotationTransaction, target: Identity,
) -> PropagationWave:
    return (
        transaction.propagation.to_b
        if target is Identity.BREAKGLASS
        else transaction.propagation.to_a
    )


def _replace_transaction_wave(
    transaction: RotationTransaction, target: Identity, wave: PropagationWave,
) -> RotationTransaction:
    propagation: PropagationState
    if target is Identity.BREAKGLASS:
        propagation = replace(transaction.propagation, to_b=wave)
    else:
        propagation = replace(transaction.propagation, to_a=wave)
    return replace(transaction, propagation=propagation)


def persist_propagation_wave_intent(
    store: StateStore, ownership: OwnershipGuard, persisted: PersistedState,
    planned: PropagationWavePlanningResult, *, recorded_at: datetime,
) -> PersistedState:
    """Persist a newly planned wave through the existing fenced state record."""
    transaction = persisted.state.current_transaction
    if transaction is None:
        raise PropagationWaveError(PropagationWaveErrorCode.TRANSACTION_MISSING)
    intent = planned.wave.intent
    if intent is None:
        raise PropagationWaveError(PropagationWaveErrorCode.IMMUTABLE_INTENT_CONFLICT)
    transaction_generation = (
        transaction.new_b_sha256
        if intent.target_identity is Identity.BREAKGLASS
        else transaction.new_a_sha256
    )
    if (
        transaction_generation is None
        or transaction_generation != intent.target_generation
    ):
        raise PropagationWaveError(
            PropagationWaveErrorCode.TRANSACTION_GENERATION_MISMATCH,
        )
    current = _transaction_wave(transaction, intent.target_identity)
    if current.intent is not None:
        if current.intent != intent:
            raise PropagationWaveError(
                PropagationWaveErrorCode.IMMUTABLE_INTENT_CONFLICT,
            )
        return persisted
    if current.applied_location_ids or current.runtime_actions:
        raise PropagationWaveError(
            PropagationWaveErrorCode.LEGACY_PROGRESS_WITHOUT_INTENT,
        )
    try:
        ownership.assert_owned()
    except SafeError:
        raise PropagationWaveError(PropagationWaveErrorCode.OWNERSHIP_LOST) from None
    updated_transaction = replace(
        _replace_transaction_wave(transaction, intent.target_identity, planned.wave),
        updated_at=recorded_at,
    )
    state: PersistentState = replace(
        persisted.state, current_transaction=updated_transaction,
    )
    return store.update(persisted.revision, state)
