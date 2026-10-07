"""Safe structural mutation of one contracted propagated credential location."""
from __future__ import annotations

import base64
import hmac
import json
import math
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Self, cast, runtime_checkable

from .discovery import classify
from .errors import ReadError, RepresentationError, SafeError
from .kubernetes import parse_inventory
from .kubernetes_api import create_kubernetes_api, validate_api_options
from .model import (
    CredentialContract, CredentialGeneration, CredentialLocation, CredentialState,
    FieldsRepresentation, Identity, IdentityBinding, IniRepresentation,
    LocationRole, ObservedCredential, PropagationLocationIntent,
    PropagationSecretGroupIntent, PropagationState, PropagationWave,
    ReferenceCredentials, RotationTransaction, SecretField, SecretSnapshot,
    SecretValue, WorkloadRef,
)
from .prepare_b import OwnershipGuard
from .representations import mutate_credential_fields, read_credential
from .state_store import PersistedState, StateStore
from .wave_digest import (
    contract_membership, intent_membership, propagation_contract_digest,
)


class CredentialMutationErrorCode(Enum):
    SOURCE_LOCATION = "credential_mutation_source_location"
    IDENTITY_NOT_ALLOWED = "credential_mutation_identity_not_allowed"
    UNSAFE_OBSERVED_STATE = "credential_mutation_unsafe_observed_state"
    REPRESENTATION_INVALID = "credential_mutation_representation_invalid"
    OWNERSHIP_LOST = "credential_mutation_ownership_lost"
    CONFLICT = "credential_mutation_conflict"
    WRITE_AMBIGUOUS = "credential_mutation_write_ambiguous"
    KUBERNETES_FAILURE = "credential_mutation_kubernetes_failure"
    POST_WRITE_VERIFICATION_FAILED = "credential_mutation_post_write_verification_failed"


_ERROR_MESSAGES: dict[CredentialMutationErrorCode, str] = {
    CredentialMutationErrorCode.SOURCE_LOCATION:
        "The canonical source is not a propagated credential mutation target.",
    CredentialMutationErrorCode.IDENTITY_NOT_ALLOWED:
        "The requested identity is not allowed by the credential location contract.",
    CredentialMutationErrorCode.UNSAFE_OBSERVED_STATE:
        "The observed credential state is not recognized or permitted for this mutation.",
    CredentialMutationErrorCode.REPRESENTATION_INVALID:
        "The declared credential representation cannot be resolved safely; content withheld.",
    CredentialMutationErrorCode.OWNERSHIP_LOST:
        "Current rotation execution ownership was not established before mutation.",
    CredentialMutationErrorCode.CONFLICT:
        "The Secret changed after observation; rediscover and reconcile before retrying.",
    CredentialMutationErrorCode.WRITE_AMBIGUOUS:
        "The Secret mutation outcome is ambiguous; reobserve before continuing.",
    CredentialMutationErrorCode.KUBERNETES_FAILURE:
        "The Kubernetes credential mutation operation failed; output withheld.",
    CredentialMutationErrorCode.POST_WRITE_VERIFICATION_FAILED:
        "The credential observed after mutation does not match the intended result.",
}


class CredentialMutationError(SafeError):
    """A credential-free, stable mutation failure category."""

    def __init__(self, kind: CredentialMutationErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


@dataclass(frozen=True, repr=False)
class DesiredCredential:
    """Caller-validated authoritative target; construction proves no authority.

    The higher-level transition must establish that ``password`` is the current
    authoritative/reconciled value for ``identity`` before constructing this
    boundary value.  This type's responsibility is redaction and explicit
    identity labeling, not authentication or external-state reconciliation.
    """

    identity: Identity
    password: SecretValue = field(repr=False)

    def __repr__(self) -> str:
        return f"DesiredCredential(identity={self.identity.value!r}, password=<redacted>)"

    def __str__(self) -> str:
        return f"DesiredCredential(identity={self.identity.value!r}, password=<redacted>)"


@dataclass(frozen=True)
class ClassifiedCredentialLocation:
    """A parsed location whose value exactly matched an authoritative reference."""

    location: CredentialLocation
    state: CredentialState
    secret: SecretSnapshot = field(repr=False)

    def __post_init__(self) -> None:
        if self.state not in (
            CredentialState.MATCHES_ADMIN_REFERENCE,
            CredentialState.MATCHES_BREAKGLASS_REFERENCE,
        ):
            raise ValueError("A classified mutation location must have a recognized state.")
        if self.secret.name != self.location.secret:
            raise ValueError("The classified Secret does not match its contract location.")

    @property
    def identity(self) -> Identity:
        if self.state is CredentialState.MATCHES_ADMIN_REFERENCE:
            return Identity.ADMIN
        return Identity.BREAKGLASS


def classify_credential_location(
    location: CredentialLocation, secret: SecretSnapshot,
    references: ReferenceCredentials,
) -> ClassifiedCredentialLocation:
    """Parse and require a recognized exact credential before mutation planning."""
    if secret.name != location.secret:
        raise CredentialMutationError(CredentialMutationErrorCode.UNSAFE_OBSERVED_STATE)
    try:
        observed = read_credential(secret, location.representation)
    except RepresentationError:
        raise CredentialMutationError(CredentialMutationErrorCode.REPRESENTATION_INVALID) from None
    state = classify(location, observed, references)
    if state not in (
        CredentialState.MATCHES_ADMIN_REFERENCE,
        CredentialState.MATCHES_BREAKGLASS_REFERENCE,
    ):
        raise CredentialMutationError(CredentialMutationErrorCode.UNSAFE_OBSERVED_STATE)
    return ClassifiedCredentialLocation(location, state, secret)


class CredentialMutationDisposition(Enum):
    UNCHANGED = "unchanged"
    CHANGED = "changed"


@dataclass(frozen=True)
class CredentialMutationResult:
    location: str
    secret: str
    disposition: CredentialMutationDisposition
    identity: Identity
    restart_dependencies: tuple[WorkloadRef, ...]

    @property
    def changed(self) -> bool:
        return self.disposition is CredentialMutationDisposition.CHANGED

    @property
    def required_restart_dependencies(self) -> tuple[WorkloadRef, ...]:
        """Restart debt for a later slice; this module never executes it."""
        return self.restart_dependencies if self.changed else ()


class CredentialSecretClientErrorCode(Enum):
    NOT_FOUND = "not_found"
    CONDITIONAL_REJECTED = "conditional_rejected"
    OUTCOME_AMBIGUOUS = "outcome_ambiguous"
    FAILURE = "failure"


class CredentialSecretClientError(Exception):
    """Value-free transport failure used by the mutation engine."""

    def __init__(self, kind: CredentialSecretClientErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value)


class CredentialSecretClient(Protocol):
    def read(self, namespace: str, name: str) -> SecretSnapshot: ...

    def conditional_replace(
        self, expected: SecretSnapshot, replacements: tuple[SecretField, ...],
    ) -> None: ...


class _CoreV1SecretApi(Protocol):
    def read_namespaced_secret(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object: ...

    def patch_namespaced_secret(
        self, name: str, namespace: str, body: list[dict[str, object]],
        **kwargs: object,
    ) -> object: ...


class _KubernetesSerializer(Protocol):
    def sanitize_for_serialization(self, value: object) -> object: ...


@runtime_checkable
class _HttpStatusError(Protocol):
    status: object


def _http_status(error: Exception) -> int | None:
    if not isinstance(error, _HttpStatusError):
        return None
    status = error.status
    return status if isinstance(status, int) and not isinstance(status, bool) else None


def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _snapshot(
    resource: object, serializer: _KubernetesSerializer, namespace: str, name: str,
) -> SecretSnapshot:
    try:
        normalized = serializer.sanitize_for_serialization(resource)
        inventory = parse_inventory(json.dumps({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": {"resourceVersion": "single-object-read"},
            "items": [normalized],
        }).encode("utf-8"), namespace)
    except (ReadError, TypeError, ValueError, UnicodeError):
        raise CredentialSecretClientError(CredentialSecretClientErrorCode.FAILURE) from None
    if len(inventory.secrets) != 1 or inventory.secrets[0].name != name:
        raise CredentialSecretClientError(CredentialSecretClientErrorCode.FAILURE)
    return inventory.secrets[0]


class KubernetesApiCredentialSecretClient:
    """Direct Secret GET and atomic UID/resourceVersion-tested JSON Patch."""

    def __init__(
        self, api: _CoreV1SecretApi, serializer: _KubernetesSerializer,
        *, timeout: float = 60.0,
    ) -> None:
        if not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ValueError("Timeout must be finite, positive, and at most 3600 seconds.")
        self._api = api
        self._serializer = serializer
        self._timeout = timeout

    @classmethod
    def from_config(
        cls, *, context: str | None = None, kubeconfig: Path | None = None,
        timeout: float = 60.0,
    ) -> Self:
        validate_api_options(context=context, timeout=timeout)
        try:
            handle = create_kubernetes_api(
                "CoreV1Api", context=context, kubeconfig=kubeconfig,
            )
        except Exception:
            raise CredentialSecretClientError(CredentialSecretClientErrorCode.FAILURE) from None
        return cls(
            cast(_CoreV1SecretApi, handle.api),
            cast(_KubernetesSerializer, handle.serializer),
            timeout=timeout,
        )

    def read(self, namespace: str, name: str) -> SecretSnapshot:
        try:
            resource = self._api.read_namespaced_secret(
                name, namespace, _request_timeout=self._timeout,
            )
        except Exception as exc:
            kind = (
                CredentialSecretClientErrorCode.NOT_FOUND
                if _http_status(exc) == 404
                else CredentialSecretClientErrorCode.FAILURE
            )
            raise CredentialSecretClientError(kind) from None
        return _snapshot(resource, self._serializer, namespace, name)

    def conditional_replace(
        self, expected: SecretSnapshot, replacements: tuple[SecretField, ...],
    ) -> None:
        patch: list[dict[str, object]] = [
            {"op": "test", "path": "/metadata/uid", "value": expected.uid},
            {
                "op": "test", "path": "/metadata/resourceVersion",
                "value": expected.resource_version,
            },
        ]
        patch.extend({
            "op": "replace",
            "path": f"/data/{_pointer(item.key)}",
            "value": base64.b64encode(item.value.reveal()).decode("ascii"),
        } for item in replacements)
        try:
            self._api.patch_namespaced_secret(
                expected.name, expected.namespace, patch,
                _content_type="application/json-patch+json",
                _request_timeout=self._timeout,
            )
        except Exception as exc:
            status = _http_status(exc)
            if status in (409, 412):
                kind = CredentialSecretClientErrorCode.CONDITIONAL_REJECTED
            elif status is None or status == 429 or status >= 500:
                kind = CredentialSecretClientErrorCode.OUTCOME_AMBIGUOUS
            else:
                kind = CredentialSecretClientErrorCode.FAILURE
            raise CredentialSecretClientError(kind) from None


def _target_is_allowed(location: CredentialLocation, identity: Identity) -> bool:
    return (
        location.identity is IdentityBinding.ACTIVE
        or location.identity.value == identity.value
    )


def _has_username(location: CredentialLocation) -> bool:
    rep = location.representation
    if isinstance(rep, FieldsRepresentation):
        return rep.username is not None
    if isinstance(rep, IniRepresentation):
        return rep.username is not None
    return rep.username_path is not None


def credential_matches_desired(
    location: CredentialLocation, observed: ObservedCredential,
    desired: DesiredCredential,
) -> bool:
    expected_username = desired.identity.value if _has_username(location) else None
    return (
        observed.username == expected_username
        and hmac.compare_digest(observed.password.reveal(), desired.password.reveal())
    )


def _matches_target(
    location: CredentialLocation, secret: SecretSnapshot,
    desired: DesiredCredential,
) -> bool:
    return credential_matches_desired(
        location, read_credential(secret, location.representation), desired,
    )


def _assert_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise CredentialMutationError(CredentialMutationErrorCode.OWNERSHIP_LOST) from None


def mutate_credential_location(
    client: CredentialSecretClient, ownership: OwnershipGuard, *,
    observed: ClassifiedCredentialLocation, desired: DesiredCredential,
    allowed_observed_identities: frozenset[Identity],
) -> CredentialMutationResult:
    """Converge one recognized propagated location to a caller-validated target.

    ``desired`` must already be the authoritative/reconciled credential for its
    labeled identity.  This one-location primitive does not establish that
    external fact; it validates the contracted location and safely propagates
    the supplied target.
    """
    location = observed.location
    if location.role is not LocationRole.PROPAGATED:
        raise CredentialMutationError(CredentialMutationErrorCode.SOURCE_LOCATION)
    if not _target_is_allowed(location, desired.identity):
        raise CredentialMutationError(CredentialMutationErrorCode.IDENTITY_NOT_ALLOWED)
    if observed.identity not in allowed_observed_identities:
        raise CredentialMutationError(CredentialMutationErrorCode.UNSAFE_OBSERVED_STATE)

    try:
        if _matches_target(location, observed.secret, desired):
            _assert_owned(ownership)
            try:
                current = client.read(
                    observed.secret.namespace, observed.secret.name,
                )
            except CredentialSecretClientError as exc:
                kind = (
                    CredentialMutationErrorCode.CONFLICT
                    if exc.kind is CredentialSecretClientErrorCode.NOT_FOUND
                    else CredentialMutationErrorCode.KUBERNETES_FAILURE
                )
                raise CredentialMutationError(kind) from None
            if current.uid != observed.secret.uid:
                raise CredentialMutationError(CredentialMutationErrorCode.CONFLICT)
            try:
                current_matches = _matches_target(location, current, desired)
            except RepresentationError:
                raise CredentialMutationError(
                    CredentialMutationErrorCode.REPRESENTATION_INVALID,
                ) from None
            if not current_matches:
                raise CredentialMutationError(CredentialMutationErrorCode.CONFLICT)
            return CredentialMutationResult(
                location.name, location.secret,
                CredentialMutationDisposition.UNCHANGED, desired.identity,
                location.restart,
            )
        replacements = mutate_credential_fields(
            observed.secret, location.representation,
            username=desired.identity.value, password=desired.password,
        )
    except RepresentationError:
        raise CredentialMutationError(CredentialMutationErrorCode.REPRESENTATION_INVALID) from None
    if not replacements:
        # The exact-target check above and the structural mutation calculation
        # must agree.  Treat disagreement as unsafe rather than issuing a write.
        raise CredentialMutationError(CredentialMutationErrorCode.REPRESENTATION_INVALID)

    _assert_owned(ownership)

    try:
        client.conditional_replace(observed.secret, replacements)
    except CredentialSecretClientError as exc:
        if exc.kind is CredentialSecretClientErrorCode.CONDITIONAL_REJECTED:
            kind = CredentialMutationErrorCode.CONFLICT
        elif exc.kind is CredentialSecretClientErrorCode.OUTCOME_AMBIGUOUS:
            kind = CredentialMutationErrorCode.WRITE_AMBIGUOUS
        else:
            kind = CredentialMutationErrorCode.KUBERNETES_FAILURE
        raise CredentialMutationError(kind) from None

    try:
        verified = client.read(observed.secret.namespace, observed.secret.name)
        if (
            verified.uid != observed.secret.uid
            or verified.resource_version == observed.secret.resource_version
            or not _matches_target(location, verified, desired)
        ):
            raise CredentialMutationError(
                CredentialMutationErrorCode.POST_WRITE_VERIFICATION_FAILED,
            )
    except CredentialMutationError:
        raise
    except (CredentialSecretClientError, RepresentationError):
        raise CredentialMutationError(
            CredentialMutationErrorCode.POST_WRITE_VERIFICATION_FAILED,
        ) from None

    return CredentialMutationResult(
        location.name, location.secret, CredentialMutationDisposition.CHANGED,
        desired.identity, location.restart,
    )


class FakeCredentialSecretClient:
    """Behavioral fake with the same conditional and preservation semantics.

    Accepts one or more named Secrets. ``snapshot`` (when set) aliases the
    first-known Secret for compatibility with single-Secret tests; ``secrets``
    exposes the full per-name mapping for grouped-wave tests.
    """

    def __init__(self, *snapshots: SecretSnapshot) -> None:
        if not snapshots:
            raise ValueError("At least one SecretSnapshot is required.")
        self.secrets: dict[tuple[str, str], SecretSnapshot] = {
            (item.namespace, item.name): item for item in snapshots
        }
        self.snapshot: SecretSnapshot = next(iter(self.secrets.values()))
        self.read_error: CredentialSecretClientErrorCode | None = None
        self.next_replace_error: CredentialSecretClientErrorCode | None = None
        self.before_replace: Callable[[FakeCredentialSecretClient], None] | None = None
        self.after_replace: Callable[[FakeCredentialSecretClient], None] | None = None
        self.read_calls = 0
        self.replace_calls = 0

    def current(self, namespace: str, name: str) -> SecretSnapshot:
        """Return the current snapshot for a named Secret (multi-Secret access)."""
        key = (namespace, name)
        if key not in self.secrets:
            raise CredentialSecretClientError(CredentialSecretClientErrorCode.NOT_FOUND)
        return self.secrets[key]

    def set_secret(self, snapshot: SecretSnapshot) -> None:
        """Swap a Secret by its name, keeping other per-name entries intact.

        If the new snapshot names the same Secret as ``self.snapshot``,
        ``self.snapshot`` is updated to keep the primary reference in sync so
        that single-Secret tests which read ``client.snapshot`` after a
        ``before_replace`` callback see the current state.
        """
        self.secrets[(snapshot.namespace, snapshot.name)] = snapshot
        if (
            self.snapshot.namespace, self.snapshot.name
        ) == (snapshot.namespace, snapshot.name):
            self.snapshot = snapshot

    def replace_snapshot(self, snapshot: SecretSnapshot) -> None:
        """Replace the primary snapshot, syncing the per-name store."""
        self.snapshot = snapshot
        self.secrets[(snapshot.namespace, snapshot.name)] = snapshot

    def _current(self, namespace: str, name: str) -> SecretSnapshot:
        key = (namespace, name)
        if key not in self.secrets:
            raise CredentialSecretClientError(CredentialSecretClientErrorCode.NOT_FOUND)
        return self.secrets[key]

    def read(self, namespace: str, name: str) -> SecretSnapshot:
        self.read_calls += 1
        if self.read_error is not None:
            raise CredentialSecretClientError(self.read_error)
        return self._current(namespace, name)

    def conditional_replace(
        self, expected: SecretSnapshot, replacements: tuple[SecretField, ...],
    ) -> None:
        self.replace_calls += 1
        if self.before_replace is not None:
            callback = self.before_replace
            self.before_replace = None
            callback(self)
        if self.next_replace_error is not None:
            kind = self.next_replace_error
            self.next_replace_error = None
            raise CredentialSecretClientError(kind)
        # Resolve the current snapshot for the named Secret.  After a
        # ``before_replace`` callback that mutated ``self.snapshot`` (the
        # single-Secret primary reference), the per-name store is re-synced so
        # the CAS precondition and write target reflect the callback's reality.
        if (
            (self.snapshot.namespace, self.snapshot.name)
            == (expected.namespace, expected.name)
        ):
            self.secrets[(expected.namespace, expected.name)] = self.snapshot
        current = self._current(expected.namespace, expected.name)
        if (
            current.uid != expected.uid
            or current.resource_version != expected.resource_version
        ):
            raise CredentialSecretClientError(
                CredentialSecretClientErrorCode.CONDITIONAL_REJECTED,
            )
        by_key = {item.key: item for item in current.data}
        by_key.update({item.key: item for item in replacements})
        try:
            resource_version = str(int(current.resource_version) + 1)
        except ValueError:
            resource_version = f"{current.resource_version}-next"
        updated = replace(
            current, resource_version=resource_version,
            data=tuple(sorted(by_key.values(), key=lambda item: item.key)),
        )
        self.replace_snapshot(updated)
        if self.after_replace is not None:
            callback = self.after_replace
            self.after_replace = None
            callback(self)
            # Propagate an after_replace tamper of the primary snapshot to the
            # per-name store so a fresh read reflects the observed reality.
            if (
                (self.snapshot.namespace, self.snapshot.name)
                == (updated.namespace, updated.name)
            ):
                self.secrets[(updated.namespace, updated.name)] = self.snapshot


class GroupedPropagationErrorCode(Enum):
    CONTRACT_DRIFT = "grouped_propagation_contract_drift"
    INTENT_MISMATCH = "grouped_propagation_intent_mismatch"
    UNSAFE_OBSERVED_STATE = "grouped_propagation_unsafe_observed_state"
    REQUIRES_MUTATION_AFTER_COMPLETION = (
        "grouped_propagation_requires_mutation_after_completion"
    )
    NO_CONVERGED_GROUP = "grouped_propagation_no_converged_group"
    REPRESENTATION_INVALID = "grouped_propagation_representation_invalid"
    SOURCE_LOCATION = "grouped_propagation_source_location"
    IDENTITY_NOT_ALLOWED = "grouped_propagation_identity_not_allowed"
    OWNERSHIP_LOST = "grouped_propagation_ownership_lost"
    CONFLICT = "grouped_propagation_conflict"
    WRITE_AMBIGUOUS = "grouped_propagation_write_ambiguous"
    KUBERNETES_FAILURE = "grouped_propagation_kubernetes_failure"
    POST_WRITE_VERIFICATION_FAILED = (
        "grouped_propagation_post_write_verification_failed"
    )
    WRITE_WITHOUT_MUTATION_REQUIRED = "grouped_propagation_write_without_mutation_required"
    PROGRESS_PERSISTENCE_FAILED = "grouped_propagation_progress_persistence_failed"


_GROUPED_ERROR_MESSAGES: dict[GroupedPropagationErrorCode, str] = {
    kind: "Grouped propagation cannot continue safely; inspect the recorded error category."
    for kind in GroupedPropagationErrorCode
}


class GroupedPropagationError(SafeError):
    """A credential-free grouped-propagation failure with a stable category."""

    def __init__(self, kind: GroupedPropagationErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _GROUPED_ERROR_MESSAGES[kind])


class GroupedPropagationSession:
    """Mutable session over the state store during grouped wave execution."""

    def __init__(self, store: StateStore, persisted: PersistedState) -> None:
        self.store = store
        self.persisted = persisted

    @property
    def transaction(self) -> RotationTransaction:
        result = self.persisted.state.current_transaction
        if result is None:
            raise GroupedPropagationError(GroupedPropagationErrorCode.INTENT_MISMATCH)
        return result

    def write(self, transaction: RotationTransaction) -> RotationTransaction:
        self.persisted = self.store.update(
            self.persisted.revision,
            replace(self.persisted.state, current_transaction=transaction),
        )
        return self.transaction


def _assert_grouped_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise GroupedPropagationError(GroupedPropagationErrorCode.OWNERSHIP_LOST) from None


def _replace_wave_for_target(
    transaction: RotationTransaction, target: Identity, wave: PropagationWave,
) -> RotationTransaction:
    propagation: PropagationState
    if target is Identity.BREAKGLASS:
        propagation = replace(transaction.propagation, to_b=wave)
    else:
        propagation = replace(transaction.propagation, to_a=wave)
    return replace(transaction, propagation=propagation)


@dataclass(frozen=True)
class GroupedGroupOutcome:
    """Per-Secret-group outcome: one write (if any), one verified Secret."""

    namespace: str
    secret_name: str
    location_identities: tuple[tuple[str, Identity], ...]
    changed_locations: tuple[str, ...]
    restart_dependencies: tuple[WorkloadRef, ...]
    secret_writes: int


@dataclass(frozen=True, repr=False)
class GroupedWaveResult:
    """Result of one grouped propagation-wave execution."""

    target_identity: Identity
    groups: tuple[GroupedGroupOutcome, ...]
    changed_locations: tuple[str, ...]
    restart_dependencies: tuple[WorkloadRef, ...]
    secret_writes: int
    wave: PropagationWave
    persisted: PersistedState


def compose_group_replacements(
    current: SecretSnapshot,
    locations: tuple[CredentialLocation, ...],
    desired: DesiredCredential,
) -> tuple[SecretField, ...]:
    """Compose per-location structural transformations on an evolving Secret.

    Each location's transformation is derived and applied to an in-memory
    working Secret in deterministic group order.  This lets several logical
    locations that share one Secret data key (for example distinct INI options
    in a single serialized document) be mutated together: every transformation
    operates on the already-updated document, so no change is discarded.  One
    final replacement is emitted per data key that actually changed relative to
    the original Secret.  Slice 4A's structural transformation machinery is
    reused; no INI/YAML mutation logic is duplicated.
    """
    working = current
    for location in locations:
        replacements = _replacements_for_location(working, location, desired)
        if not replacements:
            continue
        by_key = {item.key: item for item in working.data}
        by_key.update({item.key: item for item in replacements})
        working = replace(
            working, data=tuple(sorted(by_key.values(), key=lambda item: item.key)),
        )
    changed_keys = {item.key for item in working.data if item.value.reveal() != _original_value(current, item.key)}
    composed = [item for item in working.data if item.key in changed_keys]
    if not composed:
        return ()
    return tuple(sorted(composed, key=lambda item: item.key))


def _original_value(secret: SecretSnapshot, key: str) -> bytes:
    value = secret.get(key)
    assert value is not None  # keys in working are a superset of original keys
    return value.reveal()


def _replacements_for_location(
    current: SecretSnapshot,
    location: CredentialLocation,
    desired: DesiredCredential,
) -> tuple[SecretField, ...]:
    """Structural transformation of one logical location, or ``()`` for no-op."""
    if location.role is not LocationRole.PROPAGATED:
        raise GroupedPropagationError(GroupedPropagationErrorCode.SOURCE_LOCATION)
    if not (
        location.identity is IdentityBinding.ACTIVE
        or location.identity.value == desired.identity.value
    ):
        raise GroupedPropagationError(GroupedPropagationErrorCode.IDENTITY_NOT_ALLOWED)
    try:
        if credential_matches_desired(location, read_credential(current, location.representation), desired):
            return ()
        return mutate_credential_fields(
            current, location.representation,
            username=desired.identity.value, password=desired.password,
        )
    except RepresentationError:
        raise GroupedPropagationError(GroupedPropagationErrorCode.REPRESENTATION_INVALID) from None


@dataclass(frozen=True)
class _ReconciledLocation:
    location: CredentialLocation
    intent: PropagationLocationIntent
    observed_identity: Identity
    is_target: bool
    recorded_complete: bool
    expected_target: bool


def _reconcile_group(
    group: PropagationSecretGroupIntent,
    current: SecretSnapshot,
    applied: frozenset[str],
    contract_locations: dict[str, CredentialLocation],
    references: ReferenceCredentials,
    desired: DesiredCredential,
) -> list[_ReconciledLocation]:
    """Classify every group location against fresh state, failing closed on unsafe.

    Returns one ``_ReconciledLocation`` per group location.  Raises
    ``GroupedPropagationError`` (UNSAFE_OBSERVED_STATE) on any unsafe disposition:
    an unparseable representation, an unknown/unrecognized credential, a
    recorded-complete location that is no longer at target, or a current identity
    that contradicts durable intent.  The caller verifies UID continuity before
    calling this.
    """
    results: list[_ReconciledLocation] = []
    for location_intent in group.locations:
        location = contract_locations[location_intent.location_id]
        recorded_complete = location.name in applied
        try:
            observed = read_credential(current, location.representation)
        except RepresentationError:
            raise GroupedPropagationError(GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE) from None
        if credential_matches_desired(location, observed, desired):
            results.append(_ReconciledLocation(
                location, location_intent, desired.identity, True, recorded_complete,
                location_intent.expected_target,
            ))
            continue
        state = classify(location, observed, references)
        if state is CredentialState.MATCHES_ADMIN_REFERENCE:
            observed_identity = Identity.ADMIN
        elif state is CredentialState.MATCHES_BREAKGLASS_REFERENCE:
            observed_identity = Identity.BREAKGLASS
        else:
            raise GroupedPropagationError(GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE)
        if recorded_complete:
            # Progress claims completion but fresh state regressed: unsafe.
            raise GroupedPropagationError(GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE)
        if (
            location_intent.expected_target
            or observed_identity is not location_intent.expected_identity
        ):
            # Fresh state contradicts the original classified intent: unsafe.
            raise GroupedPropagationError(GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE)
        results.append(_ReconciledLocation(
            location, location_intent, observed_identity, False, False,
            location_intent.expected_target,
        ))
    return results


def _location_changed(
    reconciled: _ReconciledLocation, applied: frozenset[str],
) -> bool:
    """Whether this location should be counted as changed/restart-relevant.

    A location changed when it requires mutation, or when it is freshly at
    target but was *originally* non-target (``expected_target == False``) and has
    no applied marker.  The latter conservatively treats an originally-non-target
    location observed at target during recovery as a transition that occurred
    during the wave lifetime (our write succeeded before a crash, or another
    actor converged the Secret), retaining its restart debt.  A location that was
    already target at wave creation (``expected_target == True``) is not
    restart-relevant merely because it remains target.
    """
    if reconciled.is_target:
        if reconciled.recorded_complete:
            return True
        return not reconciled.expected_target
    return not reconciled.recorded_complete


def execute_grouped_propagation_wave(
    client: CredentialSecretClient,
    session: GroupedPropagationSession,
    ownership: OwnershipGuard,
    *,
    contract: CredentialContract,
    references: ReferenceCredentials,
    desired: DesiredCredential,
    wave: PropagationWave,
    now: datetime,
) -> GroupedWaveResult:
    """Safely execute one durable propagation wave.

    An initial all-wave safety pass observes every group once (fail closed on
    any unsafe state).  Each group is then re-observed freshly immediately
    before it is processed: the no-op-versus-mutation decision and the CAS basis
    both come from that fresh state, never from the earlier precheck snapshot.
    Durable progress is persisted after each successfully processed group so
    changed/restart-debt accounting survives a crash between a write and the end
    of the wave.  No restart or phase action is performed.
    """
    _assert_grouped_owned(ownership)
    intent = wave.intent
    if intent is None:
        raise GroupedPropagationError(GroupedPropagationErrorCode.INTENT_MISMATCH)
    if (
        intent.target_identity is not desired.identity
        or intent.target_generation
        != CredentialGeneration.from_secret(desired.password)
    ):
        raise GroupedPropagationError(GroupedPropagationErrorCode.INTENT_MISMATCH)
    if (
        intent.contract_digest != propagation_contract_digest(contract)
        or intent_membership(intent)
        != contract_membership(contract, desired.identity)
    ):
        raise GroupedPropagationError(GroupedPropagationErrorCode.CONTRACT_DRIFT)
    contract_locations = {item.name: item for item in contract.locations}
    initial_applied = frozenset(wave.applied_location_ids)
    if not initial_applied <= {
        location.location_id
        for group in intent.secret_groups
        for location in group.locations
    }:
        raise GroupedPropagationError(GroupedPropagationErrorCode.INTENT_MISMATCH)

    # Initial all-wave safety pass: fail closed on any unsafe group before any
    # write.  This is a coarse early gate; execution re-observes each group.
    for group in intent.secret_groups:
        try:
            snapshot = client.read(group.namespace, group.secret_name)
        except CredentialSecretClientError:
            raise GroupedPropagationError(GroupedPropagationErrorCode.KUBERNETES_FAILURE) from None
        if snapshot.uid != group.observed_uid:
            raise GroupedPropagationError(GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE)
        _reconcile_group(
            group, snapshot, initial_applied, contract_locations, references, desired,
        )

    results: list[GroupedGroupOutcome] = []
    total_writes = 0
    applied: set[str] = set(wave.applied_location_ids)
    all_changed: set[str] = set()
    all_restarts: set[WorkloadRef] = set()
    current_wave = wave
    for group in intent.secret_groups:
        applied_frozen = frozenset(applied)
        outcome = _execute_group(
            client=client, ownership=ownership, group=group,
            contract_locations=contract_locations, references=references,
            desired=desired, applied=applied_frozen,
        )
        results.append(outcome)
        total_writes += outcome.secret_writes
        # Durable changed/restart accounting: locations that actually changed,
        # plus already-converged locations that were originally non-target or
        # previously applied (crash-safe restart-debt retention).
        changed_now = set(outcome.changed_locations)
        applied |= changed_now
        all_changed |= changed_now
        all_restarts |= set(outcome.restart_dependencies)
        current_wave = _persist_group_progress(
            session, ownership=ownership, target=desired.identity,
            wave=current_wave, applied=applied, now=now,
        )

    return GroupedWaveResult(
        target_identity=desired.identity,
        groups=tuple(results),
        changed_locations=tuple(sorted(all_changed)),
        restart_dependencies=tuple(sorted(all_restarts, key=lambda item: item.label)),
        secret_writes=total_writes,
        wave=current_wave,
        persisted=session.persisted,
    )


def _persist_group_progress(
    session: GroupedPropagationSession, *, ownership: OwnershipGuard,
    target: Identity, wave: PropagationWave, applied: set[str],
    now: datetime,
) -> PropagationWave:
    """Persist wave progress after one group so accounting survives a crash.

    Reasserts execution ownership immediately before the durable write: the
    state-store update is itself a mutation and must obey the same Lease/ownership
    discipline as Secret writes.  If ownership is lost, raises ``OWNERSHIP_LOST``
    and does not update transaction state.  When there is no state change to
    write, no ownership assertion is performed.

    Returns the updated wave (so the caller can track it across groups) or the
    original wave when nothing changed.
    """
    applied_sorted = tuple(sorted(applied))
    if applied_sorted == wave.applied_location_ids:
        return wave
    updated = replace(wave, applied_location_ids=applied_sorted)
    transaction = _replace_wave_for_target(session.transaction, target, updated)
    _assert_grouped_owned(ownership)
    session.write(replace(transaction, updated_at=now))
    return updated


def _execute_group(
    client: CredentialSecretClient,
    ownership: OwnershipGuard,
    *,
    group: PropagationSecretGroupIntent,
    contract_locations: dict[str, CredentialLocation],
    references: ReferenceCredentials,
    desired: DesiredCredential,
    applied: frozenset[str],
) -> GroupedGroupOutcome:
    """Converge one Secret group from a fresh observation, at most one write."""
    # Fresh observation: the no-op/mutation decision and CAS basis both use this.
    try:
        current = client.read(group.namespace, group.secret_name)
    except CredentialSecretClientError:
        raise GroupedPropagationError(GroupedPropagationErrorCode.KUBERNETES_FAILURE) from None
    # A same-name replacement of the Secret is never a safe mutation target.
    if current.uid != group.observed_uid:
        raise GroupedPropagationError(GroupedPropagationErrorCode.UNSAFE_OBSERVED_STATE)
    reconciled = _reconcile_group(
        group, current, applied, contract_locations, references, desired,
    )
    requires_mutation = [
        item.location for item in reconciled if not item.is_target
    ]
    location_identities = tuple(
        (item.location.name, item.observed_identity) for item in reconciled
    )
    if not requires_mutation:
        # Every location is already at target: no write.  Changed accounting
        # still retains originally-non-target (crash-recovered) locations.
        changed = tuple(
            item.location.name for item in reconciled if _location_changed(item, applied)
        )
        restarts = tuple(sorted(
            {dep for item in reconciled if _location_changed(item, applied)
             for dep in item.location.restart},
            key=lambda item: item.label,
        ))
        return GroupedGroupOutcome(
            namespace=group.namespace, secret_name=group.secret_name,
            location_identities=location_identities, changed_locations=changed,
            restart_dependencies=restarts, secret_writes=0,
        )

    combined = compose_group_replacements(current, tuple(requires_mutation), desired)
    if not combined:
        # No structural change needed even though classification said mutation:
        # a contradiction.  Fail closed.
        raise GroupedPropagationError(
            GroupedPropagationErrorCode.REQUIRES_MUTATION_AFTER_COMPLETION,
        )

    _assert_grouped_owned(ownership)
    try:
        client.conditional_replace(current, combined)
    except CredentialSecretClientError as exc:
        if exc.kind is CredentialSecretClientErrorCode.CONDITIONAL_REJECTED:
            raise GroupedPropagationError(GroupedPropagationErrorCode.CONFLICT) from None
        if exc.kind is CredentialSecretClientErrorCode.OUTCOME_AMBIGUOUS:
            raise GroupedPropagationError(GroupedPropagationErrorCode.WRITE_AMBIGUOUS) from None
        raise GroupedPropagationError(GroupedPropagationErrorCode.KUBERNETES_FAILURE) from None

    # Fresh reread and per-location verification.
    try:
        verified = client.read(group.namespace, group.secret_name)
    except CredentialSecretClientError:
        raise GroupedPropagationError(
            GroupedPropagationErrorCode.POST_WRITE_VERIFICATION_FAILED,
        ) from None
    if verified.uid != group.observed_uid:
        raise GroupedPropagationError(
            GroupedPropagationErrorCode.POST_WRITE_VERIFICATION_FAILED,
        )
    for item in reconciled:
        try:
            observed = read_credential(verified, item.location.representation)
        except RepresentationError:
            raise GroupedPropagationError(
                GroupedPropagationErrorCode.POST_WRITE_VERIFICATION_FAILED,
            ) from None
        if not credential_matches_desired(item.location, observed, desired):
            raise GroupedPropagationError(
                GroupedPropagationErrorCode.POST_WRITE_VERIFICATION_FAILED,
            )

    changed = tuple(item.location.name for item in reconciled if _location_changed(item, applied))
    restarts = tuple(sorted(
        {dep for item in reconciled if _location_changed(item, applied)
         for dep in item.location.restart},
        key=lambda item: item.label,
    ))
    return GroupedGroupOutcome(
        namespace=group.namespace, secret_name=group.secret_name,
        location_identities=location_identities, changed_locations=changed,
        restart_dependencies=restarts, secret_writes=1,
    )
