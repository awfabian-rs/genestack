"""Safe structural mutation of one contracted propagated credential location."""
from __future__ import annotations

import base64
import hmac
import json
import math
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Self, cast, runtime_checkable

from .discovery import classify
from .errors import ReadError, RepresentationError, SafeError
from .kubernetes import parse_inventory
from .kubernetes_api import create_kubernetes_api, validate_api_options
from .model import (
    CredentialLocation, CredentialState, FieldsRepresentation, Identity,
    IdentityBinding, IniRepresentation, LocationRole, ReferenceCredentials,
    SecretField, SecretSnapshot, SecretValue, WorkloadRef,
)
from .prepare_b import OwnershipGuard
from .representations import mutate_credential_fields, read_credential


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


def _matches_target(
    location: CredentialLocation, secret: SecretSnapshot,
    desired: DesiredCredential,
) -> bool:
    observed = read_credential(secret, location.representation)
    expected_username = desired.identity.value if _has_username(location) else None
    return (
        observed.username == expected_username
        and hmac.compare_digest(observed.password.reveal(), desired.password.reveal())
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
    """Behavioral fake with the same conditional and preservation semantics."""

    def __init__(self, snapshot: SecretSnapshot) -> None:
        self.snapshot = snapshot
        self.read_error: CredentialSecretClientErrorCode | None = None
        self.next_replace_error: CredentialSecretClientErrorCode | None = None
        self.before_replace: Callable[[FakeCredentialSecretClient], None] | None = None
        self.after_replace: Callable[[FakeCredentialSecretClient], None] | None = None
        self.read_calls = 0
        self.replace_calls = 0

    def read(self, namespace: str, name: str) -> SecretSnapshot:
        self.read_calls += 1
        if self.read_error is not None:
            raise CredentialSecretClientError(self.read_error)
        if self.snapshot.namespace != namespace or self.snapshot.name != name:
            raise CredentialSecretClientError(CredentialSecretClientErrorCode.NOT_FOUND)
        return self.snapshot

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
        if (
            self.snapshot.uid != expected.uid
            or self.snapshot.resource_version != expected.resource_version
        ):
            raise CredentialSecretClientError(
                CredentialSecretClientErrorCode.CONDITIONAL_REJECTED,
            )
        by_key = {item.key: item for item in self.snapshot.data}
        by_key.update({item.key: item for item in replacements})
        try:
            resource_version = str(int(self.snapshot.resource_version) + 1)
        except ValueError:
            resource_version = f"{self.snapshot.resource_version}-next"
        self.snapshot = replace(
            self.snapshot, resource_version=resource_version,
            data=tuple(sorted(by_key.values(), key=lambda item: item.key)),
        )
        if self.after_replace is not None:
            callback = self.after_replace
            self.after_replace = None
            callback(self)
