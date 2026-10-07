"""Slice 4D: typed workload restart execution and rollout observation.

This module derives restart actions from durable changed-location accounting,
dispatches the Kubernetes restart through direct APIs, and observes the resulting
workload rollout/replacement.  It never issues credential mutations; restart debt
that was not yet dispatched remains durable and recoverable.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Self, cast, runtime_checkable

from .errors import ReadError, SafeError
from .kubernetes_api import create_kubernetes_api, validate_api_options
from .model import (
    CredentialContract, Identity, PropagationState, PropagationWave,
    RotationTransaction, RuntimeActionProgress, RuntimeActionState,
    WorkloadKind, WorkloadRef,
)
from .prepare_b import OwnershipGuard
from .state_store import PersistedState, StateStore, StateStoreError
from .validation import is_object_name, object_list, object_mapping
from .wave_digest import propagation_contract_digest

__all__ = [
    "RESTART_ANNOTATION", "RolloutStatus", "WorkloadSnapshot",
    "WorkloadClientError", "WorkloadClientErrorCode",
    "DeploymentClient", "DaemonSetClient", "WorkloadClient",
    "KubernetesApiWorkloadClient", "make_workload_client",
    "RestartAction", "RestartExecutionErrorCode", "RestartExecutionError",
    "RestartExecutionResult", "derive_restart_actions", "execute_restart_debt",
    "restart_request_for",
]


class RestartExecutionErrorCode(Enum):
    NO_TRANSACTION = "restart_execution_no_transaction"
    NO_WAVE_INTENT = "restart_execution_no_wave_intent"
    INTENT_MISMATCH = "restart_execution_intent_mismatch"
    CONTRACT_DRIFT = "restart_execution_contract_drift"
    WORKLOAD_MISSING = "restart_execution_workload_missing"
    WORKLOAD_INVALID = "restart_execution_workload_invalid"
    WORKLOAD_MUTATION_FAILED = "restart_execution_workload_mutation_failed"
    WORKLOAD_READ_FAILED = "restart_execution_workload_read_failed"
    WORKLOAD_REPLACED = "restart_execution_workload_replaced"
    ROLLOUT_FAILED = "restart_execution_rollout_failed"
    ROLLOUT_TIMEOUT = "restart_execution_rollout_timeout"
    OWNERSHIP_LOST = "restart_execution_ownership_lost"
    PROGRESS_PERSISTENCE_FAILED = "restart_execution_progress_persistence_failed"
    STALE_RUNTIME_ACTIONS = "restart_execution_stale_runtime_actions"


_ERROR_MESSAGES: dict[RestartExecutionErrorCode, str] = {
    RestartExecutionErrorCode.NO_TRANSACTION:
        "No active transaction exists to persist restart progress.",
    RestartExecutionErrorCode.NO_WAVE_INTENT:
        "The propagation wave has no durable intent from which restart debt derives.",
    RestartExecutionErrorCode.INTENT_MISMATCH:
        "The restart request does not match durable wave intent.",
    RestartExecutionErrorCode.CONTRACT_DRIFT:
        "The credential contract drifts from durable wave intent.",
    RestartExecutionErrorCode.WORKLOAD_MISSING:
        "A required restart workload is absent from Kubernetes.",
    RestartExecutionErrorCode.WORKLOAD_INVALID:
        "A restart workload observation is invalid; details withheld.",
    RestartExecutionErrorCode.WORKLOAD_MUTATION_FAILED:
        "The Kubernetes restart mutation failed; details withheld.",
    RestartExecutionErrorCode.WORKLOAD_READ_FAILED:
        "The Kubernetes workload read failed; details withheld.",
    RestartExecutionErrorCode.WORKLOAD_REPLACED:
        "A restart workload was replaced after dispatch; reobserve before continuing.",
    RestartExecutionErrorCode.ROLLOUT_FAILED:
        "The observed workload rollout failed.",
    RestartExecutionErrorCode.ROLLOUT_TIMEOUT:
        "The workload rollout did not complete within the bounded wait.",
    RestartExecutionErrorCode.OWNERSHIP_LOST:
        "Current rotation execution ownership was not established before restart action.",
    RestartExecutionErrorCode.PROGRESS_PERSISTENCE_FAILED:
        "Durable restart progress could not be persisted safely.",
    RestartExecutionErrorCode.STALE_RUNTIME_ACTIONS:
        "Durable runtime action records are not derivable from the current wave.",
}


class RestartExecutionError(SafeError):
    """A credential-free, stable restart-execution failure category."""

    def __init__(self, kind: RestartExecutionErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class RolloutStatus(Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class WorkloadSnapshot:
    """Typed observation of one Deployment or DaemonSet restart state."""

    namespace: str
    name: str
    uid: str
    restart_requested: str | None
    metadata_generation: int
    observed_generation: int
    ready_replicas: int
    desired_replicas: int
    updated_replicas: int
    unavailable_replicas: int
    rollout_status: RolloutStatus
    condition_reason: str | None

    def __post_init__(self) -> None:
        if not is_object_name(self.namespace) or not is_object_name(self.name):
            raise ValueError("Workload namespace and name must be valid object names.")
        if not self.uid:
            raise ValueError("Workload UID must be nonempty.")
        if self.restart_requested is not None and (
            not self.restart_requested or len(self.restart_requested) > 128
        ):
            raise ValueError("Workload restart annotation value must be a nonempty bounded string.")
        if any(
            isinstance(value, bool) or value < 0
            for value in (
                self.metadata_generation, self.observed_generation,
                self.ready_replicas, self.desired_replicas,
                self.updated_replicas, self.unavailable_replicas,
            )
        ):
            raise ValueError("Workload generations and replica counters must be nonnegative integers.")

    def generation_caught_up(self) -> bool:
        """Whether the controller has observed the current Pod-template generation.

        After a Pod-template mutation the workload's ``metadata.generation``
        increments while ``status.observedGeneration`` still reflects the prior
        generation.  Until they catch up, the status block describes the *old*
        template, so the rollout cannot be considered complete.
        """
        return self.observed_generation >= self.metadata_generation

    def complete(self, *, restart_requested: str | None = None) -> bool:
        """Whether the rollout/replacement required by a restart is observed done.

        Completion is generation-aware: the controller must have observed the
        current Pod-template generation (``observedGeneration >= generation``)
        and the replica/schedule counters must be converged.  When a
        ``restart_requested`` marker is supplied, the observed Pod-template
        restart annotation must equal it: a rollout is only accepted as
        satisfying *this* restart when the matching marker is present.
        """
        if self.rollout_status is RolloutStatus.FAILED:
            return False
        if not self.generation_caught_up():
            return False
        if restart_requested is not None and self.restart_requested != restart_requested:
            return False
        return (
            self.updated_replicas == self.desired_replicas
            and self.ready_replicas == self.desired_replicas
            and self.unavailable_replicas == 0
        )


class WorkloadClientErrorCode(Enum):
    NOT_FOUND = "not_found"
    INVALID = "invalid"
    MUTATION_FAILED = "mutation_failed"
    READ_FAILED = "read_failed"


class WorkloadClientError(Exception):
    """Value-free transport failure between a workload adapter and the executor."""

    def __init__(self, kind: WorkloadClientErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value)


class DeploymentClient(Protocol):
    def read(self, namespace: str, name: str) -> WorkloadSnapshot: ...

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot: ...


class DaemonSetClient(Protocol):
    def read(self, namespace: str, name: str) -> WorkloadSnapshot: ...

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot: ...


class WorkloadClient(Protocol):
    deployment: DeploymentClient
    daemonset: DaemonSetClient


def _client_for_kind(client: WorkloadClient, kind: WorkloadKind) -> DeploymentClient | DaemonSetClient:
    if kind is WorkloadKind.DEPLOYMENT:
        return client.deployment
    return client.daemonset


# ---------------------------------------------------------------------------
# Kubernetes observation parsing
# ---------------------------------------------------------------------------

RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt"


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReadError("duplicate_json_key", "Duplicate JSON key; input withheld.")
        result[key] = value
    return result


def _nonempty_string(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReadError(code, "Kubernetes workload observation is invalid.")
    return value


def _integer(value: object, *, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReadError(code, "Kubernetes workload observation is invalid.")
    return value


def _optional_integer(value: object, *, code: str) -> int:
    if value is None:
        return 0
    return _integer(value, code=code)


def _condition_items(status: dict[str, object], code: str) -> list[dict[str, object]]:
    conditions = status.get("conditions")
    if conditions is None:
        return []
    items: list[dict[str, object]] = []
    for item in object_list(conditions):
        items.append(object_mapping(item))
    return items


def _condition_reason(conditions: object, *, code: str) -> str | None:
    if conditions is None:
        return None
    items = object_list(conditions)
    for item in items:
        data = object_mapping(item)
        status = data.get("status")
        if status in ("True", True):
            reason = data.get("reason")
            if reason is not None:
                return _nonempty_string(reason, code=code)
    return None


def _annotations(metadata: dict[str, object]) -> dict[str, object]:
    value = metadata.get("annotations")
    return {} if value is None else object_mapping(value)


def _pod_template_restart(spec: dict[str, object], code: str) -> str | None:
    """Read the restart marker from the Pod template annotations.

    A Deployment/DaemonSet rollout restart is performed by mutating the Pod
    template (``spec.template.metadata.annotations``), never the top-level
    workload metadata.  The marker is observed from the same location it is
    written to.
    """
    template = spec.get("template")
    if template is None:
        return None
    template_mapping = object_mapping(template)
    template_metadata = object_mapping(template_mapping.get("metadata"))
    annotations = _annotations(template_metadata)
    restart = annotations.get(RESTART_ANNOTATION)
    if restart is None:
        return None
    if not isinstance(restart, str):
        raise ReadError(code, "Kubernetes workload observation is invalid.")
    return restart


def _metadata_generation(metadata: dict[str, object], code: str) -> int:
    generation = metadata.get("generation")
    if generation is None:
        return 1
    return _integer(generation, code=code)


def _parse_deployment(resource: object, serializer: object, namespace: str, name: str) -> WorkloadSnapshot:
    try:
        normalized = serializer.sanitize_for_serialization(resource)  # type: ignore[attr-defined]
        raw = json.dumps(normalized).encode("utf-8")
        value: object = json.loads(raw, object_pairs_hook=_json_pairs)
        root = object_mapping(value)
        if root.get("apiVersion") != "apps/v1" or root.get("kind") != "Deployment":
            raise ReadError("invalid_workload", "Kubernetes workload observation is invalid.")
        metadata = object_mapping(root.get("metadata"))
        if metadata.get("namespace") != namespace or metadata.get("name") != name:
            raise ReadError("invalid_workload", "Kubernetes workload observation is invalid.")
        uid = _nonempty_string(metadata.get("uid"), code="invalid_workload")
        generation = _metadata_generation(metadata, "invalid_workload")
        restart = _pod_template_restart(object_mapping(root.get("spec")), "invalid_workload")
        spec = object_mapping(root.get("spec"))
        desired = _optional_integer(spec.get("replicas"), code="invalid_workload")
        status = object_mapping(root.get("status"))
        observed = _integer(status.get("observedGeneration"), code="invalid_workload")
        updated = _optional_integer(status.get("updatedReplicas"), code="invalid_workload")
        ready = _optional_integer(status.get("readyReplicas"), code="invalid_workload")
        unavailable = _optional_integer(status.get("unavailableReplicas"), code="invalid_workload")
        rollout = RolloutStatus.PENDING
        reason = _condition_reason(status.get("conditions"), code="invalid_workload")
        for data in _condition_items(status, "invalid_workload"):
            if data.get("type") == "Available" and data.get("status") in ("True", True):
                rollout = RolloutStatus.SUCCEEDED
                break
            if (
                data.get("type") == "Progressing"
                and data.get("status") in ("False", False)
                and data.get("reason") == "ProgressDeadlineExceeded"
            ):
                rollout = RolloutStatus.FAILED
        return WorkloadSnapshot(
            namespace=namespace, name=name, uid=uid,
            restart_requested=restart,
            metadata_generation=generation,
            observed_generation=observed, ready_replicas=ready,
            desired_replicas=desired, updated_replicas=updated,
            unavailable_replicas=unavailable, rollout_status=rollout,
            condition_reason=reason,
        )
    except (ReadError, TypeError, ValueError, UnicodeError):
        raise ReadError("invalid_workload", "Kubernetes workload observation is invalid.") from None


def _parse_daemonset(resource: object, serializer: object, namespace: str, name: str) -> WorkloadSnapshot:
    try:
        normalized = serializer.sanitize_for_serialization(resource)  # type: ignore[attr-defined]
        raw = json.dumps(normalized).encode("utf-8")
        value: object = json.loads(raw, object_pairs_hook=_json_pairs)
        root = object_mapping(value)
        if root.get("apiVersion") != "apps/v1" or root.get("kind") != "DaemonSet":
            raise ReadError("invalid_workload", "Kubernetes workload observation is invalid.")
        metadata = object_mapping(root.get("metadata"))
        if metadata.get("namespace") != namespace or metadata.get("name") != name:
            raise ReadError("invalid_workload", "Kubernetes workload observation is invalid.")
        uid = _nonempty_string(metadata.get("uid"), code="invalid_workload")
        generation = _metadata_generation(metadata, "invalid_workload")
        spec = object_mapping(root.get("spec"))
        restart = _pod_template_restart(spec, "invalid_workload")
        status = object_mapping(root.get("status"))
        observed = _integer(status.get("observedGeneration"), code="invalid_workload")
        desired = _optional_integer(status.get("desiredNumberScheduled"), code="invalid_workload")
        current = _optional_integer(status.get("currentNumberScheduled"), code="invalid_workload")
        ready = _optional_integer(status.get("numberReady"), code="invalid_workload")
        updated = _optional_integer(status.get("updatedNumberScheduled"), code="invalid_workload")
        unavailable = max(0, desired - current)
        rollout = RolloutStatus.PENDING
        reason = _condition_reason(status.get("conditions"), code="invalid_workload")
        for data in _condition_items(status, "invalid_workload"):
            if data.get("type") == "Available" and data.get("status") in ("True", True):
                rollout = RolloutStatus.SUCCEEDED
                break
        return WorkloadSnapshot(
            namespace=namespace, name=name, uid=uid,
            restart_requested=restart,
            metadata_generation=generation,
            observed_generation=observed, ready_replicas=ready,
            desired_replicas=desired, updated_replicas=updated,
            unavailable_replicas=unavailable, rollout_status=rollout,
            condition_reason=reason,
        )
    except (ReadError, TypeError, ValueError, UnicodeError):
        raise ReadError("invalid_workload", "Kubernetes workload observation is invalid.") from None


# ---------------------------------------------------------------------------
# Direct Kubernetes API client
# ---------------------------------------------------------------------------

class _AppsV1Api(Protocol):
    def read_namespaced_deployment(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object: ...

    def read_namespaced_daemon_set(
        self, name: str, namespace: str, **kwargs: object,
    ) -> object: ...

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: dict[str, object],
        **kwargs: object,
    ) -> object: ...

    def patch_namespaced_daemon_set(
        self, name: str, namespace: str, body: dict[str, object],
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


class KubernetesApiWorkloadClient:
    """Direct Deployment/DaemonSet GET and Pod-template strategic-merge restart.

    A rollout restart is performed by mutating the Pod template
    (``spec.template.metadata.annotations``) with a strategic-merge patch, the
    same mechanism ``kubectl rollout restart`` uses.  A top-level workload
    annotation does not trigger a rollout.
    """

    def __init__(
        self, api: _AppsV1Api, serializer: _KubernetesSerializer, *, timeout: float = 60.0,
    ) -> None:
        if not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ReadError(
                "invalid_timeout", "Timeout must be finite, positive, and at most 3600 seconds.",
            )
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
            handle = create_kubernetes_api("AppsV1Api", context=context, kubeconfig=kubeconfig)
        except Exception:
            raise ReadError(
                "kubernetes_api_unavailable", "Cannot construct the Kubernetes workload API client.",
            ) from None
        return cls(
            cast(_AppsV1Api, handle.api),
            cast(_KubernetesSerializer, handle.serializer),
            timeout=timeout,
        )

    def read(self, namespace: str, name: str, kind: WorkloadKind) -> WorkloadSnapshot:
        try:
            if kind is WorkloadKind.DEPLOYMENT:
                resource = self._api.read_namespaced_deployment(
                    name, namespace, _request_timeout=self._timeout,
                )
            else:
                resource = self._api.read_namespaced_daemon_set(
                    name, namespace, _request_timeout=self._timeout,
                )
        except Exception as exc:
            if _http_status(exc) == 404:
                raise WorkloadClientError(WorkloadClientErrorCode.NOT_FOUND) from None
            raise WorkloadClientError(WorkloadClientErrorCode.READ_FAILED) from None
        try:
            if kind is WorkloadKind.DEPLOYMENT:
                return _parse_deployment(resource, self._serializer, namespace, name)
            return _parse_daemonset(resource, self._serializer, namespace, name)
        except ReadError:
            raise WorkloadClientError(WorkloadClientErrorCode.INVALID) from None

    def restart(self, namespace: str, name: str, kind: WorkloadKind, request: str) -> WorkloadSnapshot:
        if not request or len(request) > 128:
            raise WorkloadClientError(WorkloadClientErrorCode.INVALID)
        # Strategic-merge patch on the Pod template.  The merge sets
        # spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"]
        # to the request marker, which changes the Pod template hash and triggers
        # a controller-managed rolling replacement.  A JSON Pointer path into the
        # annotation key would require escaping the "/" in the annotation name;
        # the merge form avoids that and matches kubectl's own behavior.
        patch: dict[str, object] = {
            "apiVersion": "apps/v1",
            "kind": "Deployment" if kind is WorkloadKind.DEPLOYMENT else "DaemonSet",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {RESTART_ANNOTATION: request},
                    },
                },
            },
        }
        try:
            if kind is WorkloadKind.DEPLOYMENT:
                self._api.patch_namespaced_deployment(
                    name, namespace, patch,
                    _content_type="application/strategic-merge-patch+json",
                    _request_timeout=self._timeout,
                )
            else:
                self._api.patch_namespaced_daemon_set(
                    name, namespace, patch,
                    _content_type="application/strategic-merge-patch+json",
                    _request_timeout=self._timeout,
                )
        except Exception:
            raise WorkloadClientError(WorkloadClientErrorCode.MUTATION_FAILED) from None
        return self.read(namespace, name, kind)


@dataclass(frozen=True)
class _KubernetesWorkloadClient:
    deployment: DeploymentClient
    daemonset: DaemonSetClient


class _DeploymentAdapter:
    def __init__(self, client: KubernetesApiWorkloadClient) -> None:
        self._client = client

    def read(self, namespace: str, name: str) -> WorkloadSnapshot:
        return self._client.read(namespace, name, WorkloadKind.DEPLOYMENT)

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
        return self._client.restart(namespace, name, WorkloadKind.DEPLOYMENT, request)


class _DaemonSetAdapter:
    def __init__(self, client: KubernetesApiWorkloadClient) -> None:
        self._client = client

    def read(self, namespace: str, name: str) -> WorkloadSnapshot:
        return self._client.read(namespace, name, WorkloadKind.DAEMONSET)

    def restart(self, namespace: str, name: str, request: str) -> WorkloadSnapshot:
        return self._client.restart(namespace, name, WorkloadKind.DAEMONSET, request)


def make_workload_client(api: _AppsV1Api, serializer: _KubernetesSerializer, *, timeout: float = 60.0) -> WorkloadClient:
    base = KubernetesApiWorkloadClient(api, serializer, timeout=timeout)
    client = _KubernetesWorkloadClient(_DeploymentAdapter(base), _DaemonSetAdapter(base))
    return cast(WorkloadClient, client)


# ---------------------------------------------------------------------------
# Restart action derivation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RestartAction:
    action_id: str
    workload: WorkloadRef
    caused_by_locations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.caused_by_locations:
            raise ValueError("A restart action must retain its causal locations.")


def _wave_for_target(transaction: RotationTransaction, target: Identity) -> PropagationWave:
    if target is Identity.BREAKGLASS:
        return transaction.propagation.to_b
    return transaction.propagation.to_a


def _action_id(workload: WorkloadRef) -> str:
    """Derive a stable, schema-valid action ID for a workload restart.

    The durable ``RuntimeActionProgress.action_id`` field is constrained to
    ``[A-Za-z0-9_.-]+`` (see ``state.py`` ``_identifier``), so the workload
    ``kind/name`` label is encoded as ``kind_name`` to keep it valid while
    remaining deterministic and schema-valid.
    """
    return f"{workload.kind.value}_{workload.name}"


def restart_request_for(wave: PropagationWave) -> str:
    """Derive the durable restart-request marker for one propagation wave.

    The marker is written to the workload Pod template as the
    ``kubectl.kubernetes.io/restartedAt`` annotation value.  It must be
    recoverable by a replacement execution from durable state alone, so it is
    derived deterministically from the wave's immutable intent rather than an
    opaque caller-supplied string:

    - stable across recovery of the same restart wave (the intent is immutable);
    - different between logically separate to-B and to-A restart waves (each
      carries its own target identity, generation, and contract digest);
    - safe to place in a Kubernetes annotation (bounded string, lowercase
      alphanumerics, digits and hyphens);
    - contains no credential material.

    The marker is a compact SHA-256 digest of the full identifying tuple
    (target identity, target generation, contract digest), prefixed with
    ``genestack-`` for recognizability.  Every declared input contributes to
    the final marker, avoiding the truncation problem of a concatenated
    prefix.
    """
    intent = wave.intent
    if intent is None:
        raise RestartExecutionError(RestartExecutionErrorCode.NO_WAVE_INTENT)
    identifying = (
        f"{intent.target_identity.value}|"
        f"{intent.target_generation.value}|"
        f"{intent.contract_digest.value}"
    )
    digest = hashlib.sha256(identifying.encode("utf-8")).hexdigest()
    return f"genestack-{digest}"


def derive_restart_actions(
    contract: CredentialContract, transaction: RotationTransaction, *, target: Identity,
) -> tuple[RestartAction, ...]:
    """Derive deduplicated restart actions from durable changed-location accounting.

    Consumes the wave's durable ``applied_location_ids`` (the changed set from
    Slice 4C) and the contract's restart edges.  An empty ``restart`` list
    produces no action.  Multiple changed locations naming the same workload
    yield one action.  No credential values are involved.
    """
    wave = _wave_for_target(transaction, target)
    intent = wave.intent
    if intent is None:
        raise RestartExecutionError(RestartExecutionErrorCode.NO_WAVE_INTENT)
    if intent.target_identity is not target:
        raise RestartExecutionError(RestartExecutionErrorCode.INTENT_MISMATCH)
    generation = (
        transaction.new_b_sha256 if target is Identity.BREAKGLASS
        else transaction.new_a_sha256
    )
    if generation is None or generation != intent.target_generation:
        raise RestartExecutionError(RestartExecutionErrorCode.INTENT_MISMATCH)
    # Validate the current contract against the durable wave contract digest.
    # Restart debt depends on the contract's restart edges; a contract that
    # retains the same location IDs while changing restart edges would silently
    # derive different debt.  Fail closed on any drift.
    if propagation_contract_digest(contract) != intent.contract_digest:
        raise RestartExecutionError(RestartExecutionErrorCode.CONTRACT_DRIFT)
    contract_locations = {item.name: item for item in contract.locations}
    intent_ids = {
        location.location_id
        for group in intent.secret_groups
        for location in group.locations
    }
    changed = set(wave.applied_location_ids)
    if not changed <= intent_ids:
        raise RestartExecutionError(RestartExecutionErrorCode.INTENT_MISMATCH)
    for location_id in changed:
        if location_id not in contract_locations:
            raise RestartExecutionError(RestartExecutionErrorCode.CONTRACT_DRIFT)

    causal: dict[WorkloadRef, set[str]] = {}
    for location_id in sorted(changed):
        for workload in contract_locations[location_id].restart:
            causal.setdefault(workload, set()).add(location_id)

    return tuple(
        RestartAction(
            action_id=_action_id(workload),
            workload=workload,
            caused_by_locations=tuple(sorted(causal[workload])),
        )
        for workload in sorted(causal, key=lambda item: item.label)
    )


# ---------------------------------------------------------------------------
# Session and progress helpers
# ---------------------------------------------------------------------------

def _assert_owned(ownership: OwnershipGuard) -> None:
    try:
        ownership.assert_owned()
    except SafeError:
        raise RestartExecutionError(RestartExecutionErrorCode.OWNERSHIP_LOST) from None


def _replace_wave_for_target(
    transaction: RotationTransaction, target: Identity, wave: PropagationWave,
) -> RotationTransaction:
    propagation: PropagationState
    if target is Identity.BREAKGLASS:
        propagation = replace(transaction.propagation, to_b=wave)
    else:
        propagation = replace(transaction.propagation, to_a=wave)
    return replace(transaction, propagation=propagation)


class RestartSession:
    """Mutable session over the state store during restart execution.

    The session pairs the state store with the current execution ownership
    guard: every correctness-relevant durable write reasserts ownership
    immediately before it is issued, the same discipline Slice 4C applies to
    its progress writes.
    """

    def __init__(
        self, store: StateStore, persisted: PersistedState, ownership: OwnershipGuard,
    ) -> None:
        self.store = store
        self.persisted = persisted
        self.ownership = ownership

    @property
    def transaction(self) -> RotationTransaction:
        result = self.persisted.state.current_transaction
        if result is None:
            raise RestartExecutionError(RestartExecutionErrorCode.NO_TRANSACTION)
        return result

    def write_wave(self, target: Identity, wave: PropagationWave, now: datetime) -> PropagationWave:
        _assert_owned(self.ownership)
        transaction = _replace_wave_for_target(self.transaction, target, wave)
        transaction = replace(transaction, updated_at=now)
        try:
            self.persisted = self.store.update(
                self.persisted.revision,
                replace(self.persisted.state, current_transaction=transaction),
            )
        except StateStoreError:
            raise RestartExecutionError(
                RestartExecutionErrorCode.PROGRESS_PERSISTENCE_FAILED,
            ) from None
        return self.transaction.propagation.to_b if target is Identity.BREAKGLASS \
            else self.transaction.propagation.to_a


def _set_action_state(
    session: RestartSession, *, target: Identity, wave: PropagationWave,
    action_id: str, state: RuntimeActionState, now: datetime,
) -> PropagationWave:
    updated = tuple(
        RuntimeActionProgress(item.action_id, state) if item.action_id == action_id
        else item
        for item in wave.runtime_actions
    )
    new_wave = replace(wave, runtime_actions=updated)
    session.write_wave(target, new_wave, now)
    return new_wave


# ---------------------------------------------------------------------------
# Execution engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RestartExecutionResult:
    actions: tuple[RestartAction, ...]
    completed: tuple[str, ...]
    outstanding: tuple[str, ...]
    wave: PropagationWave
    persisted: PersistedState

    @property
    def all_complete(self) -> bool:
        return not self.outstanding


def _observe_workload(client: WorkloadClient, workload: WorkloadRef) -> WorkloadSnapshot:
    try:
        return _client_for_kind(client, workload.kind).read("openstack", workload.name)
    except WorkloadClientError as exc:
        if exc.kind is WorkloadClientErrorCode.NOT_FOUND:
            raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_MISSING) from None
        if exc.kind is WorkloadClientErrorCode.INVALID:
            raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_INVALID) from None
        raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_READ_FAILED) from None


def _dispatch_restart(
    client: WorkloadClient, workload: WorkloadRef, request: str,
) -> WorkloadSnapshot:
    try:
        return _client_for_kind(client, workload.kind).restart("openstack", workload.name, request)
    except WorkloadClientError as exc:
        if exc.kind is WorkloadClientErrorCode.NOT_FOUND:
            raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_MISSING) from None
        if exc.kind is WorkloadClientErrorCode.INVALID:
            raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_INVALID) from None
        if exc.kind is WorkloadClientErrorCode.READ_FAILED:
            raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_READ_FAILED) from None
        raise RestartExecutionError(RestartExecutionErrorCode.WORKLOAD_MUTATION_FAILED) from None


def _wait_rollout(
    client: WorkloadClient, workload: WorkloadRef, *, request: str,
    poll_interval: float, deadline: float,
    sleeper: Callable[[float], None],
) -> WorkloadSnapshot:
    """Bounded polling wait for the workload rollout to complete.

    A successful restart request is not sufficient; the observed snapshot must
    show the controller has observed the new Pod-template generation, the
    matching restart marker, and the replacement/rollout converged.  The poll
    interval and deadline are small and explicit.
    """
    if not math.isfinite(poll_interval) or not 0 < poll_interval <= 60:
        raise ValueError("Poll interval must be finite, positive, and at most 60 seconds.")
    if not math.isfinite(deadline) or not 0 < deadline <= 3600:
        raise ValueError("Deadline must be finite, positive, and at most 3600 seconds.")
    start = time.monotonic()
    while True:
        snapshot = _observe_workload(client, workload)
        if snapshot.complete(restart_requested=request):
            return snapshot
        if snapshot.rollout_status is RolloutStatus.FAILED:
            raise RestartExecutionError(RestartExecutionErrorCode.ROLLOUT_FAILED)
        remaining = deadline - (time.monotonic() - start)
        if remaining <= 0:
            raise RestartExecutionError(RestartExecutionErrorCode.ROLLOUT_TIMEOUT)
        sleeper(min(poll_interval, remaining))


def _ensure_actions(
    session: RestartSession, *, actions: tuple[RestartAction, ...],
    target: Identity, now: datetime,
) -> PropagationWave:
    """Persist any missing action records in one deterministic batch write.

    Also validates that every existing durable runtime action ID belongs to
    the derived action set.  An unexpected durable action ID indicates stale
    or inconsistent state and fails closed rather than remaining unreachable.
    """
    wave = _wave_for_target(session.transaction, target)
    derived_ids = {action.action_id for action in actions}
    existing = {item.action_id for item in wave.runtime_actions}
    unexpected = existing - derived_ids
    if unexpected:
        raise RestartExecutionError(RestartExecutionErrorCode.STALE_RUNTIME_ACTIONS)
    missing = [action for action in actions if action.action_id not in existing]
    if not missing:
        return wave
    updated: list[RuntimeActionProgress] = [
        item for item in wave.runtime_actions
        if item.action_id not in {action.action_id for action in missing}
    ]
    updated.extend(
        RuntimeActionProgress(action.action_id, RuntimeActionState.PENDING)
        for action in missing
    )
    updated.sort(key=lambda item: item.action_id)
    return session.write_wave(target, replace(wave, runtime_actions=tuple(updated)), now)


def execute_restart_debt(
    client: WorkloadClient,
    store: StateStore,
    ownership: OwnershipGuard,
    *,
    contract: CredentialContract,
    target: Identity,
    now: datetime,
    request: str | None = None,
    poll_interval: float = 5.0,
    deadline: float = 600.0,
    sleeper: Callable[[float], None] | None = None,
) -> RestartExecutionResult:
    """Execute and recover outstanding restart debt for one propagation wave.

    Derives actions from durable changed-location accounting (validating the
    contract digest against the wave intent), persists any missing action
    records, dispatches each outstanding restart through the Kubernetes API,
    observes the rollout to completion, and persists progress after each
    verified step.

    Ownership sequence around dispatch:

    1. Assert ownership at entry.
    2. Persist RUNNING (the state-store write fences ownership internally).
    3. Reassert ownership immediately before the external Kubernetes mutation.
    4. Dispatch the restart.
    5. Observe the rollout to completion.
    6. Persist COMPLETE (fenced by ownership).

    Recovery after interruption re-observes Kubernetes state rather than
    trusting the last attempted action.  No credential mutation is performed.

    ``request`` is the restart marker written to the workload Pod template.
    It defaults to the deterministic marker derived from the durable wave intent
    (see :func:`restart_request_for`), so a replacement execution recovers the
    same marker without depending on the caller reconstructing an opaque value.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Restart execution clock must return a timezone-aware value.")
    _assert_owned(ownership)
    try:
        persisted = store.load()
    except StateStoreError:
        raise RestartExecutionError(
            RestartExecutionErrorCode.PROGRESS_PERSISTENCE_FAILED,
        ) from None
    session = RestartSession(store, persisted, ownership)
    transaction = session.transaction
    actions = derive_restart_actions(contract, transaction, target=target)
    wave = _ensure_actions(session, actions=actions, target=target, now=now)
    marker = request if request is not None else restart_request_for(wave)

    completed: list[str] = []
    for action in actions:
        record = next(
            item for item in wave.runtime_actions if item.action_id == action.action_id
        )
        if record.state is RuntimeActionState.COMPLETE:
            # A durable COMPLETE is a discharged obligation for this
            # transaction: it was written only after a successful rollout
            # observation, so it is not re-observed or re-dispatched.
            completed.append(action.action_id)
            continue
        # PENDING/RUNNING: re-observe workload reality before dispatching or
        # confirming: a prior dispatch may have already succeeded and rolled out.
        snapshot = _observe_workload(client, action.workload)
        if snapshot.complete(restart_requested=marker):
            wave = _set_action_state(
                session, target=target, wave=wave,
                action_id=action.action_id, state=RuntimeActionState.COMPLETE, now=now,
            )
            completed.append(action.action_id)
            continue
        # Dispatch: persist RUNNING first (the write itself fences ownership),
        # then reassert ownership immediately before the external mutation.
        wave = _set_action_state(
            session, target=target, wave=wave,
            action_id=action.action_id, state=RuntimeActionState.RUNNING, now=now,
        )
        _assert_owned(ownership)
        _dispatch_restart(client, action.workload, marker)
        observed = _wait_rollout(
            client, action.workload, request=marker,
            poll_interval=poll_interval, deadline=deadline,
            sleeper=sleeper or time.sleep,
        )
        if not observed.complete(restart_requested=marker):
            raise RestartExecutionError(RestartExecutionErrorCode.ROLLOUT_FAILED)
        wave = _set_action_state(
            session, target=target, wave=wave,
            action_id=action.action_id, state=RuntimeActionState.COMPLETE, now=now,
        )
        completed.append(action.action_id)

    all_actions = tuple(item.action_id for item in wave.runtime_actions)
    outstanding = tuple(sorted(set(all_actions) - set(completed)))
    return RestartExecutionResult(
        actions=actions,
        completed=tuple(sorted(completed)),
        outstanding=outstanding,
        wave=wave,
        persisted=session.persisted,
    )
