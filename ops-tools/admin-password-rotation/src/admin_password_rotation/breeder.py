"""Conditional direct-Kubernetes boundary for the canonical A breeder Secret."""
from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Self, cast, runtime_checkable
from uuid import UUID

from .errors import ReadError, SafeError
from .kubernetes import parse_inventory
from .kubernetes_api import create_kubernetes_api, validate_api_options
from .model import (
    CredentialGeneration, SecretAnnotation, SecretField, SecretSnapshot, SecretValue,
)
from .validation import is_object_name


PROVENANCE_TRANSACTION = "rotation.genestack.org/transaction-id"
PROVENANCE_GENERATION = "rotation.genestack.org/new-admin-sha256"
PROVENANCE_STAGE = "rotation.genestack.org/stage"
PROVENANCE_STAGE_PENDING_KEYSTONE = "pending-keystone"


@dataclass(frozen=True)
class BreederReference:
    namespace: str = "openstack"
    name: str = "keystone-admin"

    def __post_init__(self) -> None:
        if not is_object_name(self.namespace) or not is_object_name(self.name):
            raise ValueError("Breeder namespace and name must be valid Kubernetes names.")


@dataclass(frozen=True)
class BreederProvenance:
    transaction_id: UUID
    generation: CredentialGeneration
    stage: str = PROVENANCE_STAGE_PENDING_KEYSTONE

    def __post_init__(self) -> None:
        if self.stage != PROVENANCE_STAGE_PENDING_KEYSTONE:
            raise ValueError("Unsupported breeder provenance stage.")

    def annotations(self) -> tuple[SecretAnnotation, ...]:
        return (
            SecretAnnotation(PROVENANCE_TRANSACTION, str(self.transaction_id)),
            SecretAnnotation(PROVENANCE_GENERATION, self.generation.value),
            SecretAnnotation(PROVENANCE_STAGE, self.stage),
        )

    def matches(self, secret: SecretSnapshot) -> bool:
        return all(secret.annotation(item.key) == item.value for item in self.annotations())


class BreederErrorCode(Enum):
    NOT_FOUND = "breeder_not_found"
    INVALID = "breeder_invalid"
    READ_FAILED = "breeder_read_failed"
    CONDITIONAL_REJECTED = "breeder_conditional_rejected"
    OUTCOME_AMBIGUOUS = "breeder_outcome_ambiguous"
    FAILURE = "breeder_mutation_failed"


_ERROR_MESSAGES = {
    kind: "The canonical breeder operation cannot be completed safely; details withheld."
    for kind in BreederErrorCode
}


class BreederError(SafeError):
    def __init__(self, kind: BreederErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


class BreederSecretClient(Protocol):
    def read(self, reference: BreederReference) -> SecretSnapshot: ...

    def conditional_stage(
        self, expected: SecretSnapshot, *, password: SecretValue,
        provenance: BreederProvenance,
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
    resource: object, serializer: _KubernetesSerializer, reference: BreederReference,
) -> SecretSnapshot:
    try:
        normalized = serializer.sanitize_for_serialization(resource)
        inventory = parse_inventory(json.dumps({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": {"resourceVersion": "single-object-read"},
            "items": [normalized],
        }).encode("utf-8"), reference.namespace)
    except (ReadError, TypeError, ValueError, UnicodeError):
        raise BreederError(BreederErrorCode.INVALID) from None
    if len(inventory.secrets) != 1 or inventory.secrets[0].name != reference.name:
        raise BreederError(BreederErrorCode.INVALID)
    return inventory.secrets[0]


class KubernetesApiBreederSecretClient:
    """Narrow GET plus UID/resourceVersion-conditional JSON Patch client."""

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
            raise BreederError(BreederErrorCode.READ_FAILED) from None
        return cls(
            cast(_CoreV1SecretApi, handle.api),
            cast(_KubernetesSerializer, handle.serializer),
            timeout=timeout,
        )

    def read(self, reference: BreederReference) -> SecretSnapshot:
        try:
            resource = self._api.read_namespaced_secret(
                reference.name, reference.namespace,
                _request_timeout=self._timeout,
            )
        except Exception as exc:
            kind = (
                BreederErrorCode.NOT_FOUND
                if _http_status(exc) == 404
                else BreederErrorCode.READ_FAILED
            )
            raise BreederError(kind) from None
        return _snapshot(resource, self._serializer, reference)

    def conditional_stage(
        self, expected: SecretSnapshot, *, password: SecretValue,
        provenance: BreederProvenance,
    ) -> None:
        encoded = base64.b64encode(password.reveal()).decode("ascii")
        patch: list[dict[str, object]] = [
            {"op": "test", "path": "/metadata/uid", "value": expected.uid},
            {
                "op": "test", "path": "/metadata/resourceVersion",
                "value": expected.resource_version,
            },
            {"op": "replace", "path": "/data/password", "value": encoded},
        ]
        current_keys = {item.key for item in expected.annotations}
        if not current_keys:
            patch.append({"op": "add", "path": "/metadata/annotations", "value": {}})
        for item in provenance.annotations():
            patch.append({
                "op": "replace" if item.key in current_keys else "add",
                "path": f"/metadata/annotations/{_pointer(item.key)}",
                "value": item.value,
            })
        try:
            self._api.patch_namespaced_secret(
                expected.name, expected.namespace, patch,
                _content_type="application/json-patch+json",
                _request_timeout=self._timeout,
            )
        except Exception as exc:
            status = _http_status(exc)
            if status in (409, 412, 422):
                kind = BreederErrorCode.CONDITIONAL_REJECTED
            elif status is None or status == 429 or status >= 500:
                kind = BreederErrorCode.OUTCOME_AMBIGUOUS
            else:
                kind = BreederErrorCode.FAILURE
            raise BreederError(kind) from None


class FakeBreederSecretClient:
    """Behavioral fake preserving all unrelated Secret fields and annotations."""

    def __init__(self, snapshot: SecretSnapshot) -> None:
        self.snapshot = snapshot
        self.read_error: BreederErrorCode | None = None
        self.next_mutation_error: BreederErrorCode | None = None
        self.ambiguous_next_stage_apply: bool | None = None
        self.before_stage: Callable[[FakeBreederSecretClient], None] | None = None
        self.read_calls = 0
        self.stage_calls = 0

    def read(self, reference: BreederReference) -> SecretSnapshot:
        self.read_calls += 1
        if self.read_error is not None:
            raise BreederError(self.read_error)
        if (
            self.snapshot.namespace != reference.namespace
            or self.snapshot.name != reference.name
        ):
            raise BreederError(BreederErrorCode.NOT_FOUND)
        return self.snapshot

    def conditional_stage(
        self, expected: SecretSnapshot, *, password: SecretValue,
        provenance: BreederProvenance,
    ) -> None:
        self.stage_calls += 1
        if self.before_stage is not None:
            callback = self.before_stage
            self.before_stage = None
            callback(self)
        if self.next_mutation_error is not None:
            kind = self.next_mutation_error
            self.next_mutation_error = None
            raise BreederError(kind)
        if (
            self.snapshot.uid != expected.uid
            or self.snapshot.resource_version != expected.resource_version
        ):
            raise BreederError(BreederErrorCode.CONDITIONAL_REJECTED)
        apply = self.ambiguous_next_stage_apply
        if apply is not None:
            self.ambiguous_next_stage_apply = None
        if apply is None or apply:
            retained = tuple(item for item in self.snapshot.data if item.key != "password")
            provenance_keys = {item.key for item in provenance.annotations()}
            annotations = tuple(
                item for item in self.snapshot.annotations if item.key not in provenance_keys
            ) + provenance.annotations()
            self.snapshot = replace(
                self.snapshot,
                resource_version=str(int(self.snapshot.resource_version) + 1),
                data=(*retained, SecretField("password", password)),
                annotations=annotations,
            )
        if apply is not None:
            raise BreederError(BreederErrorCode.OUTCOME_AMBIGUOUS)
