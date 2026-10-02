"""Kubernetes persistence boundary for schema-v2 durable transaction state.

The state Secret is infrastructure supplied by deployment tooling. This module
never creates it and changes only its existing ``data/state.json`` entry.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from .errors import ReadError, SafeError
from .model import PersistentState
from .state import parse_state_json, serialize_state_json
from .validation import is_object_name, object_mapping

MAX_STATE_SECRET_BYTES = 2 * 1024 * 1024
STATE_DATA_KEY = "state.json"


class StateStoreErrorCode(Enum):
    SECRET_MISSING = "state_secret_missing"
    STATE_KEY_MISSING = "state_key_missing"
    UID_MISSING = "state_secret_uid_missing"
    RESOURCE_VERSION_MISSING = "state_secret_resource_version_missing"
    SECRET_INVALID = "state_secret_invalid"
    STATE_INVALID = "state_invalid"
    IDENTITY_CHANGED = "state_secret_identity_changed"
    CONFLICT = "state_write_conflict"
    WRITE_AMBIGUOUS = "state_write_ambiguous"
    READ_AFTER_WRITE_MISMATCH = "state_read_after_write_mismatch"
    KUBERNETES_FAILURE = "state_kubernetes_failure"


_ERROR_MESSAGES: dict[StateStoreErrorCode, str] = {
    StateStoreErrorCode.SECRET_MISSING: "The configured state Secret does not exist.",
    StateStoreErrorCode.STATE_KEY_MISSING: "The state Secret does not contain the configured state key.",
    StateStoreErrorCode.UID_MISSING: "The state Secret has no stable UID.",
    StateStoreErrorCode.RESOURCE_VERSION_MISSING: "The state Secret has no resourceVersion.",
    StateStoreErrorCode.SECRET_INVALID: "The Kubernetes state Secret response is invalid; content withheld.",
    StateStoreErrorCode.STATE_INVALID: "The persisted transaction state is invalid; content withheld.",
    StateStoreErrorCode.IDENTITY_CHANGED: "The observed state Secret object identity changed.",
    StateStoreErrorCode.CONFLICT: "The persisted state changed after it was observed; reobserve before retrying.",
    StateStoreErrorCode.WRITE_AMBIGUOUS: "The state write outcome cannot be verified; reobserve before continuing.",
    StateStoreErrorCode.READ_AFTER_WRITE_MISMATCH: "The state observed after writing does not match the intended state.",
    StateStoreErrorCode.KUBERNETES_FAILURE: "The Kubernetes state persistence operation failed; output withheld.",
}


class StateStoreError(SafeError):
    """A secret-safe persistence failure with a stable operational category."""

    def __init__(self, kind: StateStoreErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value, _ERROR_MESSAGES[kind])


@dataclass(frozen=True)
class StateSecretReference:
    namespace: str
    name: str

    def __post_init__(self) -> None:
        if not is_object_name(self.namespace) or not is_object_name(self.name):
            raise ValueError("State Secret namespace and name must be valid Kubernetes object names.")

    @property
    def data_key(self) -> str:
        return STATE_DATA_KEY


@dataclass(frozen=True)
class StateRevision:
    namespace: str
    name: str
    uid: str
    resource_version: str

    def __post_init__(self) -> None:
        if not is_object_name(self.namespace) or not is_object_name(self.name):
            raise ValueError("State revision namespace and name must be valid Kubernetes object names.")
        if not self.uid or not self.resource_version:
            raise ValueError("State revision UID and resourceVersion must be nonempty.")


@dataclass(frozen=True)
class PersistedState:
    state: PersistentState
    revision: StateRevision


class StateStore(Protocol):
    def load(self) -> PersistedState: ...

    def update(self, expected: StateRevision, new_state: PersistentState) -> PersistedState: ...


class StateSecretTransportErrorCode(Enum):
    NOT_FOUND = "not_found"
    CONDITIONAL_REJECTED = "conditional_rejected"
    OUTCOME_AMBIGUOUS = "outcome_ambiguous"
    FAILURE = "failure"


class StateSecretTransportError(Exception):
    """Value-free error contract between a Kubernetes transport and the store."""

    def __init__(self, kind: StateSecretTransportErrorCode) -> None:
        self.kind = kind
        super().__init__(kind.value)


class StateSecretTransport(Protocol):
    def read(self, reference: StateSecretReference) -> bytes: ...

    def conditional_replace(
        self, expected: StateRevision, *, encoded_state: str,
    ) -> None: ...


@dataclass(frozen=True)
class StateCommandResult:
    returncode: int
    stdout: bytes


class StateCommandRunner(Protocol):
    def run(
        self, argv: tuple[str, ...], timeout: float, stdin: bytes | None,
    ) -> StateCommandResult: ...


class _CommandTimeout(Exception):
    pass


class _CommandUnavailable(Exception):
    pass


class SubprocessStateCommandRunner:
    """Run only commands assembled by ``KubectlStateSecretTransport``."""

    def run(
        self, argv: tuple[str, ...], timeout: float, stdin: bytes | None,
    ) -> StateCommandResult:
        try:
            if stdin is None:
                result = subprocess.run(
                    argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=timeout, check=False, shell=False,
                )
            else:
                result = subprocess.run(
                    argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout, check=False, shell=False,
                )
        except subprocess.TimeoutExpired:
            raise _CommandTimeout from None
        except OSError:
            raise _CommandUnavailable from None
        return StateCommandResult(result.returncode, result.stdout)


class KubectlStateSecretTransport:
    """Narrow kubectl transport for one Secret GET and conditional JSON Patch."""

    def __init__(
        self, *, context: str, kubeconfig: Path | None = None,
        timeout: float = 60.0, runner: StateCommandRunner | None = None,
    ) -> None:
        if not context or context.startswith("-") or any(ord(char) < 32 for char in context):
            raise ReadError("invalid_context", "An explicit valid kubeconfig context is required.")
        if not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ReadError("invalid_timeout", "Timeout must be finite, positive, and at most 3600 seconds.")
        self._context = context
        self._kubeconfig = kubeconfig
        self._timeout = timeout
        self._runner = runner if runner is not None else SubprocessStateCommandRunner()

    def _prefix(self, namespace: str) -> list[str]:
        argv = ["kubectl", f"--context={self._context}"]
        if self._kubeconfig is not None:
            argv.append(f"--kubeconfig={self._kubeconfig}")
        argv.extend([f"--namespace={namespace}", f"--request-timeout={self._timeout:g}s"])
        return argv

    def read(self, reference: StateSecretReference) -> bytes:
        argv = self._prefix(reference.namespace)
        argv.extend([
            "get", "secret", reference.name, "--output=json", "--ignore-not-found",
        ])
        try:
            result = self._runner.run(tuple(argv), self._timeout, None)
        except (_CommandTimeout, _CommandUnavailable):
            raise StateSecretTransportError(StateSecretTransportErrorCode.FAILURE) from None
        if result.returncode != 0:
            raise StateSecretTransportError(StateSecretTransportErrorCode.FAILURE)
        if not result.stdout.strip():
            raise StateSecretTransportError(StateSecretTransportErrorCode.NOT_FOUND)
        return result.stdout

    def conditional_replace(
        self, expected: StateRevision, *, encoded_state: str,
    ) -> None:
        # JSON Patch test operations make UID and resourceVersion preconditions
        # atomic with replacement of the one existing data entry.
        patch: list[dict[str, str]] = [
            {"op": "test", "path": "/metadata/uid", "value": expected.uid},
            {
                "op": "test", "path": "/metadata/resourceVersion",
                "value": expected.resource_version,
            },
            {"op": "replace", "path": f"/data/{STATE_DATA_KEY}", "value": encoded_state},
        ]
        payload = json.dumps(patch, separators=(",", ":"), sort_keys=True).encode("utf-8")
        argv = self._prefix(expected.namespace)
        argv.extend([
            "patch", "secret", expected.name, "--type=json", "--patch-file=-", "--output=name",
        ])
        try:
            result = self._runner.run(tuple(argv), self._timeout, payload)
        except _CommandTimeout:
            raise StateSecretTransportError(StateSecretTransportErrorCode.OUTCOME_AMBIGUOUS) from None
        except _CommandUnavailable:
            raise StateSecretTransportError(StateSecretTransportErrorCode.FAILURE) from None
        if result.returncode != 0:
            raise StateSecretTransportError(StateSecretTransportErrorCode.CONDITIONAL_REJECTED)


@dataclass(frozen=True)
class _StateSecretResource:
    revision: StateRevision
    encoded_state: str | None


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StateStoreError(StateStoreErrorCode.SECRET_INVALID)
        result[key] = value
    return result


def _parse_secret_resource(
    raw: bytes, reference: StateSecretReference,
) -> _StateSecretResource:
    if len(raw) > MAX_STATE_SECRET_BYTES:
        raise StateStoreError(StateStoreErrorCode.SECRET_INVALID)
    try:
        value: object = json.loads(raw, object_pairs_hook=_json_pairs)
        root = object_mapping(value)
        if root.get("apiVersion") != "v1" or root.get("kind") != "Secret":
            raise StateStoreError(StateStoreErrorCode.SECRET_INVALID)
        metadata = object_mapping(root.get("metadata"))
        if metadata.get("namespace") != reference.namespace or metadata.get("name") != reference.name:
            raise StateStoreError(StateStoreErrorCode.SECRET_INVALID)
        uid_value = metadata.get("uid")
        if not isinstance(uid_value, str) or not uid_value:
            raise StateStoreError(StateStoreErrorCode.UID_MISSING)
        resource_version_value = metadata.get("resourceVersion")
        if not isinstance(resource_version_value, str) or not resource_version_value:
            raise StateStoreError(StateStoreErrorCode.RESOURCE_VERSION_MISSING)
        data_value = root.get("data")
        data = {} if data_value is None else object_mapping(data_value)
        if reference.data_key not in data:
            encoded_value: str | None = None
        else:
            state_value = data[reference.data_key]
            if not isinstance(state_value, str):
                raise StateStoreError(StateStoreErrorCode.STATE_INVALID)
            encoded_value = state_value
        return _StateSecretResource(
            StateRevision(
                reference.namespace, reference.name, uid_value, resource_version_value,
            ),
            encoded_value,
        )
    except StateStoreError:
        raise
    except (ReadError, ValueError, UnicodeError, RecursionError):
        raise StateStoreError(StateStoreErrorCode.SECRET_INVALID) from None


class KubernetesStateStore:
    """Load and conditionally replace schema-v2 state in a precreated Secret."""

    def __init__(
        self, reference: StateSecretReference, transport: StateSecretTransport,
    ) -> None:
        self._reference = reference
        self._transport = transport

    def _read_resource(self) -> _StateSecretResource:
        try:
            raw = self._transport.read(self._reference)
        except StateSecretTransportError as exc:
            if exc.kind is StateSecretTransportErrorCode.NOT_FOUND:
                raise StateStoreError(StateStoreErrorCode.SECRET_MISSING) from None
            raise StateStoreError(StateStoreErrorCode.KUBERNETES_FAILURE) from None
        return _parse_secret_resource(raw, self._reference)

    @staticmethod
    def _decode_state(resource: _StateSecretResource) -> PersistentState:
        if resource.encoded_state is None:
            raise StateStoreError(StateStoreErrorCode.STATE_KEY_MISSING)
        try:
            decoded = base64.b64decode(resource.encoded_state, validate=True)
            text = decoded.decode("utf-8")
            return parse_state_json(text)
        except (binascii.Error, UnicodeError, ReadError, ValueError):
            raise StateStoreError(StateStoreErrorCode.STATE_INVALID) from None

    def load(self) -> PersistedState:
        resource = self._read_resource()
        return PersistedState(self._decode_state(resource), resource.revision)

    def _classify_rejected_write(self, expected: StateRevision) -> StateStoreError:
        try:
            resource = self._read_resource()
        except StateStoreError as exc:
            if exc.kind is StateStoreErrorCode.SECRET_MISSING:
                return StateStoreError(StateStoreErrorCode.IDENTITY_CHANGED)
            return StateStoreError(StateStoreErrorCode.KUBERNETES_FAILURE)
        if resource.revision.uid != expected.uid:
            return StateStoreError(StateStoreErrorCode.IDENTITY_CHANGED)
        if resource.revision.resource_version != expected.resource_version:
            return StateStoreError(StateStoreErrorCode.CONFLICT)
        return StateStoreError(StateStoreErrorCode.KUBERNETES_FAILURE)

    def update(
        self, expected: StateRevision, new_state: PersistentState,
    ) -> PersistedState:
        if expected.namespace != self._reference.namespace or expected.name != self._reference.name:
            raise StateStoreError(StateStoreErrorCode.IDENTITY_CHANGED)
        try:
            serialized = serialize_state_json(new_state)
        except (ReadError, ValueError):
            raise StateStoreError(StateStoreErrorCode.STATE_INVALID) from None
        encoded = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
        try:
            self._transport.conditional_replace(
                expected, encoded_state=encoded,
            )
        except StateSecretTransportError as exc:
            if exc.kind is StateSecretTransportErrorCode.CONDITIONAL_REJECTED:
                raise self._classify_rejected_write(expected) from None
            if exc.kind is StateSecretTransportErrorCode.OUTCOME_AMBIGUOUS:
                raise StateStoreError(StateStoreErrorCode.WRITE_AMBIGUOUS) from None
            raise StateStoreError(StateStoreErrorCode.KUBERNETES_FAILURE) from None

        try:
            observed_resource = self._read_resource()
        except StateStoreError:
            raise StateStoreError(StateStoreErrorCode.WRITE_AMBIGUOUS) from None
        if observed_resource.revision.uid != expected.uid:
            raise StateStoreError(StateStoreErrorCode.IDENTITY_CHANGED)
        try:
            observed_state = self._decode_state(observed_resource)
        except StateStoreError:
            raise StateStoreError(StateStoreErrorCode.READ_AFTER_WRITE_MISMATCH) from None
        if observed_state != new_state:
            raise StateStoreError(StateStoreErrorCode.READ_AFTER_WRITE_MISMATCH)
        if observed_resource.revision.resource_version == expected.resource_version:
            raise StateStoreError(StateStoreErrorCode.WRITE_AMBIGUOUS)
        return PersistedState(observed_state, observed_resource.revision)
