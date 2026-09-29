"""Read-only kubectl adapter and identical JSON boundary for offline fixtures.

The adapter has no arbitrary command method. Live use requires explicit opt-in
and a named context. Only `get secrets -o json` is issued; authentication plugins
in a trusted kubeconfig may still have their own local side effects.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import subprocess
from pathlib import Path
from typing import Protocol

from .errors import ReadError
from .model import SecretField, SecretInventory, SecretSnapshot, SecretValue
from .validation import is_identifier, is_object_name, nonempty_string, object_list, object_mapping

MAX_INVENTORY_BYTES = 128 * 1024 * 1024


class KubernetesReader(Protocol):
    def list_secrets(self, namespace: str) -> SecretInventory: ...


class CommandRunner(Protocol):
    def run(self, argv: tuple[str, ...], timeout: float) -> bytes: ...


class SubprocessRunner:
    def run(self, argv: tuple[str, ...], timeout: float) -> bytes:
        try:
            result = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout, check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            raise ReadError("kubernetes_timeout", "Kubernetes read timed out; captured output withheld.") from None
        except OSError:
            raise ReadError("kubectl_unavailable", "Cannot execute kubectl.") from None
        if result.returncode != 0:
            raise ReadError("kubernetes_read", "kubectl failed; raw output withheld. Check context, connectivity and Secret list permission.")
        return result.stdout


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReadError("duplicate_json_key", "Duplicate JSON key; input withheld.")
        result[key] = value
    return result


def parse_inventory(raw: bytes, namespace: str) -> SecretInventory:
    if len(raw) > MAX_INVENTORY_BYTES:
        raise ReadError("inventory_too_large", "Secret inventory exceeds the input limit.")
    try:
        value: object = json.loads(raw, object_pairs_hook=_json_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ReadError("invalid_json", "Secret inventory is not valid JSON; input withheld.") from None
    root = object_mapping(value)
    if root.get("apiVersion") != "v1" or root.get("kind") not in ("SecretList", "List"):
        raise ReadError("invalid_inventory", "Expected a v1 SecretList or List.")
    metadata = object_mapping(root.get("metadata"))
    if metadata.get("continue") not in (None, ""):
        raise ReadError("incomplete_inventory", "A paginated Secret inventory must be fully collected.")
    resource_version = nonempty_string(metadata.get("resourceVersion"))
    result: list[SecretSnapshot] = []
    names: set[str] = set()
    for item in object_list(root.get("items")):
        obj = object_mapping(item)
        if obj.get("apiVersion") != "v1" or obj.get("kind") != "Secret":
            raise ReadError("invalid_secret", "Inventory contains a non-Secret object.")
        meta = object_mapping(obj.get("metadata"))
        name = nonempty_string(meta.get("name"))
        if not is_object_name(name):
            raise ReadError("invalid_secret_name", "Inventory contains an invalid Secret name.")
        if meta.get("namespace") != namespace:
            raise ReadError("namespace_mismatch", "Secret inventory contains a different namespace.")
        if name in names:
            raise ReadError("duplicate_secret", "Secret inventory contains duplicate objects.")
        names.add(name)
        fields: list[SecretField] = []
        # Kubernetes may omit .data on an empty Secret; this is not an API error.
        data_value = obj.get("data")
        data = {} if data_value is None else object_mapping(data_value)
        for key, encoded_value in data.items():
            if not is_identifier(key) or not isinstance(encoded_value, str):
                raise ReadError("invalid_secret_data", "Secret data must map valid keys to base64 strings.")
            try:
                decoded = base64.b64decode(encoded_value, validate=True)
            except (binascii.Error, ValueError):
                raise ReadError("invalid_base64", "Secret data contains invalid base64; input withheld.") from None
            fields.append(SecretField(key, SecretValue(decoded)))
        result.append(SecretSnapshot(
            namespace, name, nonempty_string(meta.get("uid")),
            nonempty_string(meta.get("resourceVersion")),
            tuple(sorted(fields, key=lambda x: x.key)),
        ))
    return SecretInventory(namespace, resource_version, tuple(sorted(result, key=lambda x: x.name)))


class SnapshotReader:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def list_secrets(self, namespace: str) -> SecretInventory:
        return parse_inventory(self._raw, namespace)


class KubectlReader:
    def __init__(
        self, *, context: str, kubeconfig: Path | None = None,
        timeout: float = 60.0, runner: CommandRunner | None = None,
    ) -> None:
        if not context or context.startswith("-") or any(ord(x) < 32 for x in context):
            raise ReadError("invalid_context", "An explicit valid kubeconfig context is required.")
        if not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ReadError("invalid_timeout", "Timeout must be finite, positive, and at most 3600 seconds.")
        self._context = context
        self._kubeconfig = kubeconfig
        self._timeout = timeout
        self._runner = runner if runner is not None else SubprocessRunner()

    def list_secrets(self, namespace: str) -> SecretInventory:
        if namespace != "openstack":
            raise ReadError("namespace_mismatch", "This slice only reads the openstack namespace.")
        argv = ["kubectl", f"--context={self._context}"]
        if self._kubeconfig is not None:
            argv.append(f"--kubeconfig={self._kubeconfig}")
        argv.extend([
            f"--namespace={namespace}", f"--request-timeout={self._timeout:g}s",
            "get", "secrets", "-o", "json", "--chunk-size=500",
        ])
        return parse_inventory(self._runner.run(tuple(argv), self._timeout), namespace)
