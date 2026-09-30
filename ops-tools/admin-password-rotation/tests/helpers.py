from __future__ import annotations

import json
from pathlib import Path

from admin_password_rotation.config import parse_contract
from admin_password_rotation.model import (
    CredentialContract, SecretField, SecretInventory, SecretSnapshot, SecretValue,
)

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b"SYNTHETIC_Admin_Reference_00000001"
BREAKGLASS = b"SYNTHETIC_Breakglass_000000000001"

MINIMAL = """namespace: openstack
locations:
  keystone-admin:
    secret: keystone-admin
    identity: admin
    role: source
    representation:
      type: fields
      password: password
    restart: []
  consumer:
    secret: consumer
    identity: active
    role: propagated
    representation:
      type: fields
      username: OS_USERNAME
      password: OS_PASSWORD
    restart:
      - deployment/consumer
"""


def contract() -> CredentialContract:
    return parse_contract(MINIMAL)


def secret(name: str, data: dict[str, bytes]) -> SecretSnapshot:
    return SecretSnapshot("openstack", name, f"fixture-{name}", "123", tuple(
        SecretField(key, SecretValue(value)) for key, value in sorted(data.items())
    ))


def inventory(*extra: SecretSnapshot) -> SecretInventory:
    return SecretInventory("openstack", "456", (
        secret("keystone-admin", {"password": PASSWORD}),
        secret("consumer", {"OS_USERNAME": b"admin", "OS_PASSWORD": PASSWORD}),
        *extra,
    ))


def inventory_json(
    *, data: object | None = None, meta: object | None = None,
    kind: str = "SecretList", resource_version: object = "123",
) -> bytes:
    return json.dumps({
        "apiVersion": "v1", "kind": kind, "metadata": {"resourceVersion": resource_version},
        "items": [{
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"namespace": "openstack", "name": "example", "uid": "u", "resourceVersion": "1"} if meta is None else meta,
            "data": {} if data is None else data,
        }],
    }).encode()
