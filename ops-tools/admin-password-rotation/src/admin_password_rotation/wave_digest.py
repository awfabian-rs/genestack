"""Shared, credential-free wave planning primitives.

This module is a leaf: it imports only from ``model`` and ``errors``.  It
contains the contract-semantics digest and the membership helpers used both
by ``propagation_wave`` (planning/reconciliation) and ``propagation`` (grouped
execution) so that the two modules can verify intent consistency without
introducing a circular import.
"""
from __future__ import annotations

import hashlib
import json

from .model import (
    ConfigurationDigest, CredentialContract, CredentialLocation, FieldsRepresentation,
    Identity, IdentityBinding, IniRepresentation, LocationRole,
    PropagationWaveIntent, WorkloadRef,
)


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


def _canonical_restart_dependencies(
    dependencies: tuple[WorkloadRef, ...],
) -> tuple[WorkloadRef, ...]:
    return tuple(sorted(dependencies, key=lambda item: item.label))


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


def intent_membership(
    intent: PropagationWaveIntent,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Durable intent membership: (namespace, secret, location-ids) per group."""
    return tuple(
        (
            group.namespace, group.secret_name,
            tuple(location.location_id for location in group.locations),
        )
        for group in intent.secret_groups
    )


def contract_membership(
    contract: CredentialContract, target: Identity,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Applicable contract membership for the requested target identity."""
    grouped: dict[tuple[str, str], list[str]] = {}
    for location in contract.locations:
        if _applicable(location, target):
            grouped.setdefault((contract.namespace, location.secret), []).append(location.name)
    return tuple(
        (key[0], key[1], tuple(sorted(grouped[key]))) for key in sorted(grouped)
    )
