"""Reference-relative classification and bounded undeclared-copy discovery."""
from __future__ import annotations

import hmac
from collections import defaultdict

from .errors import RepresentationError
from .model import (
    CredentialContract, CredentialLocation, CredentialState, FieldsRepresentation,
    Finding, IdentityBinding, IniRepresentation, ObservedCredential,
    ReferenceCredentials, Representation, SecretInventory, SecretSnapshot,
    YamlRepresentation,
)
from .representations import parse_ini, text_field, yaml_document
from .syntax import Scalar, YamlValue, resolve, scalar_values


def classify(
    location: CredentialLocation, observed: ObservedCredential,
    references: ReferenceCredentials,
) -> CredentialState:
    """Matching a supplied reference never establishes live authentication."""
    username = observed.username
    if username is None:
        username = location.identity.value
    allowed_admin = location.identity in (IdentityBinding.ADMIN, IdentityBinding.ACTIVE)
    allowed_breakglass = location.identity in (IdentityBinding.BREAKGLASS, IdentityBinding.ACTIVE)
    if allowed_admin and username == "admin" and hmac.compare_digest(observed.password.reveal(), references.admin.reveal()):
        return CredentialState.MATCHES_ADMIN_REFERENCE
    if allowed_breakglass and username == "breakglass":
        if references.breakglass is None:
            return CredentialState.UNVERIFIED_BREAKGLASS
        if hmac.compare_digest(observed.password.reveal(), references.breakglass.reveal()):
            return CredentialState.MATCHES_BREAKGLASS_REFERENCE
    return CredentialState.UNKNOWN


def _mask(text: str, spans: tuple[tuple[int, int], ...]) -> str:
    """Scanner-only view, never a candidate document to persist."""
    for start, end in sorted(set(spans), reverse=True):
        text = text[:start] + text[end:]
    return text


def _yaml_views(text: str, root: YamlValue, spans: tuple[tuple[int, int], ...]) -> tuple[bytes, ...]:
    # Both lexical and decoded scalar views: escaped values cannot hide extra copies.
    values = tuple(
        scalar.text.encode("utf-8") for scalar in scalar_values(root)
        if (scalar.start, scalar.end) not in spans
    )
    return (_mask(text, spans).encode("utf-8"), *values)


def _audit_views(secret: SecretSnapshot, key: str, reps: tuple[Representation, ...]) -> tuple[bytes, ...]:
    raw = secret.get(key)
    if raw is None:
        return ()
    if not reps:
        return (raw.reveal(),)
    first = reps[0]
    if isinstance(first, FieldsRepresentation):
        # Only matched password selectors, never username fields, enter reps.
        return ()
    text = text_field(secret, key)
    if isinstance(first, IniRepresentation):
        ini = parse_ini(text)
        spans = tuple(ini.span(rep.section, rep.password) for rep in reps if isinstance(rep, IniRepresentation))
        return (_mask(text, spans).encode("utf-8"),)
    outer, inner_text, inner, embedded = yaml_document(text, first)
    passwords = tuple(resolve(inner, rep.password_path) for rep in reps if isinstance(rep, YamlRepresentation))
    spans = tuple((node.start, node.end) for node in passwords if isinstance(node, Scalar))
    inner_views = _yaml_views(inner_text, inner, spans)
    if embedded is None:
        return inner_views
    return (*_yaml_views(text, outer, ((embedded.start, embedded.end),)), *inner_views)


def discover_unexpected(
    contract: CredentialContract, inventory: SecretInventory,
    references: ReferenceCredentials,
    accepted_locations: tuple[CredentialLocation, ...],
) -> tuple[Finding, ...]:
    """Find known password bytes outside exactly matched declared password nodes.

This is bounded discovery, not an inventory of every possible admin credential:
unknown/historical passwords, compressed documents and arbitrary encodings are
not exhaustively decoded. Uncontracted OS_USERNAME admin/breakglass is also a
candidate even when its password differs. See docs/DESIGN.md.
"""
    claims: dict[tuple[str, str], list[Representation]] = defaultdict(list)
    for loc in accepted_locations:
        rep = loc.representation
        key = rep.password if isinstance(rep, FieldsRepresentation) else rep.key
        claims[(loc.secret, key)].append(rep)
    expected_env_pairs = {
        loc.secret for loc in contract.locations
        if isinstance(loc.representation, FieldsRepresentation)
        and loc.representation.username == "OS_USERNAME"
        and loc.representation.password == "OS_PASSWORD"
    }
    needles = tuple(x.reveal() for x in (references.admin, references.breakglass) if x is not None and x.reveal())
    findings: list[Finding] = []
    for secret in inventory.secrets:
        for item in secret.data:
            try:
                views = _audit_views(secret, item.key, tuple(claims.get((secret.name, item.key), ())))
            except RepresentationError:
                findings.append(Finding("audit_unreadable", "Cannot structurally account for a declared password during audit.", secret=secret.name, key=item.key))
                views = (item.value.reveal(),)
            if any(needle in view for needle in needles for view in views):
                findings.append(Finding("undeclared_password_match", "A comparison password occurs outside an accepted declared credential selector.", secret=secret.name, key=item.key))
        username = secret.get("OS_USERNAME")
        if (secret.name not in expected_env_pairs and username is not None
                and username.reveal() in (b"admin", b"breakglass")):
            findings.append(Finding("undeclared_admin_env", "An administrative OS_USERNAME representation is not contracted.", secret=secret.name, key="OS_USERNAME"))
    return tuple(findings)
