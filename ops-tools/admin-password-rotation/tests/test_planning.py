from __future__ import annotations

from dataclasses import replace

import pytest

from admin_password_rotation.config import load_contract, parse_contract
from admin_password_rotation.discovery import classify
from admin_password_rotation.kubernetes import parse_inventory
from admin_password_rotation.model import (
    CredentialState, FieldsRepresentation, IdentityBinding, IniRepresentation,
    ObservedCredential, ReferenceCredentials, SecretInventory, SecretValue,
    YamlRepresentation,
)
from admin_password_rotation.planning import build_topology_plan
from admin_password_rotation.reporting import DEFERRED_CHECKS, public_report, render_json, render_text
from .helpers import BREAKGLASS, MINIMAL, PASSWORD, ROOT, contract, inventory, secret


@pytest.mark.parametrize(("profile", "config", "count"), [("dfw-dev", "credential-contract.yaml", 24), ("prod", "credential-contract.prod.yaml", 22)])
def test_synthetic_profile_end_to_end(profile: str, config: str, count: int) -> None:
    plan = build_topology_plan(load_contract(ROOT / "config" / config), parse_inventory((ROOT / "tests/fixtures" / f"{profile}-stable.json").read_bytes(), "openstack"))
    assert len(plan.locations) == count
    assert plan.topology_checks_passed
    assert len(plan.potential_restart_dependencies) == 8
    report = public_report(plan)
    assert report["rotation_ready"] is False
    assert report["authoritative_state_verified"] is False
    assert report["planned_mutations"] == []


def test_prod_profile_does_not_silently_accept_dev_extras() -> None:
    plan = build_topology_plan(load_contract(ROOT / "config/credential-contract.prod.yaml"), parse_inventory((ROOT / "tests/fixtures/dfw-dev-stable.json").read_bytes(), "openstack"))
    assert not plan.topology_checks_passed
    assert {x.secret for x in plan.findings} == {"freezer-keystone-admin", "trove-keystone-admin"}


def test_dev_profile_requires_its_extra_locations() -> None:
    plan = build_topology_plan(load_contract(ROOT / "config/credential-contract.yaml"), parse_inventory((ROOT / "tests/fixtures/prod-stable.json").read_bytes(), "openstack"))
    assert {x.secret for x in plan.findings if x.code == "missing_secret"} == {"freezer-keystone-admin", "trove-keystone-admin"}


def test_missing_breeder_prevents_comparison_and_does_not_invent_authority() -> None:
    inv = inventory()
    plan = build_topology_plan(contract(), replace(inv, secrets=inv.secrets[1:]))
    assert not plan.topology_checks_passed
    assert any(x.code == "reference_unavailable" for x in plan.findings)
    assert not plan.potential_restart_dependencies


def test_unknown_credential_has_no_overwrite_or_restart_plan() -> None:
    inv = inventory()
    bad = secret("consumer", {"OS_USERNAME": b"DO_NOT_PRINT_THIS_USERNAME", "OS_PASSWORD": b"DO_NOT_PRINT_THIS_PASSWORD"})
    plan = build_topology_plan(contract(), replace(inv, secrets=(inv.secrets[0], bad)))
    assert plan.locations[0].state is CredentialState.UNKNOWN
    assert not plan.potential_restart_dependencies
    assert "DO_NOT_PRINT" not in render_json(plan) + render_text(plan)


def test_username_breakglass_does_not_establish_a_verified_credential() -> None:
    inv = inventory()
    plan = build_topology_plan(contract(), replace(inv, secrets=(inv.secrets[0], secret("consumer", {"OS_USERNAME": b"breakglass", "OS_PASSWORD": BREAKGLASS}))))
    assert plan.locations[0].state is CredentialState.UNVERIFIED_BREAKGLASS
    assert not plan.topology_checks_passed


def test_classifier_can_compare_explicit_breakglass_reference_without_claiming_auth() -> None:
    loc = contract().locations[0]
    observed = ObservedCredential("breakglass", SecretValue(BREAKGLASS))
    refs = ReferenceCredentials(SecretValue(PASSWORD), SecretValue(BREAKGLASS))
    assert classify(loc, observed, refs) is CredentialState.MATCHES_BREAKGLASS_REFERENCE
    assert classify(replace(loc, identity=IdentityBinding.ADMIN), observed, refs) is CredentialState.UNKNOWN


def test_password_only_fixed_admin_compares_only_declared_components() -> None:
    loc = replace(contract().locations[0], identity=IdentityBinding.ADMIN, representation=FieldsRepresentation("p"))
    assert classify(loc, ObservedCredential(None, SecretValue(PASSWORD)), ReferenceCredentials(SecretValue(PASSWORD))) is CredentialState.MATCHES_ADMIN_REFERENCE


def test_restart_dependency_deduplicated_and_all_causes_retained() -> None:
    original = contract()
    consumer = original.locations[0]
    second = replace(consumer, name="second", secret="second")
    c = replace(original, locations=(*original.locations, second))
    inv = inventory(secret("second", {"OS_USERNAME": b"admin", "OS_PASSWORD": PASSWORD}))
    plan = build_topology_plan(c, inv)
    assert len(plan.potential_restart_dependencies) == 1
    assert plan.potential_restart_dependencies[0].caused_by_locations == ("consumer", "second")


def test_empty_restart_list_does_not_invent_restarts() -> None:
    c = parse_contract(MINIMAL.replace("    restart:\n      - deployment/consumer", "    restart: []"))
    assert build_topology_plan(c, inventory()).potential_restart_dependencies == ()


def test_extra_secret_and_extra_field_are_discovered() -> None:
    inv = inventory(secret("surprise", {"opaque": b"prefix-" + PASSWORD + b"-suffix"}))
    plan = build_topology_plan(contract(), inv)
    assert any(x.code == "undeclared_password_match" and x.secret == "surprise" for x in plan.findings)
    inv = replace(inv, secrets=(inv.secrets[0], secret("consumer", {"OS_USERNAME": b"admin", "OS_PASSWORD": PASSWORD, "extra": PASSWORD})))
    plan = build_topology_plan(contract(), inv)
    assert any(x.key == "extra" for x in plan.findings)


def test_uncontracted_admin_env_detected_even_with_unknown_password() -> None:
    plan = build_topology_plan(contract(), inventory(secret("surprise", {"OS_USERNAME": b"admin", "OS_PASSWORD": b"unknown"})))
    assert any(x.code == "undeclared_admin_env" for x in plan.findings)


def _document_plan(rep: IniRepresentation | YamlRepresentation, text: bytes) -> tuple[bool, tuple[str, ...]]:
    c = contract()
    consumer = replace(c.locations[0], representation=rep)
    c = replace(c, locations=(consumer, c.source))
    inv = SecretInventory("openstack", "123", (secret("keystone-admin", {"password": PASSWORD}), secret("consumer", {"x": text})))
    plan = build_topology_plan(c, inv)
    return plan.topology_checks_passed, tuple(x.code for x in plan.findings)


def test_extra_ini_option_in_same_field_not_whitelisted() -> None:
    text = b"[auth]\nu = admin\np = " + PASSWORD + b"\nextra = " + PASSWORD + b"\n"
    ok, codes = _document_plan(IniRepresentation("x", "auth", "p", "u"), text)
    assert not ok and "undeclared_password_match" in codes


def test_ini_comment_with_password_remains_a_finding() -> None:
    text = b"[auth]\nu = admin\np = " + PASSWORD + b"\n# historical copy: " + PASSWORD + b"\n"
    ok, codes = _document_plan(IniRepresentation("x", "auth", "p", "u"), text)
    assert not ok and "undeclared_password_match" in codes


def test_extra_yaml_value_in_same_field_not_whitelisted() -> None:
    text = b"u: admin\np: " + PASSWORD + b"\nextra: " + PASSWORD
    ok, codes = _document_plan(YamlRepresentation("x", ("p",), ("u",)), text)
    assert not ok and "undeclared_password_match" in codes


def test_escaped_yaml_extra_copy_detected_semantically() -> None:
    escaped = b"\\u0053" + PASSWORD[1:]
    text = b'u: admin\np: ' + PASSWORD + b'\nextra: "' + escaped + b'"'
    ok, codes = _document_plan(YamlRepresentation("x", ("p",), ("u",)), text)
    assert not ok and "undeclared_password_match" in codes


def test_escaped_declared_yaml_password_is_accounted_for() -> None:
    text = b'u: admin\np: "\\u0053' + PASSWORD[1:] + b'"'
    assert _document_plan(YamlRepresentation("x", ("p",), ("u",)), text)[0]


def test_extra_embedded_yaml_password_not_hidden_by_outer_scalar() -> None:
    text = b"clouds.yaml: |-\n  u: admin\n  p: " + PASSWORD + b"\n  extra: " + PASSWORD + b"\n"
    ok, codes = _document_plan(YamlRepresentation("x", ("p",), ("u",), ("clouds.yaml",)), text)
    assert not ok and "undeclared_password_match" in codes


def test_read_only_and_output_contains_neither_password_nor_base64() -> None:
    import base64
    inv = inventory()
    before = inv
    plan = build_topology_plan(contract(), inv)
    assert inv == before
    outputs = render_json(plan) + render_text(plan) + repr(inv)
    assert PASSWORD.decode() not in outputs
    assert base64.b64encode(PASSWORD).decode() not in outputs
    assert public_report(plan)["executed_actions"] == []


def test_secret_and_observed_reprs_are_redacted() -> None:
    observed = ObservedCredential("USERNAME_SENTINEL", SecretValue(PASSWORD))
    assert "USERNAME_SENTINEL" not in repr(observed)
    assert PASSWORD.decode() not in repr(observed) + repr(SecretValue(PASSWORD)) + str(SecretValue(PASSWORD))


def test_unreadable_breeder_never_looks_consistent() -> None:
    inv = inventory()
    plan = build_topology_plan(contract(), replace(inv, secrets=(secret("keystone-admin", {"password": b""}), inv.secrets[1])))
    assert not plan.topology_checks_passed
    assert any(x.code == "invalid_credential_string" for x in plan.findings)
    assert any(x.code == "reference_unavailable" for x in plan.findings)


def test_disjoint_yaml_locations_in_one_secret_field() -> None:
    c = contract()
    first = replace(c.locations[0], name="one", representation=YamlRepresentation("x", ("one", "p"), ("one", "u")))
    second = replace(first, name="two", representation=YamlRepresentation("x", ("two", "p"), ("two", "u")))
    text = b"one:\n  u: admin\n  p: " + PASSWORD + b"\ntwo:\n  u: admin\n  p: " + PASSWORD + b"\n"
    inv = SecretInventory("openstack", "1", (secret("keystone-admin", {"password": PASSWORD}), secret("consumer", {"x": text})))
    plan = build_topology_plan(replace(c, locations=(first, second, c.source)), inv)
    assert plan.topology_checks_passed
    assert plan.potential_restart_dependencies[0].caused_by_locations == ("one", "two")


def test_different_unknown_password_in_arbitrary_uncontracted_format_is_not_claimed_discovered() -> None:
    # This pins the explicitly documented limitation, not a guarantee of completeness.
    inv = inventory(secret("opaque", {"file": b"some_other_admin_password=unknown"}))
    plan = build_topology_plan(contract(), inv)
    assert plan.topology_checks_passed
    assert public_report(plan)["rotation_ready"] is False
    assert "historical_unknown_or_encoded_credential_discovery" in DEFERRED_CHECKS
