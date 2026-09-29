from __future__ import annotations

import pytest

from admin_password_rotation.config import load_contract, parse_contract
from admin_password_rotation.errors import ConfigError
from admin_password_rotation.model import FieldsRepresentation
from .helpers import MINIMAL, ROOT


@pytest.mark.parametrize(("name", "count"), [("credential-contract.yaml", 24), ("credential-contract.prod.yaml", 22)])
def test_real_contract_profiles(name: str, count: int) -> None:
    result = load_contract(ROOT / "config" / name)
    assert len(result.locations) == count
    assert result.source.secret == "keystone-admin"


def test_active_requires_username() -> None:
    with pytest.raises(ConfigError, match="active_requires_username"):
        parse_contract(MINIMAL.replace("      username: OS_USERNAME\n", ""))


def test_fixed_admin_can_be_password_only() -> None:
    result = parse_contract(MINIMAL.replace("    identity: active", "    identity: admin").replace("      username: OS_USERNAME\n", ""))
    assert isinstance(result.locations[0].representation, FieldsRepresentation)


@pytest.mark.parametrize(("old", "new"), [
    ("type: fields", "type: magic"),
    ("role: propagated", "role: magic"),
    ("identity: active", "identity: magic"),
    ("namespace: openstack", "namespace: elsewhere"),
    ("deployment/consumer", "pod/consumer"),
    ("deployment/consumer", "deployment.apps/consumer"),
    ("deployment/consumer", "deployment/bad/name"),
    ("deployment/consumer", "deployment/-bad"),
    ("secret: consumer", "secret: BadName"),
    ("password: OS_PASSWORD", "password: ''"),
    ("password: OS_PASSWORD", "password: 123"),
    ("role: source", "role: propagated"),
    ("secret: keystone-admin", "secret: other-source"),
])
def test_invalid_contract_values(old: str, new: str) -> None:
    with pytest.raises(ConfigError):
        parse_contract(MINIMAL.replace(old, new))


@pytest.mark.parametrize("text", [
    MINIMAL + "namespace: openstack\n",
    MINIMAL.replace("    secret: consumer", "    secret: consumer\n    secret: duplicate"),
    MINIMAL.replace("    role: propagated", "    role: propagated\n    optional: true"),
    MINIMAL.replace("      password: OS_PASSWORD", "      password: OS_PASSWORD\n      mystery: extra"),
    MINIMAL.replace("    restart: []\n", "", 1),
    MINIMAL.replace("      - deployment/consumer", "      - deployment/consumer\n      - deployment/consumer"),
    MINIMAL.replace("      username: OS_USERNAME", "      username: OS_PASSWORD"),
])
def test_ambiguous_missing_or_unknown_configuration_rejected(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_contract(text)


def test_named_representation_resolves() -> None:
    text = MINIMAL.replace("locations:\n", "representations:\n  env:\n    type: fields\n    username: OS_USERNAME\n    password: OS_PASSWORD\nlocations:\n")
    text = text.replace("    representation:\n      type: fields\n      username: OS_USERNAME\n      password: OS_PASSWORD", "    representation: env")
    assert len(parse_contract(text).locations) == 2


def test_undefined_named_representation_rejected() -> None:
    with pytest.raises(ConfigError, match="missing_named_representation"):
        parse_contract(MINIMAL.replace("    representation:\n      type: fields\n      username: OS_USERNAME\n      password: OS_PASSWORD", "    representation: absent"))


def test_password_and_username_paths_must_differ() -> None:
    text = MINIMAL.replace("      type: fields\n      username: OS_USERNAME\n      password: OS_PASSWORD", "      type: yaml\n      key: clouds.yaml\n      username_path: [auth, password]\n      password_path: [auth, password]")
    with pytest.raises(ConfigError, match="overlapping_locations"):
        parse_contract(text)


def test_aliases_and_unsafe_tags_rejected() -> None:
    for text in ["a: &a {x: y}\nb: *a\n", "!!python/object/apply:os.system ['echo unsafe']"]:
        with pytest.raises(ConfigError):
            parse_contract(text)
