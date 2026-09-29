from __future__ import annotations

import pytest

from admin_password_rotation.errors import RepresentationError
from admin_password_rotation.model import FieldsRepresentation, IniRepresentation, YamlRepresentation
from admin_password_rotation.representations import read_credential
from .helpers import PASSWORD, secret


def test_fields_decoded_once_and_read_exactly() -> None:
    obj = secret("test", {"u": b"admin", "p": b"literal%value#;=:+_"})
    result = read_credential(obj, FieldsRepresentation("p", "u"))
    assert result.username == "admin"
    assert result.password.reveal() == b"literal%value#;=:+_"


def test_password_only_has_no_invented_username() -> None:
    assert read_credential(secret("test", {"p": PASSWORD}), FieldsRepresentation("p")).username is None


@pytest.mark.parametrize("data", [{}, {"p": b""}, {"p": b"\xff"}, {"p": b"test\n"}, {"p": b"a\x00b"}])
def test_invalid_fields_fail(data: dict[str, bytes]) -> None:
    with pytest.raises(RepresentationError):
        read_credential(secret("test", data), FieldsRepresentation("p"))


def test_ini_section_is_exact_and_interpolation_disabled() -> None:
    text = b"[DEFAULT]\npassword = wrong\n[service_auth]\nusername = admin\npassword = literal%value#;=:+_\n[other]\npassword = another\n"
    obj = secret("test", {"octavia.conf": text})
    result = read_credential(obj, IniRepresentation("octavia.conf", "service_auth", "password", "username"))
    assert result.password.reveal() == b"literal%value#;=:+_"


def test_blazar_default_section() -> None:
    text = b"[DEFAULT]\nos_admin_username = admin\nos_admin_password = value\n[database]\npassword = other\n"
    result = read_credential(secret("test", {"blazar.conf": text}), IniRepresentation("blazar.conf", "DEFAULT", "os_admin_password", "os_admin_username"))
    assert result.password.reveal() == b"value"


def test_inherited_default_is_not_accepted_as_explicit_option() -> None:
    with pytest.raises(RepresentationError, match="missing_ini_option"):
        read_credential(secret("test", {"x": b"[DEFAULT]\npassword = inherited\n[target]\nusername = admin\n"}), IniRepresentation("x", "target", "password", "username"))


@pytest.mark.parametrize("text", [
    b"[target]\npassword = one\npassword = two\n",
    b"not ini at all SECRET_SENTINEL",
    b"[target]\npassword = first\n second\n third\n",
])
def test_invalid_ini_is_safe(text: bytes) -> None:
    with pytest.raises(RepresentationError) as error:
        read_credential(secret("test", {"x": text}), IniRepresentation("x", "target", "password"))
    assert "SECRET_SENTINEL" not in str(error.value)


def test_multiline_unrelated_option_does_not_remove_prior_password() -> None:
    text = b"[target]\npassword = one\nother = first\n second\n third\n"
    assert read_credential(secret("test", {"x": text}), IniRepresentation("x", "target", "password")).password.reveal() == b"one"


def test_yaml_direct() -> None:
    obj = secret("test", {"clouds.yaml": b"clouds:\n  default:\n    auth:\n      username: admin\n      password: 'literal%#:_value'\n    verify: true\n"})
    rep = YamlRepresentation("clouds.yaml", ("clouds", "default", "auth", "password"), ("clouds", "default", "auth", "username"))
    assert read_credential(obj, rep).password.reveal() == b"literal%#:_value"


def test_yaml_embedded_document_and_dot_key() -> None:
    obj = secret("test", {"generated": b"clouds.yaml: |-\n  auth:\n    username: admin\n    password: inner\n"})
    rep = YamlRepresentation("generated", ("auth", "password"), ("auth", "username"), ("clouds.yaml",))
    assert read_credential(obj, rep).password.reveal() == b"inner"


@pytest.mark.parametrize("text", [
    b"password: 123", b"password: true", b"password: null", b"password: ''",
    b"other: value", b"password: first\npassword: second", b"password: [list]",
    b"password: !!python/object:object {}", b"password: [broken SECRET_SENTINEL",
])
def test_yaml_invalid_string_paths_types_and_tags(text: bytes) -> None:
    with pytest.raises(RepresentationError) as error:
        read_credential(secret("test", {"x": text}), YamlRepresentation("x", ("password",)))
    assert "SECRET_SENTINEL" not in str(error.value)


def test_yaml_embedded_document_must_be_string() -> None:
    with pytest.raises(RepresentationError):
        read_credential(secret("test", {"x": b"clouds.yaml: {password: x}"}), YamlRepresentation("x", ("password",), document_path=("clouds.yaml",)))


def test_yaml_alias_in_credential_document_rejected() -> None:
    with pytest.raises(RepresentationError, match="yaml_alias"):
        read_credential(secret("test", {"x": b"p: &p password\nother: *p"}), YamlRepresentation("x", ("p",)))


def test_yaml_nested_structure_depth_bounded() -> None:
    from admin_password_rotation.syntax import parse_yaml
    with pytest.raises(RepresentationError, match="yaml_complexity"):
        parse_yaml("[" * 70 + "x" + "]" * 70)


def test_yaml_size_bounded() -> None:
    from admin_password_rotation.syntax import MAX_DOCUMENT_BYTES, parse_yaml
    with pytest.raises(RepresentationError, match="document_too_large"):
        parse_yaml("x" * (MAX_DOCUMENT_BYTES + 1))
