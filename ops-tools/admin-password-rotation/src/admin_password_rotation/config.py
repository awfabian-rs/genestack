"""Load a contract into fully validated immutable domain objects."""
from __future__ import annotations

from pathlib import Path

from .errors import ConfigError, RepresentationError
from .model import (
    CredentialContract, CredentialLocation, FieldsRepresentation, IdentityBinding,
    IniRepresentation, LocationRole, Representation, WorkloadKind, WorkloadRef,
    YamlPath, YamlRepresentation,
)
from .syntax import MappingValue, YamlValue, mapping, parse_yaml, sequence, string
from .validation import is_identifier, is_object_name


def _keys(value: MappingValue, required: set[str], optional: set[str]) -> None:
    actual = {k.text for k, _ in value.items}
    if not required <= actual:
        raise ConfigError("missing_config_field", "A required configuration field is missing.")
    if actual - required - optional:
        raise ConfigError("unknown_config_field", "An unsupported configuration field is present.")


def _selector(value: YamlValue | None) -> str:
    result = string(value)
    if not is_identifier(result):
        raise ConfigError("invalid_selector", "A selector must be a nonempty simple identifier.")
    return result


def _optional_selector(value: MappingValue, name: str) -> str | None:
    return None if value.get(name) is None else _selector(value.get(name))


def _path(value: YamlValue | None) -> YamlPath:
    result = tuple(string(x) for x in sequence(value).items)
    if not result or any(not is_identifier(x) for x in result):
        raise ConfigError("invalid_path", "Paths must contain nonempty string identifiers.")
    return result


def _optional_path(value: MappingValue, name: str) -> YamlPath | None:
    return None if value.get(name) is None else _path(value.get(name))


def _representation(value: YamlValue | None) -> Representation:
    data = mapping(value)
    kind = string(data.get("type"))
    if kind == "fields":
        _keys(data, {"type", "password"}, {"username"})
        return FieldsRepresentation(_selector(data.get("password")), _optional_selector(data, "username"))
    if kind == "ini":
        _keys(data, {"type", "key", "section", "password"}, {"username"})
        return IniRepresentation(
            _selector(data.get("key")), _selector(data.get("section")),
            _selector(data.get("password")), _optional_selector(data, "username"),
        )
    if kind == "yaml":
        _keys(data, {"type", "key", "password_path"}, {"username_path", "document_path"})
        return YamlRepresentation(
            _selector(data.get("key")), _path(data.get("password_path")),
            _optional_path(data, "username_path"), _optional_path(data, "document_path"),
        )
    raise ConfigError("unsupported_representation", "Unsupported credential representation type.")


def _restart(value: YamlValue | None) -> tuple[WorkloadRef, ...]:
    targets: set[WorkloadRef] = set()
    for item in sequence(value).items:
        parts = string(item).split("/")
        if len(parts) != 2 or not is_object_name(parts[1]):
            raise ConfigError("invalid_restart", "Restart targets must have kind/name form.")
        try:
            kind = WorkloadKind(parts[0])
        except ValueError:
            raise ConfigError("unsupported_workload", "Only deployment and daemonset restart references are supported.") from None
        target = WorkloadRef(kind, parts[1])
        if target in targets:
            raise ConfigError("duplicate_restart", "A location repeats a restart target.")
        targets.add(target)
    return tuple(sorted(targets, key=lambda x: x.label))


def _claims(rep: Representation) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Credential component addresses, including usernames, to reject overlap."""
    if isinstance(rep, FieldsRepresentation):
        keys = (rep.password,) if rep.username is None else (rep.password, rep.username)
        return tuple((key, ()) for key in keys)
    if isinstance(rep, IniRepresentation):
        options = (rep.password,) if rep.username is None else (rep.password, rep.username)
        return tuple((rep.key, ("ini", rep.section, option)) for option in options)
    paths = (rep.password_path,) if rep.username_path is None else (rep.password_path, rep.username_path)
    prefix = ("yaml", *(rep.document_path or ()), "<document>")
    return tuple((rep.key, (*prefix, *path)) for path in paths)


def _validate_overlap(locations: tuple[CredentialLocation, ...]) -> None:
    claimed: dict[tuple[str, str], list[tuple[str, ...]]] = {}
    formats: dict[tuple[str, str], tuple[str, YamlPath | None]] = {}
    for loc in locations:
        rep = loc.representation
        for key, path in _claims(rep):
            address = (loc.secret, key)
            previous = claimed.setdefault(address, [])
            if any(path[:len(old)] == old or old[:len(path)] == path for old in previous):
                raise ConfigError("overlapping_locations", "Credential selectors overlap within a Secret.")
            previous.append(path)
        if isinstance(rep, (IniRepresentation, YamlRepresentation)):
            fmt = ("ini", None) if isinstance(rep, IniRepresentation) else ("yaml", rep.document_path)
            address = (loc.secret, rep.key)
            if address in formats and formats[address] != fmt:
                raise ConfigError("mixed_document_formats", "One Secret field cannot use mixed formats or embedded-document roots.")
            formats[address] = fmt


def parse_contract(text: str) -> CredentialContract:
    try:
        root = mapping(parse_yaml(text))
        _keys(root, {"namespace", "locations"}, {"representations"})
        namespace = string(root.get("namespace"))
        if namespace != "openstack":
            raise ConfigError("unsupported_namespace", "This slice supports only the openstack namespace.")
        named: dict[str, Representation] = {}
        if root.get("representations") is not None:
            for name_node, value in mapping(root.get("representations")).items:
                name = _selector(name_node)
                named[name] = _representation(value)
        locations: list[CredentialLocation] = []
        for name_node, value in mapping(root.get("locations")).items:
            name = _selector(name_node)
            data = mapping(value)
            _keys(data, {"secret", "identity", "role", "representation", "restart"}, set())
            secret = string(data.get("secret"))
            if not is_object_name(secret):
                raise ConfigError("invalid_secret_name", "Invalid Secret resource name.")
            try:
                identity = IdentityBinding(string(data.get("identity")))
                role = LocationRole(string(data.get("role")))
            except ValueError:
                raise ConfigError("invalid_identity_or_role", "Unsupported identity binding or location role.") from None
            representation_value = data.get("representation")
            if isinstance(representation_value, MappingValue):
                rep = _representation(representation_value)
            else:
                representation_name = string(representation_value)
                if representation_name not in named:
                    raise ConfigError("missing_named_representation", "Named representation is not defined.")
                rep = named[representation_name]
            username = rep.username_path if isinstance(rep, YamlRepresentation) else rep.username
            if identity is IdentityBinding.ACTIVE and username is None:
                raise ConfigError("active_requires_username", "An active location requires username and password selectors.")
            locations.append(CredentialLocation(name, secret, identity, role, rep, _restart(data.get("restart"))))
        sources = [x for x in locations if x.role is LocationRole.SOURCE]
        if len(sources) != 1:
            raise ConfigError("canonical_source", "Exactly one canonical source is required.")
        source = sources[0]
        if (source.secret != "keystone-admin" or source.identity is not IdentityBinding.ADMIN
                or source.representation != FieldsRepresentation("password") or source.restart):
            raise ConfigError("canonical_source", "The source must be keystone-admin/password, fixed admin, with no restart.")
        result = CredentialContract(namespace, tuple(sorted(locations, key=lambda x: x.name)))
        _validate_overlap(result.locations)
        return result
    except RepresentationError as exc:
        raise ConfigError(exc.code, exc.message) from None


def load_contract(path: Path) -> CredentialContract:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ConfigError("contract_read", "Cannot read the UTF-8 contract file.") from None
    return parse_contract(text)
