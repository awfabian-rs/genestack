"""Bounded, duplicate-rejecting YAML reader with source spans for auditing.

No constructors are run. Non-string scalars retain their YAML tag and are
rejected when a credential/selector requires a string. This is a READER, not
a round-trip writer. Aliases, merge keys, complex keys and custom tags fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .errors import RepresentationError

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NODES = 20000
MAX_DEPTH = 64
STR_TAG = "tag:yaml.org,2002:str"
SCALAR_TAGS = {STR_TAG, *("tag:yaml.org,2002:" + x for x in ("null", "bool", "int", "float", "timestamp"))}


@dataclass(frozen=True)
class Scalar:
    text: str = field(repr=False)
    is_string: bool
    start: int
    end: int


@dataclass(frozen=True)
class MappingValue:
    items: tuple[tuple[Scalar, YamlValue], ...] = field(repr=False)

    def get(self, name: str) -> YamlValue | None:
        return next((v for k, v in self.items if k.text == name), None)


@dataclass(frozen=True)
class SequenceValue:
    items: tuple[YamlValue, ...] = field(repr=False)


YamlValue: TypeAlias = Scalar | MappingValue | SequenceValue


def parse_yaml(text: str) -> YamlValue:
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise RepresentationError("document_too_large", "YAML document exceeds the size limit.")
    try:
        # compose preserves tag distinctions and locations without constructing objects.
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError, ValueError):
        raise RepresentationError("invalid_yaml", "YAML parsing failed; input withheld.") from None
    if node is None:
        raise RepresentationError("empty_yaml", "Expected a nonempty YAML document.")
    seen: set[int] = set()

    def convert(current: Node, depth: int) -> YamlValue:
        if depth > MAX_DEPTH or len(seen) >= MAX_NODES:
            raise RepresentationError("yaml_complexity", "YAML document exceeds complexity limits.")
        if id(current) in seen:
            raise RepresentationError("yaml_alias", "YAML aliases are not supported in this slice.")
        seen.add(id(current))
        if isinstance(current, ScalarNode):
            if current.tag not in SCALAR_TAGS:
                raise RepresentationError("yaml_tag", "Unsupported YAML tag.")
            return Scalar(current.value, current.tag == STR_TAG, current.start_mark.index, current.end_mark.index)
        if isinstance(current, SequenceNode):
            if current.tag != "tag:yaml.org,2002:seq":
                raise RepresentationError("yaml_tag", "Unsupported sequence tag.")
            return SequenceValue(tuple(convert(x, depth + 1) for x in current.value))
        if isinstance(current, MappingNode):
            if current.tag != "tag:yaml.org,2002:map":
                raise RepresentationError("yaml_tag", "Unsupported mapping tag.")
            pairs: list[tuple[Scalar, YamlValue]] = []
            keys: set[str] = set()
            for key_node, value_node in current.value:
                key = convert(key_node, depth + 1)
                if not isinstance(key, Scalar) or not key.is_string:
                    raise RepresentationError("yaml_key", "YAML mapping keys must be strings; merges are unsupported.")
                if key.text in keys:
                    raise RepresentationError("duplicate_yaml_key", "Duplicate YAML mapping key; value withheld.")
                keys.add(key.text)
                pairs.append((key, convert(value_node, depth + 1)))
            return MappingValue(tuple(pairs))
        raise RepresentationError("yaml_node", "Unsupported YAML node.")

    return convert(node, 0)


def mapping(value: YamlValue | None) -> MappingValue:
    if not isinstance(value, MappingValue):
        raise RepresentationError("expected_mapping", "Expected a YAML mapping.")
    return value


def string(value: YamlValue | None) -> str:
    if not isinstance(value, Scalar) or not value.is_string or not value.text:
        raise RepresentationError("expected_string", "Expected a nonempty YAML string.")
    return value.text


def sequence(value: YamlValue | None) -> SequenceValue:
    if not isinstance(value, SequenceValue):
        raise RepresentationError("expected_sequence", "Expected a YAML sequence.")
    return value


def resolve(value: YamlValue, path: tuple[str, ...]) -> YamlValue:
    current = value
    for key in path:
        child = mapping(current).get(key)
        if child is None:
            raise RepresentationError("missing_yaml_path", "A declared YAML path does not resolve.")
        current = child
    return current


def scalar_values(value: YamlValue) -> tuple[Scalar, ...]:
    if isinstance(value, Scalar):
        return (value,)
    if isinstance(value, SequenceValue):
        return tuple(s for item in value.items for s in scalar_values(item))
    return tuple(s for key, item in value.items for s in (key, *scalar_values(item)))
