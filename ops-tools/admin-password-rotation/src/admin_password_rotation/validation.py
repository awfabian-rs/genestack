"""Small runtime guards for the untrusted JSON/configuration boundary."""
from __future__ import annotations

import re
from typing import cast

from .errors import ReadError


def object_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReadError("invalid_mapping", "Expected an object with string keys.")
    # Runtime isinstance above establishes the container; each key is checked below.
    raw = cast(dict[object, object], value)
    result: dict[str, object] = {}
    for key, item in raw.items():
        if not isinstance(key, str):
            raise ReadError("invalid_mapping_key", "Expected a string object key.")
        result[key] = item
    return result


def object_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ReadError("invalid_list", "Expected a list.")
    return cast(list[object], value)


def nonempty_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ReadError("invalid_string", "Expected a nonempty string.")
    return value


def is_object_name(value: str) -> bool:
    # DNS subdomain form, applied only to resource names, not credentials.
    return len(value) <= 253 and all(
        bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part))
        and len(part) <= 63 for part in value.split(".")
    )


def is_identifier(value: str) -> bool:
    return len(value) <= 253 and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))
