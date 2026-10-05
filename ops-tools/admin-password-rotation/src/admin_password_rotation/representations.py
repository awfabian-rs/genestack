"""Read and structurally mutate exact credential selectors."""
from __future__ import annotations

import configparser
import json
import re
from dataclasses import dataclass, field, replace

from .errors import RepresentationError
from .model import (
    FieldsRepresentation, IniRepresentation, ObservedCredential, Representation,
    SecretField, SecretSnapshot, SecretValue, YamlRepresentation,
)
from .syntax import MAX_DOCUMENT_BYTES, Scalar, YamlValue, parse_yaml, resolve, string


@dataclass(frozen=True)
class IniDocument:
    parser: configparser.ConfigParser = field(repr=False)
    # Only explicit, single-line option values have spans. No inherited defaults.
    spans: tuple[tuple[str, str, int, int], ...]

    def span(self, section: str, option: str) -> tuple[int, int]:
        found = [(start, end) for sec, key, start, end in self.spans if (sec, key) == (section, option)]
        if len(found) != 1:
            raise RepresentationError("missing_ini_option", "Declared INI option must be explicit and single-line.")
        return found[0]


def text_field(secret: SecretSnapshot, key: str) -> str:
    value = secret.get(key)
    if value is None:
        raise RepresentationError("missing_secret_field", "A declared Secret data field is missing.")
    if len(value.reveal()) > MAX_DOCUMENT_BYTES:
        raise RepresentationError("document_too_large", "Secret field exceeds the parser size limit.")
    try:
        return value.reveal().decode("utf-8")
    except UnicodeError:
        raise RepresentationError("invalid_utf8", "A declared credential field is not UTF-8.") from None


def credential_string(value: str) -> str:
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise RepresentationError("invalid_credential_string", "Credential values must be nonempty, single-line text without NUL.")
    return value


def preserve_option_case(optionstr: str) -> str:
    return optionstr


def parse_ini(text: str) -> IniDocument:
    parser = configparser.ConfigParser(interpolation=None, strict=True, inline_comment_prefixes=None)
    parser.optionxform = preserve_option_case
    try:
        parser.read_string(text)
    except (configparser.Error, ValueError):
        raise RepresentationError("invalid_ini", "INI parsing failed; input withheld.") from None
    section = ""
    offset = 0
    spans: list[tuple[str, str, int, int]] = []
    current_indent = -1
    span_is_current = False
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        stripped = content.strip()
        indent = len(content) - len(content.lstrip())
        if not stripped or stripped.startswith(("#", ";")):
            offset += len(line)
            continue
        if current_indent >= 0 and indent > current_indent:
            # Continuations make the preceding option unsuitable as a credential.
            if span_is_current:
                spans.pop()
                span_is_current = False
            offset += len(line)
            continue
        header = re.match(r"\[([^\]]+)\]", stripped)
        if header:
            section = header.group(1)
            current_indent = -1
            span_is_current = False
        else:
            option = re.match(r"\s*([^:=]+?)\s*[:=](.*)$", content)
            if option:
                key = option.group(1).strip()
                raw = option.group(2)
                left = len(raw) - len(raw.lstrip())
                right = len(raw.rstrip())
                spans.append((section, key, offset + option.start(2) + left, offset + option.start(2) + right))
                current_indent = indent
                span_is_current = True
        offset += len(line)
    return IniDocument(parser, tuple(spans))


def ini_value(doc: IniDocument, text: str, section: str, option: str) -> str:
    start, end = doc.span(section, option)
    try:
        value = doc.parser.get(section, option, raw=True)
    except configparser.Error:
        raise RepresentationError("missing_ini_option", "A declared INI option does not resolve.") from None
    if value != text[start:end]:
        raise RepresentationError("complex_ini_credential", "Declared INI credential is not an exact single-line option.")
    return credential_string(value)


def yaml_document(text: str, rep: YamlRepresentation) -> tuple[YamlValue, str, YamlValue, Scalar | None]:
    outer = parse_yaml(text)
    if rep.document_path is None:
        return outer, text, outer, None
    embedded = resolve(outer, rep.document_path)
    inner_text = string(embedded)
    if not isinstance(embedded, Scalar):  # Explicit narrowing after the string guard.
        raise RepresentationError("expected_string", "Embedded YAML must be a string.")
    return outer, inner_text, parse_yaml(inner_text), embedded


def read_credential(secret: SecretSnapshot, rep: Representation) -> ObservedCredential:
    if isinstance(rep, FieldsRepresentation):
        password = credential_string(text_field(secret, rep.password))
        username = None if rep.username is None else credential_string(text_field(secret, rep.username))
    elif isinstance(rep, IniRepresentation):
        text = text_field(secret, rep.key)
        doc = parse_ini(text)
        password = ini_value(doc, text, rep.section, rep.password)
        username = None if rep.username is None else ini_value(doc, text, rep.section, rep.username)
    else:
        _, _, document, _ = yaml_document(text_field(secret, rep.key), rep)
        password = credential_string(string(resolve(document, rep.password_path)))
        username = None if rep.username_path is None else credential_string(string(resolve(document, rep.username_path)))
    return ObservedCredential(username, SecretValue(password.encode("utf-8")))


def _replace_spans(
    text: str, replacements: tuple[tuple[int, int, str], ...],
) -> str:
    ordered = sorted(replacements, key=lambda item: item[0])
    previous_end = -1
    for start, end, _value in ordered:
        if start < 0 or end < start or end > len(text) or start < previous_end:
            raise RepresentationError(
                "overlapping_credential_selectors",
                "Declared credential selectors do not identify disjoint source spans.",
            )
        previous_end = end
    result = text
    for start, end, value in reversed(ordered):
        result = result[:start] + value + result[end:]
    return result


def _yaml_string(value: str) -> str:
    # JSON strings are valid YAML strings and give us a small, deterministic,
    # constructor-free scalar serializer.  In particular, punctuation and
    # control characters can never turn the replacement into YAML structure.
    return json.dumps(value, ensure_ascii=False)


def _with_fields(
    secret: SecretSnapshot, replacements: tuple[SecretField, ...],
) -> SecretSnapshot:
    by_key = {item.key: item for item in secret.data}
    by_key.update({item.key: item for item in replacements})
    return replace(secret, data=tuple(sorted(by_key.values(), key=lambda item: item.key)))


def mutate_credential_fields(
    secret: SecretSnapshot, rep: Representation, *, username: str,
    password: SecretValue,
) -> tuple[SecretField, ...]:
    """Build minimal Secret-field replacements for one declared credential.

    The returned fields are suitable for an atomic conditional patch.  Direct
    fields are replaced individually.  INI and YAML documents are changed only
    at the source spans of their declared credential selectors.  Embedded YAML
    is serialized back into its one declared outer scalar after the inner leaf
    changes have been applied.
    """
    target_username = credential_string(username)
    try:
        target_password = credential_string(password.reveal().decode("utf-8"))
    except UnicodeDecodeError:
        raise RepresentationError(
            "invalid_credential_string",
            "Credential values must be valid UTF-8 text.",
        ) from None

    current = read_credential(secret, rep)
    replacements: tuple[SecretField, ...]
    if isinstance(rep, FieldsRepresentation):
        changed: list[SecretField] = []
        if current.password.reveal() != password.reveal():
            changed.append(SecretField(rep.password, password))
        if rep.username is not None and current.username != target_username:
            changed.append(SecretField(
                rep.username, SecretValue(target_username.encode("utf-8")),
            ))
        replacements = tuple(changed)
    elif isinstance(rep, IniRepresentation):
        text = text_field(secret, rep.key)
        document = parse_ini(text)
        spans: list[tuple[int, int, str]] = []
        if current.password.reveal() != password.reveal():
            start, end = document.span(rep.section, rep.password)
            spans.append((start, end, target_password))
        if rep.username is not None and current.username != target_username:
            start, end = document.span(rep.section, rep.username)
            spans.append((start, end, target_username))
        mutated = _replace_spans(text, tuple(spans))
        replacements = (
            () if mutated == text else (
                SecretField(rep.key, SecretValue(mutated.encode("utf-8"))),
            )
        )
    else:
        text = text_field(secret, rep.key)
        _outer, inner_text, document, embedded = yaml_document(text, rep)
        spans = []
        if current.password.reveal() != password.reveal():
            node = resolve(document, rep.password_path)
            string(node)
            if not isinstance(node, Scalar):
                raise RepresentationError("expected_string", "Expected a YAML string credential.")
            spans.append((node.start, node.end, _yaml_string(target_password)))
        if rep.username_path is not None and current.username != target_username:
            node = resolve(document, rep.username_path)
            string(node)
            if not isinstance(node, Scalar):
                raise RepresentationError("expected_string", "Expected a YAML string credential.")
            spans.append((node.start, node.end, _yaml_string(target_username)))
        mutated_inner = _replace_spans(inner_text, tuple(spans))
        if embedded is None:
            mutated = mutated_inner
        elif mutated_inner == inner_text:
            mutated = text
        else:
            # Replacing precisely the declared embedded-document scalar leaves
            # all other outer-document bytes untouched.
            original_scalar = text[embedded.start:embedded.end]
            terminator = (
                "\r\n" if original_scalar.endswith("\r\n")
                else "\n" if original_scalar.endswith("\n")
                else ""
            )
            mutated = _replace_spans(text, (
                (
                    embedded.start, embedded.end,
                    _yaml_string(mutated_inner) + terminator,
                ),
            ))
        replacements = (
            () if mutated == text else (
                SecretField(rep.key, SecretValue(mutated.encode("utf-8"))),
            )
        )

    # A serializer result is never trusted without reparsing it through the
    # same representation boundary used by discovery.
    reparsed = read_credential(_with_fields(secret, replacements), rep)
    expected_username = None if (
        isinstance(rep, FieldsRepresentation) and rep.username is None
        or isinstance(rep, IniRepresentation) and rep.username is None
        or isinstance(rep, YamlRepresentation) and rep.username_path is None
    ) else target_username
    if (
        reparsed.username != expected_username
        or reparsed.password.reveal() != password.reveal()
    ):
        raise RepresentationError(
            "mutation_round_trip_mismatch",
            "Mutated credential representation did not round-trip safely.",
        )
    return replacements
