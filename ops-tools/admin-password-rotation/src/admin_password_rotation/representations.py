"""Read exact structural credential selectors. Nothing here writes configuration."""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass, field

from .errors import RepresentationError
from .model import (
    FieldsRepresentation, IniRepresentation, ObservedCredential, Representation,
    SecretSnapshot, SecretValue, YamlRepresentation,
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
