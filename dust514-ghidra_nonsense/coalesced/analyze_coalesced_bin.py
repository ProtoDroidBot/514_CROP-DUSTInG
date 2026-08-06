#!/usr/bin/env python3
"""Parse and analyze a decrypted Unreal Engine coalesced configuration binary.

The input is treated as immutable.  NPD/EDAT containers are intentionally out of
scope: callers must provide the already-decrypted ``COALESCED_*.BIN`` payload.
Artifact output is deterministic, preserves source ordering and duplicate keys,
and never interprets embedded logical paths as filesystem destinations.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import io
import json
import math
import os
import re
import stat
import statistics
import struct
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RECORDS = 50_000
DEFAULT_MAX_STRING_UNITS = 16 * 1024 * 1024
SAFE_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SAFE_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
SHA256_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
INT32_MIN = -(1 << 31)


class AnalysisError(RuntimeError):
    """Raised when requested analysis evidence is invalid or unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __str__(self) -> str:
        return f"{self.code}: {super().__str__()}"


class FormatError(AnalysisError):
    """Raised for a bounded, contextual binary-format failure."""

    def __init__(self, code: str, offset: int, context: str, detail: str) -> None:
        self.offset = offset
        self.context = context
        self.detail = detail
        super().__init__(
            code,
            f"offset 0x{offset:X} while {context}: {detail}",
        )


@dataclass(frozen=True)
class ParseLimits:
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_records: int = DEFAULT_MAX_RECORDS
    max_string_units: int = DEFAULT_MAX_STRING_UNITS


@dataclass(frozen=True)
class SerializedString:
    text: str
    offset: int
    end_offset: int
    serialized_length: int
    payload_bytes: int
    encoding: str


@dataclass(frozen=True)
class ConfigEntry:
    global_index: int
    file_index: int
    section_index: int
    entry_index: int
    offset: int
    end_offset: int
    key: SerializedString
    value: SerializedString


@dataclass(frozen=True)
class ConfigSection:
    file_index: int
    section_index: int
    offset: int
    end_offset: int
    name: SerializedString
    declared_entry_count: int
    entries: tuple[ConfigEntry, ...]


@dataclass(frozen=True)
class LogicalFile:
    file_index: int
    offset: int
    end_offset: int
    path: SerializedString
    declared_section_count: int
    sections: tuple[ConfigSection, ...]


@dataclass(frozen=True)
class CoalescedDocument:
    data: bytes
    declared_file_count: int
    files: tuple[LogicalFile, ...]
    parsed_bytes: int
    unicode_string_count: int
    ansi_string_count: int
    empty_string_count: int


class BinaryReader:
    def __init__(self, data: bytes, limits: ParseLimits) -> None:
        self.data = data
        self.limits = limits
        self.offset = 0
        self.unicode_string_count = 0
        self.ansi_string_count = 0
        self.empty_string_count = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read_exact(self, length: int, context: str) -> bytes:
        if length < 0:
            raise FormatError(
                "negative_read_length",
                self.offset,
                context,
                f"requested {length} bytes",
            )
        end = self.offset + length
        if end > len(self.data):
            raise FormatError(
                "truncated_payload",
                self.offset,
                context,
                f"requires {length} bytes but only {self.remaining} remain",
            )
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def read_i32_be(self, context: str) -> int:
        start = self.offset
        raw = self.read_exact(4, context)
        try:
            return struct.unpack(">i", raw)[0]
        except struct.error as exc:  # Defensive; read_exact already guarantees size.
            raise FormatError(
                "invalid_int32",
                start,
                context,
                str(exc),
            ) from exc

    def read_count(self, context: str, minimum_record_bytes: int) -> int:
        start = self.offset
        count = self.read_i32_be(context)
        if count < 0:
            raise FormatError(
                "negative_container_count",
                start,
                context,
                f"declared count is {count}",
            )
        if count > self.limits.max_records:
            raise FormatError(
                "container_count_limit",
                start,
                context,
                f"declared count {count} exceeds limit {self.limits.max_records}",
            )
        if minimum_record_bytes and count > self.remaining // minimum_record_bytes:
            raise FormatError(
                "infeasible_container_count",
                start,
                context,
                (
                    f"declared count {count} cannot fit in {self.remaining} remaining "
                    f"bytes at a {minimum_record_bytes}-byte minimum"
                ),
            )
        return count

    def read_fstring(self, context: str) -> SerializedString:
        start = self.offset
        serialized_length = self.read_i32_be(f"{context} length")
        if serialized_length == 0:
            self.empty_string_count += 1
            return SerializedString(
                text="",
                offset=start,
                end_offset=self.offset,
                serialized_length=0,
                payload_bytes=0,
                encoding="empty",
            )
        if serialized_length == INT32_MIN:
            raise FormatError(
                "fstring_length_overflow",
                start,
                context,
                "INT32_MIN cannot be converted to an absolute string length",
            )

        if serialized_length < 0:
            code_units = -serialized_length
            if code_units > self.limits.max_string_units:
                raise FormatError(
                    "fstring_length_limit",
                    start,
                    context,
                    (
                        f"declared UTF-16 length {code_units} exceeds limit "
                        f"{self.limits.max_string_units}"
                    ),
                )
            payload_length = code_units * 2
            payload = self.read_exact(payload_length, f"{context} UTF-16 payload")
            if not payload.endswith(b"\x00\x00"):
                raise FormatError(
                    "missing_utf16_terminator",
                    self.offset - min(payload_length, 2),
                    context,
                    "negative-length FString does not end in a UTF-16 NUL",
                )
            try:
                text = payload[:-2].decode("utf-16-le", errors="strict")
            except UnicodeDecodeError as exc:
                raise FormatError(
                    "invalid_utf16",
                    start + 4 + exc.start,
                    context,
                    str(exc),
                ) from exc
            self.unicode_string_count += 1
            return SerializedString(
                text=text,
                offset=start,
                end_offset=self.offset,
                serialized_length=serialized_length,
                payload_bytes=payload_length,
                encoding="utf-16-le",
            )

        byte_count = serialized_length
        if byte_count > self.limits.max_string_units:
            raise FormatError(
                "fstring_length_limit",
                start,
                context,
                (
                    f"declared single-byte length {byte_count} exceeds limit "
                    f"{self.limits.max_string_units}"
                ),
            )
        payload = self.read_exact(byte_count, f"{context} single-byte payload")
        if not payload.endswith(b"\x00"):
            raise FormatError(
                "missing_ansi_terminator",
                self.offset - min(byte_count, 1),
                context,
                "positive-length FString does not end in a NUL byte",
            )
        text = payload[:-1].decode("latin-1")
        self.ansi_string_count += 1
        return SerializedString(
            text=text,
            offset=start,
            end_offset=self.offset,
            serialized_length=serialized_length,
            payload_bytes=byte_count,
            encoding="latin-1",
        )


def parse_coalesced(data: bytes, limits: ParseLimits | None = None) -> CoalescedDocument:
    limits = limits or ParseLimits()
    if len(data) > limits.max_input_bytes:
        raise FormatError(
            "input_size_limit",
            0,
            "checking input size",
            f"{len(data)} bytes exceeds limit {limits.max_input_bytes}",
        )
    if data.startswith(b"NPD\x00"):
        raise FormatError(
            "edat_input_unsupported",
            0,
            "checking input container",
            "NPD/EDAT input is unsupported; provide a decrypted COALESCED_*.BIN",
        )
    if len(data) < 4:
        raise FormatError(
            "truncated_file_count",
            0,
            "reading top-level file count",
            f"requires 4 bytes but input contains {len(data)}",
        )

    reader = BinaryReader(data, limits)
    file_count = reader.read_count("reading top-level file count", 8)
    files: list[LogicalFile] = []
    aggregate_records = file_count
    global_entry_index = 0

    for file_index in range(file_count):
        file_offset = reader.offset
        path = reader.read_fstring(f"reading file[{file_index}] path")
        section_count = reader.read_count(
            f"reading file[{file_index}] section count",
            8,
        )
        aggregate_records += section_count
        if aggregate_records > limits.max_records:
            raise FormatError(
                "aggregate_record_limit",
                reader.offset - 4,
                f"reading file[{file_index}] section count",
                f"aggregate records exceed limit {limits.max_records}",
            )
        sections: list[ConfigSection] = []
        for section_index in range(section_count):
            section_offset = reader.offset
            section_name = reader.read_fstring(
                f"reading file[{file_index}] section[{section_index}] name"
            )
            entry_count = reader.read_count(
                f"reading file[{file_index}] section[{section_index}] entry count",
                8,
            )
            aggregate_records += entry_count
            if aggregate_records > limits.max_records:
                raise FormatError(
                    "aggregate_record_limit",
                    reader.offset - 4,
                    f"reading file[{file_index}] section[{section_index}] entry count",
                    f"aggregate records exceed limit {limits.max_records}",
                )
            entries: list[ConfigEntry] = []
            for entry_index in range(entry_count):
                entry_offset = reader.offset
                key = reader.read_fstring(
                    (
                        f"reading file[{file_index}] section[{section_index}] "
                        f"entry[{entry_index}] key"
                    )
                )
                value = reader.read_fstring(
                    (
                        f"reading file[{file_index}] section[{section_index}] "
                        f"entry[{entry_index}] value"
                    )
                )
                entries.append(
                    ConfigEntry(
                        global_index=global_entry_index,
                        file_index=file_index,
                        section_index=section_index,
                        entry_index=entry_index,
                        offset=entry_offset,
                        end_offset=reader.offset,
                        key=key,
                        value=value,
                    )
                )
                global_entry_index += 1
            sections.append(
                ConfigSection(
                    file_index=file_index,
                    section_index=section_index,
                    offset=section_offset,
                    end_offset=reader.offset,
                    name=section_name,
                    declared_entry_count=entry_count,
                    entries=tuple(entries),
                )
            )
        files.append(
            LogicalFile(
                file_index=file_index,
                offset=file_offset,
                end_offset=reader.offset,
                path=path,
                declared_section_count=section_count,
                sections=tuple(sections),
            )
        )

    if reader.offset != len(data):
        raise FormatError(
            "trailing_bytes",
            reader.offset,
            "validating exact end of file",
            f"{len(data) - reader.offset} bytes remain after the declared records",
        )

    return CoalescedDocument(
        data=data,
        declared_file_count=file_count,
        files=tuple(files),
        parsed_bytes=reader.offset,
        unicode_string_count=reader.unicode_string_count,
        ansi_string_count=reader.ansi_string_count,
        empty_string_count=reader.empty_string_count,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def casefold_sorted(values: Iterable[str]) -> list[str]:
    return sorted(values, key=lambda value: (value.casefold(), value))


def source_fingerprint(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "name": path.name,
        "size_bytes": len(data),
        "md5": hashlib.md5(data).hexdigest().upper(),  # nosec: identification only
        "sha1": hashlib.sha1(data).hexdigest().upper(),  # nosec: identification only
        "sha256": sha256_bytes(data),
    }


def read_bounded_source(path: Path, max_input_bytes: int) -> tuple[bytes, os.stat_result]:
    with path.open("rb") as source_file:
        before_stat = os.fstat(source_file.fileno())
        if before_stat.st_size > max_input_bytes:
            raise AnalysisError(
                "input_size_limit",
                f"{before_stat.st_size} bytes exceeds limit {max_input_bytes}",
            )
        data = source_file.read(max_input_bytes + 1)
        after_stat = os.fstat(source_file.fileno())
    if len(data) > max_input_bytes:
        raise AnalysisError(
            "input_size_limit",
            f"input grew beyond limit {max_input_bytes} while being read",
        )
    if (
        before_stat.st_size != after_stat.st_size
        or before_stat.st_mtime_ns != after_stat.st_mtime_ns
        or len(data) != after_stat.st_size
    ):
        raise AnalysisError(
            "source_changed_during_analysis",
            "the input file changed while it was being read",
        )
    return data, after_stat


def normalized_logical_path(source_path: str) -> str | None:
    path = PureWindowsPath(source_path)
    if path.drive or path.root:
        return None
    parts = list(path.parts)
    while parts and parts[0] in (".", ".."):
        parts.pop(0)
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    return "/".join(parts)


def file_category(source_path: str) -> str:
    suffix = PureWindowsPath(source_path).suffix.casefold()
    if suffix == ".ini":
        return "configuration"
    if suffix == ".int":
        return "localization"
    return "other"


def all_entries(document: CoalescedDocument) -> Iterable[ConfigEntry]:
    for logical_file in document.files:
        for section in logical_file.sections:
            yield from section.entries


def all_strings(document: CoalescedDocument) -> Iterable[SerializedString]:
    for logical_file in document.files:
        yield logical_file.path
        for section in logical_file.sections:
            yield section.name
            for entry in section.entries:
                yield entry.key
                yield entry.value


def classify_config_value(value: str) -> str:
    stripped = value.strip()
    if stripped == "":
        return "empty"
    if stripped.casefold() in {"true", "false"}:
        return "boolean"
    if re.fullmatch(r"[+-]?\d+", stripped):
        return "integer"
    if re.fullmatch(
        r"[+-]?(?:(?:\d+\.\d*|\d*\.\d+)(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+)[fF]?",
        stripped,
    ):
        return "float"
    if stripped.startswith("(") and stripped.endswith(")"):
        return "parenthesized_compound"
    return "other_string"


def logical_file_entry_counter(logical_file: LogicalFile) -> Counter[tuple[str, str, str]]:
    return Counter(
        (section.name.text, entry.key.text, entry.value.text)
        for section in logical_file.sections
        for entry in section.entries
    )


def compare_logical_files(
    document: CoalescedDocument,
    first_leaf: str,
    second_leaf: str,
) -> dict[str, Any] | None:
    first_matches = [
        logical_file
        for logical_file in document.files
        if PureWindowsPath(logical_file.path.text).name.casefold()
        == first_leaf.casefold()
    ]
    second_matches = [
        logical_file
        for logical_file in document.files
        if PureWindowsPath(logical_file.path.text).name.casefold()
        == second_leaf.casefold()
    ]
    if len(first_matches) != 1 or len(second_matches) != 1:
        return None
    first = first_matches[0]
    second = second_matches[0]
    first_counter = logical_file_entry_counter(first)
    second_counter = logical_file_entry_counter(second)
    intersection = first_counter & second_counter
    shared = sum(intersection.values())
    first_count = sum(first_counter.values())
    second_count = sum(second_counter.values())
    union = first_count + second_count - shared
    first_sequence = [
        (section.name.text, entry.key.text, entry.value.text)
        for section in first.sections
        for entry in section.entries
    ]
    second_sequence = [
        (section.name.text, entry.key.text, entry.value.text)
        for section in second.sections
        for entry in section.entries
    ]
    return {
        "first_file": PureWindowsPath(first.path.text).name,
        "second_file": PureWindowsPath(second.path.text).name,
        "first_entries": first_count,
        "second_entries": second_count,
        "shared_occurrences": shared,
        "first_only_occurrences": first_count - shared,
        "second_only_occurrences": second_count - shared,
        "occurrence_jaccard": round(shared / union, 6) if union else 1.0,
        "ordered_sequences_identical": first_sequence == second_sequence,
    }


def build_content_analysis(
    document: CoalescedDocument,
    entry_rows: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    config_rows = [row for row in entry_rows if row["file_category"] == "configuration"]
    localization_rows = [
        row for row in entry_rows if row["file_category"] == "localization"
    ]
    config_classes = Counter(classify_config_value(row["value"]) for row in config_rows)

    namespace_counts: Counter[str] = Counter()
    namespace_casefold_counts: Counter[str] = Counter()
    namespace_casefold_variants: dict[str, set[str]] = {}
    localization_sections: list[dict[str, Any]] = []
    for logical_file in document.files:
        category = file_category(logical_file.path.text)
        leaf = PureWindowsPath(logical_file.path.text).name
        display_path = normalized_logical_path(logical_file.path.text) or logical_file.path.text
        for section in logical_file.sections:
            if category == "configuration":
                namespace = section.name.text.split(".", 1)[0]
                namespace_counts[namespace] += len(section.entries)
                namespace_casefold_counts[namespace.casefold()] += len(section.entries)
                namespace_casefold_variants.setdefault(namespace.casefold(), set()).add(
                    namespace
                )
            elif category == "localization":
                localization_sections.append(
                    {
                        "file_index": logical_file.file_index,
                        "file": display_path,
                        "file_leaf": leaf,
                        "section_index": section.section_index,
                        "section": section.name.text,
                        "entry_count": len(section.entries),
                    }
                )

    localization_lengths = [len(row["value"]) for row in localization_rows]
    localization_nonempty = [row for row in localization_rows if row["value"]]
    localization_roots: Counter[str] = Counter()
    localization_root_characters: Counter[str] = Counter()
    for row in localization_rows:
        normalized = row["file_normalized_logical_path"] or ""
        root = normalized.split("/", 1)[0] if normalized else "unknown"
        localization_roots[root] += 1
        localization_root_characters[root] += len(row["value"])

    private_endpoints = []
    database_aliases: set[str] = set()
    database_catalogs: set[str] = set()
    public_urls: set[str] = set()
    service_identifiers: set[str] = set()
    ports: set[int] = set()
    credential_hits = []
    absolute_windows_path_hits = []
    ipv4_re = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?")
    url_re = re.compile(r"https?://[^\s\"'<>),]+", re.IGNORECASE)
    service_identifier_re = re.compile(r"\bsip:[A-Za-z0-9._-]+", re.IGNORECASE)
    db_alias_re = re.compile(r"\b[A-Za-z0-9_.-]+-db\b", re.IGNORECASE)
    catalog_re = re.compile(r"Initial\s+Catalog\s*=\s*([^;\r\n]+)", re.IGNORECASE)
    credential_re = re.compile(
        r"(?i)(?:password|passwd|token|client[_-]?secret|api[_-]?key|secret)\s*="
    )
    credential_key_re = re.compile(
        r"(?i)(?:password|passwd|token|client[_-]?secret|api[_-]?key|credential|secret)"
    )
    uri_userinfo_re = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@")
    long_hex_re = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,}(?![0-9a-f])")
    absolute_windows_re = re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:\\")

    for row in entry_rows:
        value = row["value"]
        location = {
            "file": PureWindowsPath(row["file_source_path"]).name,
            "section": row["section"],
            "key": row["key"],
            "offset": row["offset"],
            "offset_hex": row["offset_hex"],
        }
        for candidate in ipv4_re.findall(value):
            host, separator, port_text = candidate.partition(":")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                continue
            if address.is_private:
                private_endpoints.append(
                    {
                        **location,
                        "address": host,
                        "port": int(port_text) if separator and port_text else None,
                    }
                )
            if separator and port_text and 0 < int(port_text) <= 65535:
                ports.add(int(port_text))
        public_urls.update(url_re.findall(value))
        service_identifiers.update(service_identifier_re.findall(value))
        database_aliases.update(db_alias_re.findall(value))
        database_catalogs.update(match.strip() for match in catalog_re.findall(value))
        key_casefold = row["key"].casefold()
        port_value = re.fullmatch(r"(\d{1,5})\s*;?", value.strip())
        if (
            "viewport" not in key_casefold
            and key_casefold.endswith("port")
            and port_value
        ):
            port = int(port_value.group(1))
            if 0 < port <= 65535:
                ports.add(port)
        credential_reasons = []
        if credential_re.search(value):
            credential_reasons.append("assignment_syntax_in_value")
        if uri_userinfo_re.search(value):
            credential_reasons.append("uri_userinfo")
        if long_hex_re.search(value):
            credential_reasons.append("long_hexadecimal_value")
        if (
            row["file_category"] == "configuration"
            and credential_key_re.search(row["key"])
            and value.strip().casefold() not in {"", "none", "false", "true", "0"}
        ):
            credential_reasons.append("credential_like_key_with_nonempty_value")
        if credential_reasons:
            credential_hits.append({**location, "reasons": credential_reasons})
        if absolute_windows_re.search(value):
            absolute_windows_path_hits.append(location)

    private_endpoint_rows = {
        (
            row["address"],
            row["port"],
            row["file"],
            row["section"],
            row["key"],
        ): row
        for row in private_endpoints
    }
    private_endpoints = list(private_endpoint_rows.values())
    private_endpoints.sort(
        key=lambda row: (row["address"], row["port"] or -1, row["file"], row["offset"])
    )

    comparisons = [
        comparison
        for comparison in (
            compare_logical_files(
                document,
                "DustInput_Shipping.ini",
                "PS3-DustInput.ini",
            ),
            compare_logical_files(
                document,
                "DustEngine-DedicatedServerCook.ini",
                "PS3-DustEngine.ini",
            ),
        )
        if comparison is not None
    ]

    return {
        "configuration": {
            "entry_count": len(config_rows),
            "value_syntax_counts": dict(sorted(config_classes.items())),
            "section_namespace_entry_counts": [
                {"namespace": namespace, "entry_count": count}
                for namespace, count in sorted(
                    namespace_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "section_namespace_entry_counts_case_insensitive": [
                {
                    "namespace_casefold": namespace_casefold,
                    "variants": casefold_sorted(
                        namespace_casefold_variants[namespace_casefold]
                    ),
                    "entry_count": count,
                }
                for namespace_casefold, count in sorted(
                    namespace_casefold_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            ],
        },
        "localization": {
            "entry_count": len(localization_rows),
            "nonempty_entry_count": len(localization_nonempty),
            "empty_entry_count": len(localization_rows) - len(localization_nonempty),
            "value_characters": sum(localization_lengths),
            "mean_value_characters": (
                round(statistics.mean(localization_lengths), 6)
                if localization_lengths
                else 0.0
            ),
            "median_value_characters": (
                statistics.median(localization_lengths) if localization_lengths else 0
            ),
            "maximum_value_characters": max(localization_lengths, default=0),
            "distinct_values": len({row["value"] for row in localization_rows}),
            "rows_with_backtick_placeholders": sum(
                "`~" in row["value"] for row in localization_rows
            ),
            "rows_with_control_tokens": sum(
                bool(re.search(r"\[[A-Za-z][A-Za-z0-9_]*\]", row["value"]))
                for row in localization_rows
            ),
            "rows_with_brace_interpolation": sum(
                bool(re.search(r"\{[^{}]+\}", row["value"]))
                for row in localization_rows
            ),
            "rows_with_line_breaks": sum(
                "\r" in row["value"] or "\n" in row["value"]
                for row in localization_rows
            ),
            "rows_with_non_ascii": sum(
                any(ord(character) > 0x7F for character in row["value"])
                for row in localization_rows
            ),
            "entries_by_logical_root": dict(sorted(localization_roots.items())),
            "value_characters_by_logical_root": dict(
                sorted(localization_root_characters.items())
            ),
            "largest_sections": sorted(
                localization_sections,
                key=lambda row: (
                    -row["entry_count"],
                    row["file_index"],
                    row["section_index"],
                ),
            ),
        },
        "cross_file_comparisons": comparisons,
        "network_and_disclosure_review": {
            "private_ip_endpoints": private_endpoints,
            "database_aliases": casefold_sorted(database_aliases),
            "database_catalogs": casefold_sorted(database_catalogs),
            "configured_ports": sorted(ports),
            "public_urls": casefold_sorted(public_urls),
            "service_identifiers": casefold_sorted(service_identifiers),
            "credential_assignment_or_token_hits": credential_hits,
            "absolute_windows_path_hits": absolute_windows_path_hits,
            "credential_candidate_detected_by_patterns": bool(credential_hits),
            "review_scope": (
                "Pattern-based scan of serialized key/value text; not a complete "
                "semantic security audit and not a determination of credential usability."
            ),
        },
    }


def markdown_cell(value: object) -> str:
    return (
        str(value)
        .replace("|", "\\|")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def serialized_string_fields(prefix: str, value: SerializedString) -> dict[str, Any]:
    return {
        prefix: value.text,
        f"{prefix}_offset": value.offset,
        f"{prefix}_offset_hex": f"0x{value.offset:X}",
        f"{prefix}_end_offset": value.end_offset,
        f"{prefix}_serialized_length": value.serialized_length,
        f"{prefix}_payload_bytes": value.payload_bytes,
        f"{prefix}_encoding": value.encoding,
    }


def build_file_rows(document: CoalescedDocument) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for logical_file in document.files:
        section_rows = []
        file_entry_count = 0
        file_empty_values = 0
        for section in logical_file.sections:
            key_counts = Counter(entry.key.text for entry in section.entries)
            entry_count = len(section.entries)
            file_entry_count += entry_count
            empty_values = sum(entry.value.text == "" for entry in section.entries)
            file_empty_values += empty_values
            section_rows.append(
                {
                    "section_index": section.section_index,
                    "offset": section.offset,
                    "offset_hex": f"0x{section.offset:X}",
                    "end_offset": section.end_offset,
                    "name": section.name.text,
                    "entry_count": entry_count,
                    "unique_key_count": len(key_counts),
                    "duplicate_entry_count": sum(
                        count - 1 for count in key_counts.values() if count > 1
                    ),
                    "empty_value_count": empty_values,
                }
            )
        normalized = normalized_logical_path(logical_file.path.text)
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "file_index": logical_file.file_index,
                "offset": logical_file.offset,
                "offset_hex": f"0x{logical_file.offset:X}",
                "end_offset": logical_file.end_offset,
                "serialized_size_bytes": logical_file.end_offset - logical_file.offset,
                "serialized_sha256": sha256_bytes(
                    document.data[logical_file.offset : logical_file.end_offset]
                ),
                "source_path": logical_file.path.text,
                "normalized_logical_path": normalized,
                "logical_path_safe_for_display": normalized is not None,
                "leaf_name": PureWindowsPath(logical_file.path.text).name,
                "category": file_category(logical_file.path.text),
                "section_count": len(logical_file.sections),
                "entry_count": file_entry_count,
                "empty_value_count": file_empty_values,
                "sections": section_rows,
            }
        )
    return rows


def build_entry_rows(document: CoalescedDocument) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for logical_file in document.files:
        normalized = normalized_logical_path(logical_file.path.text)
        for section in logical_file.sections:
            occurrences: Counter[str] = Counter()
            for entry in section.entries:
                occurrences[entry.key.text] += 1
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "global_entry_index": entry.global_index,
                    "file_index": logical_file.file_index,
                    "file_source_path": logical_file.path.text,
                    "file_normalized_logical_path": normalized,
                    "file_category": file_category(logical_file.path.text),
                    "section_index": section.section_index,
                    "section": section.name.text,
                    "entry_index": entry.entry_index,
                    "key_occurrence": occurrences[entry.key.text],
                    "offset": entry.offset,
                    "offset_hex": f"0x{entry.offset:X}",
                    "end_offset": entry.end_offset,
                    "serialized_size_bytes": entry.end_offset - entry.offset,
                }
                row.update(serialized_string_fields("key", entry.key))
                row.update(serialized_string_fields("value", entry.value))
                rows.append(row)
    return rows


def find_values(
    document: CoalescedDocument,
    leaf_name: str,
    section_name: str,
    key: str,
) -> list[tuple[LogicalFile, ConfigSection, ConfigEntry]]:
    matches = []
    for logical_file in document.files:
        if PureWindowsPath(logical_file.path.text).name.casefold() != leaf_name.casefold():
            continue
        for section in logical_file.sections:
            if section.name.text.casefold() != section_name.casefold():
                continue
            for entry in section.entries:
                if entry.key.text.casefold() == key.casefold():
                    matches.append((logical_file, section, entry))
    return matches


def build_profile_evidence(document: CoalescedDocument) -> dict[str, Any]:
    marker_specs = [
        (
            "game_name",
            "PS3-DustEngine.ini",
            "URL",
            "GameName",
            "Dust 514",
        ),
        (
            "ps3_client",
            "PS3-DustEngine.ini",
            "Engine.Engine",
            "Client",
            "PS3Drv.PS3Client",
        ),
        (
            "engine_language",
            "PS3-DustEngine.ini",
            "Engine.Engine",
            "Language",
            "INT",
        ),
        (
            "language_name",
            "Core.int",
            "Language",
            "Language",
            "English (International)",
        ),
        (
            "language_id",
            "Core.int",
            "Language",
            "LangId",
            "9",
        ),
        (
            "save_game_title",
            "PS3.int",
            "General",
            "SaveGameTitle",
            "DUST 514®",
        ),
    ]
    markers = []
    for marker_id, leaf, section_name, key, expected in marker_specs:
        matches = find_values(document, leaf, section_name, key)
        actual_values = [entry.value.text for _, _, entry in matches]
        matched = expected in actual_values
        locations = [
            {
                "file_index": logical_file.file_index,
                "file_source_path": logical_file.path.text,
                "section_index": section.section_index,
                "entry_index": entry.entry_index,
                "offset": entry.offset,
                "offset_hex": f"0x{entry.offset:X}",
            }
            for logical_file, section, entry in matches
        ]
        markers.append(
            {
                "id": marker_id,
                "file": leaf,
                "section": section_name,
                "key": key,
                "expected": expected,
                "actual_values": actual_values,
                "locations": locations,
                "matched": matched,
            }
        )

    normalized_paths = {
        normalized_logical_path(logical_file.path.text)
        for logical_file in document.files
    }
    required_paths = [
        "DustGame/Config/PS3-DustEngine.ini",
        "DustGame/Config/PS3-DustGame.ini",
        "DustGame/Config/PS3-DustInput.ini",
        "Engine/Localization/INT/Core.int",
        "DustGame/Localization/INT/DustGame.int",
        "DustGame/Localization/INT/PS3.int",
    ]
    path_checks = [
        {"path": path, "matched": path in normalized_paths}
        for path in required_paths
    ]
    matched_markers = sum(marker["matched"] for marker in markers)
    matched_paths = sum(check["matched"] for check in path_checks)
    matched = matched_markers == len(markers) and matched_paths == len(path_checks)
    return {
        "profile": "dust514-ps3-int",
        "matched": matched,
        "marker_score": f"{matched_markers}/{len(markers)}",
        "path_score": f"{matched_paths}/{len(path_checks)}",
        "markers": markers,
        "required_paths": path_checks,
    }


def build_summary(
    document: CoalescedDocument,
    source: dict[str, Any],
    tool_sha256: str,
    file_rows: Sequence[dict[str, Any]],
    entry_rows: Sequence[dict[str, Any]],
    profile_evidence: dict[str, Any],
) -> dict[str, Any]:
    section_count = sum(len(logical_file.sections) for logical_file in document.files)
    entry_count = len(entry_rows)
    categories = Counter(row["category"] for row in file_rows)
    category_totals: dict[str, dict[str, int]] = {}
    for row in file_rows:
        totals = category_totals.setdefault(
            row["category"],
            {"files": 0, "serialized_bytes": 0, "sections": 0, "entries": 0},
        )
        totals["files"] += 1
        totals["serialized_bytes"] += row["serialized_size_bytes"]
        totals["sections"] += row["section_count"]
        totals["entries"] += row["entry_count"]
    extensions = Counter(
        PureWindowsPath(row["source_path"]).suffix.casefold()
        for row in file_rows
    )
    root_components = Counter()
    for row in file_rows:
        normalized = row["normalized_logical_path"]
        if normalized:
            root_components[normalized.split("/", 1)[0]] += 1

    duplicate_groups = []
    case_insensitive_duplicate_groups = []
    exact_pair_groups = []
    top_sections = []
    for logical_file in document.files:
        leaf = PureWindowsPath(logical_file.path.text).name
        for section in logical_file.sections:
            key_counts = Counter(entry.key.text for entry in section.entries)
            casefold_key_counts = Counter(
                entry.key.text.casefold() for entry in section.entries
            )
            casefold_key_variants: dict[str, set[str]] = {}
            for entry in section.entries:
                casefold_key_variants.setdefault(entry.key.text.casefold(), set()).add(
                    entry.key.text
                )
            pair_counts = Counter(
                (entry.key.text, entry.value.text) for entry in section.entries
            )
            for key, count in key_counts.items():
                if count > 1:
                    duplicate_groups.append(
                        {
                            "file_index": logical_file.file_index,
                            "file": leaf,
                            "section_index": section.section_index,
                            "section": section.name.text,
                            "key": key,
                            "count": count,
                        }
                    )
            for key_casefold, count in casefold_key_counts.items():
                if count > 1:
                    case_insensitive_duplicate_groups.append(
                        {
                            "file_index": logical_file.file_index,
                            "file": leaf,
                            "section_index": section.section_index,
                            "section": section.name.text,
                            "key_casefold": key_casefold,
                            "key_variants": casefold_sorted(
                                casefold_key_variants[key_casefold]
                            ),
                            "count": count,
                        }
                    )
            for (key, value), count in pair_counts.items():
                if count > 1:
                    exact_pair_groups.append(
                        {
                            "file_index": logical_file.file_index,
                            "file": leaf,
                            "section_index": section.section_index,
                            "section": section.name.text,
                            "key": key,
                            "value": value,
                            "count": count,
                        }
                    )
            top_sections.append(
                {
                    "file_index": logical_file.file_index,
                    "file": leaf,
                    "section_index": section.section_index,
                    "section": section.name.text,
                    "entry_count": len(section.entries),
                }
            )
    duplicate_groups.sort(
        key=lambda row: (
            -row["count"],
            row["file_index"],
            row["section_index"],
            row["key"],
        )
    )
    case_insensitive_duplicate_groups.sort(
        key=lambda row: (
            -row["count"],
            row["file_index"],
            row["section_index"],
            row["key_casefold"],
        )
    )
    exact_pair_groups.sort(
        key=lambda row: (
            -row["count"],
            row["file_index"],
            row["section_index"],
            row["key"],
            row["value"],
        )
    )
    top_sections.sort(
        key=lambda row: (
            -row["entry_count"],
            row["file_index"],
            row["section_index"],
        )
    )

    empty_values = sum(row["value"] == "" for row in entry_rows)
    multiline_values = sum(
        "\r" in row["value"] or "\n" in row["value"] for row in entry_rows
    )
    non_ascii_values = sum(
        any(ord(character) > 0x7F for character in row["value"])
        for row in entry_rows
    )
    longest_row = max(entry_rows, key=lambda row: len(row["value"]), default=None)
    string_count = (
        document.unicode_string_count
        + document.ansi_string_count
        + document.empty_string_count
    )
    data_length = len(document.data)
    null_count = document.data.count(0)
    printable_count = sum(0x20 <= byte <= 0x7E for byte in document.data)
    strings = list(all_strings(document))
    string_payload_bytes = sum(value.payload_bytes for value in strings)
    string_length_prefix_bytes = len(strings) * 4
    container_count_fields = 1 + len(document.files) + section_count
    container_count_bytes = container_count_fields * 4
    byte_accounting_total = (
        string_payload_bytes + string_length_prefix_bytes + container_count_bytes
    )
    unique_section_names = {
        section.name.text
        for logical_file in document.files
        for section in logical_file.sections
    }
    content_analysis = build_content_analysis(document, entry_rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "scope": {
            "input": "plaintext coalesced binary payload supplied as already decrypted",
            "edat_npd_analysis": False,
            "edat_decryption": False,
            "source_mutated": False,
            "embedded_files_extracted": False,
        },
        "tool": {
            "name": Path(__file__).name,
            "sha256": tool_sha256,
        },
        "source": source,
        "format": {
            "container": "Unreal Engine coalesced configuration/localization cache",
            "container_count_encoding": "signed 32-bit big-endian",
            "fstring_length_encoding": "signed 32-bit big-endian",
            "negative_fstring_payload_encoding": "UTF-16LE with NUL terminator",
            "positive_fstring_payload_encoding": "single-byte Latin-1 with NUL terminator",
            "parsed_bytes": document.parsed_bytes,
            "trailing_bytes": data_length - document.parsed_bytes,
        },
        "counts": {
            "logical_files": len(document.files),
            "sections": section_count,
            "unique_section_names": len(unique_section_names),
            "entries": entry_count,
            "strings": string_count,
            "unicode_strings": document.unicode_string_count,
            "ansi_strings": document.ansi_string_count,
            "empty_strings": document.empty_string_count,
            "files_by_category": dict(sorted(categories.items())),
            "files_by_extension": dict(sorted(extensions.items())),
            "files_by_logical_root": dict(sorted(root_components.items())),
            "empty_values": empty_values,
            "multiline_values": multiline_values,
            "non_ascii_values": non_ascii_values,
            "duplicate_key_groups": len(duplicate_groups),
            "duplicate_key_entries_beyond_first": sum(
                row["count"] - 1 for row in duplicate_groups
            ),
            "case_insensitive_duplicate_key_groups": len(
                case_insensitive_duplicate_groups
            ),
            "case_insensitive_duplicate_key_entries_beyond_first": sum(
                row["count"] - 1 for row in case_insensitive_duplicate_groups
            ),
            "exact_duplicate_pair_groups": len(exact_pair_groups),
            "exact_duplicate_pair_entries_beyond_first": sum(
                row["count"] - 1 for row in exact_pair_groups
            ),
        },
        "category_totals": dict(sorted(category_totals.items())),
        "byte_accounting": {
            "top_level_and_nested_count_fields": container_count_fields,
            "container_count_bytes": container_count_bytes,
            "string_length_prefix_bytes": string_length_prefix_bytes,
            "string_payload_bytes": string_payload_bytes,
            "accounted_bytes": byte_accounting_total,
            "source_bytes": data_length,
            "reconciles": byte_accounting_total == data_length,
            "strings_with_tab_cr_or_lf": sum(
                any(character in value.text for character in ("\t", "\r", "\n"))
                for value in strings
            ),
        },
        "byte_distribution": {
            "shannon_entropy_bits_per_byte": round(
                shannon_entropy(document.data), 6
            ),
            "nul_bytes": null_count,
            "nul_fraction": round(null_count / data_length, 8) if data_length else 0.0,
            "ascii_printable_bytes": printable_count,
            "ascii_printable_fraction": (
                round(printable_count / data_length, 8) if data_length else 0.0
            ),
        },
        "profile_detection": profile_evidence,
        "content_analysis": content_analysis,
        "top_sections_by_entries": top_sections[:20],
        "top_duplicate_key_groups": duplicate_groups[:20],
        "top_case_insensitive_duplicate_key_groups": (
            case_insensitive_duplicate_groups[:20]
        ),
        "exact_duplicate_pair_groups": exact_pair_groups,
        "longest_value": (
            {
                "characters": len(longest_row["value"]),
                "file_index": longest_row["file_index"],
                "file": PureWindowsPath(longest_row["file_source_path"]).name,
                "section_index": longest_row["section_index"],
                "section": longest_row["section"],
                "entry_index": longest_row["entry_index"],
                "key": longest_row["key"],
                "offset": longest_row["offset"],
                "offset_hex": longest_row["offset_hex"],
            }
            if longest_row is not None
            else None
        ),
    }


def build_validation(
    document: CoalescedDocument,
    source: dict[str, Any],
    file_rows: Sequence[dict[str, Any]],
    entry_rows: Sequence[dict[str, Any]],
    profile_evidence: dict[str, Any],
    requested_profile: str,
    require_profile: bool,
    expected_sha256: str | None,
) -> dict[str, Any]:
    section_count = sum(len(logical_file.sections) for logical_file in document.files)
    parsed_entry_count = sum(
        len(section.entries)
        for logical_file in document.files
        for section in logical_file.sections
    )
    allowed_extensions = {".ini", ".int"}
    extensions = {
        PureWindowsPath(logical_file.path.text).suffix.casefold()
        for logical_file in document.files
    }
    ue3_shape = (
        bool(document.files)
        and extensions <= allowed_extensions
        and all(logical_file.path.text for logical_file in document.files)
        and (
            document.unicode_string_count
            + document.ansi_string_count
            + document.empty_string_count
        )
        > 0
    )
    hash_matches = (
        None
        if expected_sha256 is None
        else source["sha256"] == expected_sha256.upper()
    )
    profile_matches = (
        profile_evidence["matched"]
        if requested_profile == "dust514-ps3-int"
        else True
    )
    strings = list(all_strings(document))
    accounted_bytes = (
        sum(value.payload_bytes for value in strings)
        + len(strings) * 4
        + (1 + len(document.files) + section_count) * 4
    )
    checks = [
        {
            "name": "parsed_to_exact_eof",
            "passed": document.parsed_bytes == len(document.data),
            "evidence": {
                "parsed_bytes": document.parsed_bytes,
                "source_bytes": len(document.data),
                "trailing_bytes": len(document.data) - document.parsed_bytes,
            },
        },
        {
            "name": "declared_file_count_reconciles",
            "passed": document.declared_file_count == len(document.files),
            "evidence": {
                "declared": document.declared_file_count,
                "parsed": len(document.files),
            },
        },
        {
            "name": "section_counts_reconcile",
            "passed": section_count
            == sum(file_row["section_count"] for file_row in file_rows),
            "evidence": {"sections": section_count},
        },
        {
            "name": "entry_counts_reconcile",
            "passed": parsed_entry_count == len(entry_rows),
            "evidence": {
                "parsed_entries": parsed_entry_count,
                "output_rows": len(entry_rows),
            },
        },
        {
            "name": "serialized_byte_accounting_reconciles",
            "passed": accounted_bytes == len(document.data),
            "evidence": {
                "accounted_bytes": accounted_bytes,
                "source_bytes": len(document.data),
            },
        },
        {
            "name": "ue3_coalesced_shape",
            "passed": ue3_shape,
            "evidence": {
                "extensions": sorted(extensions),
                "allowed_extensions": sorted(allowed_extensions),
            },
        },
        {
            "name": "embedded_paths_not_used_as_destinations",
            "passed": True,
            "evidence": {
                "logical_paths_recorded_verbatim": True,
                "embedded_files_extracted": False,
            },
        },
        {
            "name": "expected_sha256",
            "required": expected_sha256 is not None,
            "passed": hash_matches,
            "status": (
                "not_checked"
                if hash_matches is None
                else "passed" if hash_matches else "failed"
            ),
            "evidence": {
                "expected": expected_sha256.upper() if expected_sha256 else None,
                "actual": source["sha256"],
            },
        },
        {
            "name": "requested_profile",
            "required": require_profile,
            "passed": profile_matches,
            "evidence": {
                "requested": requested_profile,
                "detected_dust514_ps3_int": profile_evidence["matched"],
                "marker_score": profile_evidence["marker_score"],
                "path_score": profile_evidence["path_score"],
            },
        },
    ]
    valid = all(check["passed"] for check in checks if check.get("required", True))
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": valid,
        "structurally_valid": True,
        "matches_ue3_coalesced_shape": ue3_shape,
        "matches_dust514_ps3_int_profile": profile_evidence["matched"],
        "matches_expected_fixture_hash": hash_matches,
        "requested_profile": requested_profile,
        "profile_required": require_profile,
        "checks": checks,
    }


def render_report(
    summary: dict[str, Any],
    validation: dict[str, Any],
    file_rows: Sequence[dict[str, Any]],
    input_name: str,
    artifact_prefix: str,
) -> str:
    source = summary["source"]
    counts = summary["counts"]
    profile = summary["profile_detection"]
    content = summary["content_analysis"]
    config_analysis = content["configuration"]
    localization_analysis = content["localization"]
    disclosure = content["network_and_disclosure_review"]
    lines = [
        f"# {input_name} coalesced-payload analysis",
        "",
        "## Outcome",
        "",
        (
            f"The {source['size_bytes']:,}-byte source parsed exactly to EOF as an "
            "Unreal Engine coalesced configuration/localization cache. The parser "
            f"recovered {counts['logical_files']} logical files, {counts['sections']} "
            f"sections, and {counts['entries']:,} ordered key/value entries without "
            "flattening duplicate keys."
        ),
        "",
        (
            "The DUST 514 PS3 INT profile "
            + ("matched." if profile["matched"] else "did not fully match.")
            + " This profile result is separate from structural validity."
        ),
        "",
        "This analysis covers only the plaintext `.BIN` payload supplied as decrypted. "
        "Its parseability establishes plaintext structure, not the history of how it was "
        "obtained. NPD/EDAT inspection, key handling, and decryption are explicitly out of scope.",
        "",
        "## Source identity",
        "",
        "| Property | Value |",
        "| --- | --- |",
        f"| Name | `{markdown_cell(source['name'])}` |",
        f"| Size | `{source['size_bytes']}` (`0x{source['size_bytes']:X}`) |",
        f"| SHA-256 | `{source['sha256']}` |",
        f"| MD5 | `{source['md5']}` |",
        f"| Validation | `{'passed' if validation['valid'] else 'failed'}` |",
        "",
        "## Serialization",
        "",
        "- Container and string-length fields are signed 32-bit big-endian integers.",
        "- Negative FString lengths select NUL-terminated UTF-16LE payloads; positive "
        "  lengths select NUL-terminated single-byte payloads.",
        f"- `{counts['unicode_strings']:,}` strings are UTF-16LE, "
        f"`{counts['ansi_strings']:,}` are single-byte, and "
        f"`{counts['empty_strings']:,}` use the zero-length encoding.",
        "- The positive-length single-byte branch is a supported parser convention but was "
        f"  observed `{counts['ansi_strings']}` times in this payload.",
        "- The ordered model is file → section → key/value entries. Repeated keys are "
        "  retained because UE configuration arrays commonly depend on them.",
        "",
        "## Logical file inventory",
        "",
        "| # | Embedded source path | Category | Sections | Entries | Serialized bytes |",
        "| ---: | --- | --- | ---: | ---: | ---: |",
    ]
    for row in file_rows:
        lines.append(
            "| {file_index} | `{path}` | {category} | {sections} | {entries} | {size} |".format(
                file_index=row["file_index"],
                path=markdown_cell(row["source_path"]),
                category=row["category"],
                sections=row["section_count"],
                entries=row["entry_count"],
                size=row["serialized_size_bytes"],
            )
        )

    lines.extend(
        [
            "",
            "## Identity evidence",
            "",
            f"Marker score: `{profile['marker_score']}`; required-path score: "
            f"`{profile['path_score']}`.",
            "",
            "| Marker | File / section / key | Expected value | Result |",
            "| --- | --- | --- | --- |",
        ]
    )
    for marker in profile["markers"]:
        lines.append(
            "| `{marker}` | `{file}` / `{section}` / `{key}` | `{expected}` | {result} |".format(
                marker=markdown_cell(marker["id"]),
                file=markdown_cell(marker["file"]),
                section=markdown_cell(marker["section"]),
                key=markdown_cell(marker["key"]),
                expected=markdown_cell(marker["expected"]),
                result="matched" if marker["matched"] else "not matched",
            )
        )

    lines.extend(
        [
            "",
            "## Structural findings",
            "",
            f"- Configuration files: `{counts['files_by_category'].get('configuration', 0)}`; "
            f"localization files: `{counts['files_by_category'].get('localization', 0)}`.",
            f"- Exact-case duplicate-key groups: `{counts['duplicate_key_groups']}` "
            f"(`{counts['duplicate_key_entries_beyond_first']}` entries beyond the first).",
            f"- Case-insensitive duplicate-key groups: "
            f"`{counts['case_insensitive_duplicate_key_groups']}` "
            f"(`{counts['case_insensitive_duplicate_key_entries_beyond_first']}` "
            "entries beyond the first).",
            f"- Exact duplicate key/value groups: `{counts['exact_duplicate_pair_groups']}` "
            f"(`{counts['exact_duplicate_pair_entries_beyond_first']}` entries beyond the first).",
            f"- Empty values: `{counts['empty_values']}`; multiline values: "
            f"`{counts['multiline_values']}`; values containing non-ASCII characters: "
            f"`{counts['non_ascii_values']}`.",
            (
                f"- Longest value: `{summary['longest_value']['characters']}` characters at "
                f"`{summary['longest_value']['file']}` / "
                f"`{summary['longest_value']['section']}` / "
                f"`{summary['longest_value']['key']}`."
                if summary["longest_value"]
                else "- No values were present."
            ),
            f"- Shannon entropy: `{summary['byte_distribution']['shannon_entropy_bits_per_byte']}` "
            f"bits/byte; NUL-byte fraction: "
            f"`{summary['byte_distribution']['nul_fraction']:.4%}`. The low entropy and "
            "complete textual parse show that the supplied payload itself is not an opaque "
            "compressed or encrypted container.",
            f"- Byte accounting reconciles: `{summary['byte_accounting']['accounted_bytes']}` "
            f"accounted bytes versus `{summary['byte_accounting']['source_bytes']}` source bytes.",
            "",
            "### Largest sections",
            "",
            "| File | Section | Entries |",
            "| --- | --- | ---: |",
        ]
    )
    for row in summary["top_sections_by_entries"][:12]:
        lines.append(
            f"| `{markdown_cell(row['file'])}` | `{markdown_cell(row['section'])}` | "
            f"{row['entry_count']} |"
        )

    lines.extend(
        [
            "",
            "## Configuration content",
            "",
            "All configuration values remain strings in the serialized cache. The following "
            "classification is syntactic and does not assign runtime types:",
            "",
            "| Value shape | Entries |",
            "| --- | ---: |",
        ]
    )
    for shape, count in sorted(
        config_analysis["value_syntax_counts"].items(),
        key=lambda item: (-item[1], item[0]),
    ):
        lines.append(f"| `{markdown_cell(shape)}` | {count} |")
    lines.extend(
        [
            "",
            (
                "Dominant section namespaces show that this matched DUST fixture spans "
                "gameplay, input, engine, rendering, editor/cook, networking, UI, audio, "
                "and texture-streaming settings."
                if profile["matched"]
                else "Observed namespace counts are reported without assigning a product-specific "
                "subsystem interpretation."
            ),
            "",
            "| Case-insensitive section namespace | Exact-case variants | Entries |",
            "| --- | --- | ---: |",
        ]
    )
    for row in config_analysis[
        "section_namespace_entry_counts_case_insensitive"
    ][:12]:
        lines.append(
            f"| `{markdown_cell(row['namespace_casefold'])}` | "
            f"`{markdown_cell(', '.join(row['variants']))}` | {row['entry_count']} |"
        )

    lines.extend(
        [
            "",
            "## Localization content",
            "",
            f"The `{counts['files_by_category'].get('localization', 0)}` localization records "
            f"contain `{localization_analysis['entry_count']}` entries "
            f"and `{localization_analysis['value_characters']:,}` value characters. "
            f"`{localization_analysis['nonempty_entry_count']}` entries are nonempty and "
            f"`{localization_analysis['empty_entry_count']}` are empty. The median value is "
            f"`{localization_analysis['median_value_characters']}` characters and the maximum "
            f"is `{localization_analysis['maximum_value_characters']}`.",
            "",
            f"Formatting evidence includes `{localization_analysis['rows_with_backtick_placeholders']}` "
            f"rows with Unreal backtick placeholders, "
            f"`{localization_analysis['rows_with_control_tokens']}` with bracketed identifier "
            "control tokens, "
            f"and `{localization_analysis['rows_with_brace_interpolation']}` with brace interpolation.",
            "",
            "| Largest localization section | File | Entries |",
            "| --- | --- | ---: |",
        ]
    )
    for row in localization_analysis["largest_sections"][:10]:
        lines.append(
            f"| `{markdown_cell(row['section'])}` | `{markdown_cell(row['file'])}` | "
            f"{row['entry_count']} |"
        )

    if content["cross_file_comparisons"]:
        lines.extend(
            [
                "",
                "## Cross-file comparisons",
                "",
                "Comparisons use multisets of `(section, key, value)` occurrences so repeated "
                "configuration-array entries remain significant.",
                "",
                "| First file | Second file | Shared | First-only | Second-only | Jaccard |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for comparison in content["cross_file_comparisons"]:
            lines.append(
                "| `{first}` | `{second}` | {shared} | {first_only} | {second_only} | {jaccard:.6f} |".format(
                    first=markdown_cell(comparison["first_file"]),
                    second=markdown_cell(comparison["second_file"]),
                    shared=comparison["shared_occurrences"],
                    first_only=comparison["first_only_occurrences"],
                    second_only=comparison["second_only_occurrences"],
                    jaccard=comparison["occurrence_jaccard"],
                )
            )

    private_endpoint_text = ", ".join(
        f"`{value}`"
        for value in sorted(
            {
                f"{row['address']}{':' + str(row['port']) if row['port'] else ''}"
                for row in disclosure["private_ip_endpoints"]
            }
        )
    ) or "none"
    aliases_text = ", ".join(
        f"`{value}`" for value in disclosure["database_aliases"]
    ) or "none"
    catalogs_text = ", ".join(
        f"`{value}`" for value in disclosure["database_catalogs"]
    ) or "none"
    ports_text = ", ".join(
        f"`{value}`" for value in disclosure["configured_ports"]
    ) or "none"
    services_text = ", ".join(
        f"`{value}`" for value in disclosure["service_identifiers"]
    ) or "none"
    lines.extend(
        [
            "",
            "## Network and disclosure review",
            "",
            f"- Private IP endpoints present in serialized values: {private_endpoint_text}.",
            f"- Database aliases: {aliases_text}; catalog names: {catalogs_text}.",
            f"- Ports found in endpoint values or port-named settings: {ports_text}.",
            f"- Non-HTTP service identifiers: {services_text}.",
            f"- Pattern scan found `{len(disclosure['credential_assignment_or_token_hits'])}` "
            "credential-like-key, assignment, URI-userinfo, or long-hexadecimal candidates. "
            + (
                "Manual review is required; this does not establish usability."
                if disclosure["credential_candidate_detected_by_patterns"]
                else "No candidate was detected by these bounded patterns."
            ),
            "",
            "Private IPs, database aliases, and catalog names are potentially sensitive "
            "internal/development metadata. Listed ports may be generic engine defaults and "
            "are included as inventory context. This scan is pattern-based and is not a "
            "complete semantic security audit.",
        ]
    )

    lines.extend(
        [
            "",
            "## Artifacts and limitations",
            "",
            f"- `{artifact_prefix}_source_files.jsonl` records one row per logical file, "
            "including section summaries and serialized-region hashes.",
            f"- `{artifact_prefix}_entries.jsonl.gz` is the canonical ordered entry set; "
            "it preserves duplicates, embedded newlines, non-ASCII text, encodings, and offsets.",
            f"- `{artifact_prefix}_summary.json` and `{artifact_prefix}_validation.json` "
            "separate observed facts, format validation, profile matching, and fixture-hash matching.",
            "- Embedded `..\\..` paths are recorded as data and are never joined to an output "
            "directory. No reconstructed INI/INT files are emitted.",
            "- Original standalone comments, formatting whitespace, quoting choices, and "
            "include/coalescing provenance are not represented as distinct syntax. Whitespace "
            "and comment-like text embedded inside serialized values are preserved.",
            "- Output-directory title, region, and version labels are caller-supplied external "
            "provenance; they are not inferred from the serialized payload.",
            "- This run does not establish byte-for-byte identity with any EDAT wrapper because "
            "EDAT decryption was deliberately excluded.",
            "",
        ]
    )
    return "\n".join(lines)


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def jsonl_bytes(rows: Iterable[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
        for row in rows
    ).encode("utf-8")


def deterministic_gzip(data: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=buffer,
        mtime=0,
    ) as compressed:
        compressed.write(data)
    return buffer.getvalue()


def build_artifacts(
    summary: dict[str, Any],
    validation: dict[str, Any],
    file_rows: Sequence[dict[str, Any]],
    entry_rows: Sequence[dict[str, Any]],
    report: str,
    artifact_prefix: str,
) -> dict[str, bytes]:
    artifacts = {
        f"{artifact_prefix}_summary.json": json_bytes(summary),
        f"{artifact_prefix}_validation.json": json_bytes(validation),
        f"{artifact_prefix}_source_files.jsonl": jsonl_bytes(file_rows),
        f"{artifact_prefix}_entries.jsonl.gz": deterministic_gzip(
            jsonl_bytes(entry_rows)
        ),
        f"{artifact_prefix}_report.md": report.encode("utf-8"),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": summary["source"],
        "artifacts": [
            {
                "name": name,
                "size_bytes": len(data),
                "sha256": sha256_bytes(data),
            }
            for name, data in artifacts.items()
        ],
    }
    artifacts[f"{artifact_prefix}_artifact_manifest.json"] = json_bytes(manifest)
    return artifacts


def is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AnalysisError(
            "reparse_check_failed",
            f"could not inspect artifact target for reparse metadata: {path}: {exc}",
        ) from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def stable_artifact_target_state(path: Path) -> tuple[Any, ...]:
    if is_reparse_point(path):
        return ("reparse",)
    if not path.exists():
        return ("missing",)
    try:
        before = path.stat()
        if not path.is_file():
            return (
                "non_file",
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_dev,
                before.st_ino,
            )
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
    except OSError as exc:
        raise AnalysisError(
            "artifact_state_check_failed",
            f"could not safely fingerprint artifact target {path}: {exc}",
        ) from exc
    before_identity = (
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_dev,
        before.st_ino,
    )
    after_identity = (
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_dev,
        after.st_ino,
    )
    if before_identity != after_identity:
        raise AnalysisError(
            "artifact_changed_during_preflight",
            f"artifact target changed while being fingerprinted: {path}",
        )
    return ("file", *after_identity, digest.hexdigest().upper())


def assert_artifact_does_not_alias_source(target: Path, source: Path | None) -> None:
    if source is None:
        return
    resolved_source = source.resolve(strict=True)
    try:
        aliases_source = target.resolve(strict=False) == resolved_source
    except OSError as exc:
        raise AnalysisError(
            "protected_alias_check_failed",
            f"could not resolve artifact target {target}: {exc}",
        ) from exc
    if not aliases_source and target.exists():
        try:
            aliases_source = os.path.samefile(target, resolved_source)
        except OSError as exc:
            raise AnalysisError(
                "protected_alias_check_failed",
                f"could not compare artifact target {target} with input: {exc}",
            ) from exc
    if aliases_source:
        raise AnalysisError(
            "output_aliases_input",
            f"refusing artifact target that aliases the input file: {target}",
        )


def assert_artifact_bytes(path: Path, expected: bytes) -> None:
    if is_reparse_point(path) or not path.is_file():
        raise AnalysisError(
            "artifact_verification_failed",
            f"artifact is missing, non-file, or a reparse point: {path}",
        )
    try:
        if path.stat().st_size != len(expected) or path.read_bytes() != expected:
            raise AnalysisError(
                "artifact_verification_failed",
                f"artifact bytes differ from the planned output: {path}",
            )
    except OSError as exc:
        raise AnalysisError(
            "artifact_verification_failed",
            f"could not verify artifact {path}: {exc}",
        ) from exc


def output_plan(
    output_directory: Path,
    artifacts: dict[str, bytes],
    force: bool,
    protected_source: Path | None = None,
    _state_out: dict[str, tuple[Any, ...]] | None = None,
) -> dict[str, str]:
    seen_names_casefold: set[str] = set()
    for name, data in artifacts.items():
        if not isinstance(name, str) or not isinstance(data, bytes):
            raise AnalysisError(
                "unsafe_artifact_name",
                f"artifact map requires string names and byte payloads: {name!r}",
            )
        path = PureWindowsPath(name)
        if (
            not SAFE_ARTIFACT_NAME_RE.fullmatch(name)
            or path.drive
            or path.root
            or len(path.parts) != 1
        ):
            raise AnalysisError(
                "unsafe_artifact_name",
                f"artifact map contains an unsafe filename: {name!r}",
            )
        name_casefold = name.casefold()
        if name_casefold in seen_names_casefold:
            raise AnalysisError(
                "artifact_name_collision",
                f"case-insensitive artifact filename collision: {name!r}",
            )
        seen_names_casefold.add(name_casefold)

    plan = {}
    for name, data in artifacts.items():
        target = output_directory / name
        assert_artifact_does_not_alias_source(target, protected_source)
        target_state = stable_artifact_target_state(target)
        if _state_out is not None:
            _state_out[name] = target_state
        if target_state[0] == "reparse":
            plan[name] = "would_refuse_reparse_target"
        elif target_state[0] == "missing":
            plan[name] = "would_write"
        elif target_state[0] != "file":
            plan[name] = "would_refuse_non_file"
        elif target_state[2] == len(data) and target_state[-1] == sha256_bytes(data):
            plan[name] = "unchanged"
        elif force:
            plan[name] = "would_overwrite"
        else:
            plan[name] = "would_refuse_different"
    return plan


def write_artifacts(
    output_directory: Path,
    artifacts: dict[str, bytes],
    force: bool,
    protected_source: Path | None = None,
    protected_source_sha256: str | None = None,
    protected_source_max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
) -> dict[str, str]:
    preflight_states: dict[str, tuple[Any, ...]] = {}
    plan = output_plan(
        output_directory,
        artifacts,
        force,
        protected_source=protected_source,
        _state_out=preflight_states,
    )
    refusals = {
        name: status for name, status in plan.items() if status.startswith("would_refuse")
    }
    if refusals:
        details = ", ".join(f"{name} ({status})" for name, status in refusals.items())
        raise AnalysisError(
            "output_collision",
            f"refusing output changes without a safe target or --force: {details}",
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    statuses: dict[str, str] = {}
    manifest_suffix = "_artifact_manifest.json"
    manifest_names = [name for name in artifacts if name.endswith(manifest_suffix)]
    if len(manifest_names) != 1:
        raise AnalysisError(
            "invalid_manifest_count",
            f"expected exactly one artifact manifest, found {len(manifest_names)}",
        )
    ordered_names = [
        name for name in artifacts if not name.endswith(manifest_suffix)
    ] + manifest_names
    targets = {name: output_directory / name for name in ordered_names}
    initial_states = preflight_states
    for name, target in targets.items():
        if stable_artifact_target_state(target) != initial_states[name]:
            raise AnalysisError(
                "artifact_changed_since_preflight",
                f"artifact target changed immediately after preflight: {target}",
            )
    staged: list[tuple[str, Path, Path, str]] = []
    try:
        for name in ordered_names:
            data = artifacts[name]
            target = targets[name]
            if plan[name] == "unchanged":
                statuses[name] = "unchanged"
                continue
            temporary_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    prefix=(
                        f".coalesced-{sha256_bytes(name.encode('utf-8'))[:12]}-"
                    ),
                    suffix=".part",
                    dir=output_directory,
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    temporary.write(data)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                status = (
                    "overwritten" if plan[name] == "would_overwrite" else "written"
                )
                staged.append((name, target, temporary_path, status))
                temporary_path = None
            finally:
                if temporary_path is not None and temporary_path.exists():
                    temporary_path.unlink()

        if protected_source is not None and protected_source_sha256 is not None:
            protected_data, _ = read_bounded_source(
                protected_source,
                protected_source_max_bytes,
            )
            if sha256_bytes(protected_data) != protected_source_sha256:
                raise AnalysisError(
                    "source_changed_during_analysis",
                    "the input file changed before artifact commit",
                )

        for name in ordered_names:
            target = targets[name]
            assert_artifact_does_not_alias_source(target, protected_source)
            if is_reparse_point(target):
                raise AnalysisError(
                    "reparse_target_before_commit",
                    f"artifact target became a reparse point: {target}",
                )
            if stable_artifact_target_state(target) != initial_states[name]:
                raise AnalysisError(
                    "artifact_changed_since_preflight",
                    f"artifact target changed after preflight: {target}",
                )

        for name, target, temporary_path, status in staged:
            assert_artifact_does_not_alias_source(target, protected_source)
            if is_reparse_point(target):
                raise AnalysisError(
                    "reparse_target_before_commit",
                    f"artifact target became a reparse point: {target}",
                )
            if stable_artifact_target_state(target) != initial_states[name]:
                raise AnalysisError(
                    "artifact_changed_since_preflight",
                    f"artifact target changed immediately before commit: {target}",
                )
            if name.endswith(manifest_suffix):
                for primary_name in ordered_names:
                    if primary_name.endswith(manifest_suffix):
                        continue
                    assert_artifact_bytes(
                        targets[primary_name],
                        artifacts[primary_name],
                    )
            os.replace(temporary_path, target)
            statuses[name] = status

        for name in ordered_names:
            assert_artifact_does_not_alias_source(targets[name], protected_source)
            assert_artifact_bytes(targets[name], artifacts[name])
    finally:
        for _, _, temporary_path, _ in staged:
            if temporary_path.exists():
                temporary_path.unlink()
    return statuses


def expected_sha256_type(value: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("expected exactly 64 hexadecimal SHA-256 digits")
    return value.upper()


def artifact_prefix_type(value: str) -> str:
    if not SAFE_PREFIX_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "artifact prefix must be a 1-128 character safe filename component"
        )
    return value


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_path", type=Path)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument(
        "--profile",
        choices=("auto", "generic", "dust514-ps3-int"),
        default="auto",
    )
    parser.add_argument("--require-profile", action="store_true")
    parser.add_argument("--expect-sha256", type=expected_sha256_type)
    parser.add_argument("--artifact-prefix", type=artifact_prefix_type)
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-records", type=int, default=DEFAULT_MAX_RECORDS)
    parser.add_argument("--max-string-units", type=int, default=DEFAULT_MAX_STRING_UNITS)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    if args.require_profile and args.profile != "dust514-ps3-int":
        raise AnalysisError(
            "invalid_profile_requirement",
            "--require-profile requires --profile dust514-ps3-int",
        )
    if args.force and args.output_directory is None:
        raise AnalysisError(
            "force_without_output",
            "--force is only meaningful with --output-directory",
        )
    for name in ("max_input_bytes", "max_records", "max_string_units"):
        if getattr(args, name) <= 0:
            raise AnalysisError(
                "invalid_limit",
                f"--{name.replace('_', '-')} must be positive",
            )

    input_path = args.input_path.resolve()
    if input_path.suffix.casefold() == ".edat":
        raise AnalysisError(
            "edat_input_unsupported",
            "EDAT/NPD input is unsupported; provide a decrypted COALESCED_*.BIN",
        )
    if not input_path.is_file():
        raise AnalysisError("missing_input", f"input file does not exist: {input_path}")
    data, before_stat = read_bounded_source(input_path, args.max_input_bytes)
    source = source_fingerprint(input_path, data)
    limits = ParseLimits(
        max_input_bytes=args.max_input_bytes,
        max_records=args.max_records,
        max_string_units=args.max_string_units,
    )
    document = parse_coalesced(data, limits)
    file_rows = build_file_rows(document)
    entry_rows = build_entry_rows(document)
    profile_evidence = build_profile_evidence(document)
    tool_sha256 = sha256_bytes(Path(__file__).read_bytes())
    summary = build_summary(
        document,
        source,
        tool_sha256,
        file_rows,
        entry_rows,
        profile_evidence,
    )
    validation = build_validation(
        document,
        source,
        file_rows,
        entry_rows,
        profile_evidence,
        args.profile,
        args.require_profile,
        args.expect_sha256,
    )
    if not validation["valid"]:
        failed = [
            check["name"]
            for check in validation["checks"]
            if check.get("required", True) and not check["passed"]
        ]
        raise AnalysisError(
            "validation_failed",
            f"required validation checks failed: {', '.join(failed)}",
        )

    if args.artifact_prefix:
        artifact_prefix = args.artifact_prefix
    else:
        artifact_prefix = input_path.name
        if artifact_prefix.casefold().endswith(".bin"):
            artifact_prefix = artifact_prefix[:-4]
        artifact_prefix = artifact_prefix.upper()
        if not SAFE_PREFIX_RE.fullmatch(artifact_prefix):
            raise AnalysisError(
                "unsafe_artifact_prefix",
                "could not derive a safe artifact prefix; pass --artifact-prefix",
            )

    report = render_report(
        summary,
        validation,
        file_rows,
        input_path.name,
        artifact_prefix,
    )
    artifacts = build_artifacts(
        summary,
        validation,
        file_rows,
        entry_rows,
        report,
        artifact_prefix,
    )
    output_directory = (
        args.output_directory.resolve() if args.output_directory is not None else None
    )
    plan = (
        output_plan(
            output_directory,
            artifacts,
            args.force,
            protected_source=input_path,
        )
        if output_directory is not None
        else {name: "stdout_only" for name in artifacts}
    )

    if args.dry_run or output_directory is None:
        result = {
            "status": "dry_run" if args.dry_run else "analyzed_without_artifact_writes",
            "source": source,
            "counts": summary["counts"],
            "validation": {
                "valid": validation["valid"],
                "matches_ue3_coalesced_shape": validation[
                    "matches_ue3_coalesced_shape"
                ],
                "matches_dust514_ps3_int_profile": validation[
                    "matches_dust514_ps3_int_profile"
                ],
                "matches_expected_fixture_hash": validation[
                    "matches_expected_fixture_hash"
                ],
            },
            "artifact_plan": plan,
        }
    else:
        statuses = write_artifacts(
            output_directory,
            artifacts,
            args.force,
            protected_source=input_path,
            protected_source_sha256=source["sha256"],
            protected_source_max_bytes=args.max_input_bytes,
        )
        result = {
            "status": "complete",
            "source": source,
            "output_directory": str(output_directory),
            "counts": summary["counts"],
            "artifacts": statuses,
        }

    verification_data, after_stat = read_bounded_source(
        input_path,
        args.max_input_bytes,
    )
    if (
        before_stat.st_size != after_stat.st_size
        or before_stat.st_mtime_ns != after_stat.st_mtime_ns
        or sha256_bytes(verification_data) != source["sha256"]
    ):
        raise AnalysisError(
            "source_changed_during_analysis",
            "the input file changed while it was being analyzed",
        )
    print(
        json.dumps(
            result,
            indent=2 if args.dry_run or output_directory is None else None,
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except AnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except OSError as exc:
        print(f"error: io_error: {exc}", file=sys.stderr)
        raise SystemExit(3)
