#!/usr/bin/env python3
"""Safely reconstruct logical files from a decrypted UE3 coalesced payload.

This is a standalone companion to ``analyze_coalesced_bin.py``. It parses the
decrypted ``.BIN`` directly, never reads an EDAT, and never participates in the
Ghidra EBOOT workflow. Embedded paths are treated as untrusted data and are
normalized beneath one explicit extraction root before any output is written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Sequence

from analyze_coalesced_bin import (
    AnalysisError,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_STRING_UNITS,
    ParseLimits,
    SAFE_PREFIX_RE,
    expected_sha256_type,
    parse_coalesced,
    read_bounded_source,
    sha256_bytes,
    source_fingerprint,
)


EXTRACTION_SCHEMA_VERSION = 1
MANIFEST_SUFFIX = "_extraction_manifest.json"
WINDOWS_INVALID_CHARACTERS = frozenset('<>:"/\\|?*')
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {f"COM{index}" for index in "¹²³"}
    | {f"LPT{index}" for index in "¹²³"}
)


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def validate_windows_component(component: str, context: str) -> None:
    if not component or component in {".", ".."}:
        raise AnalysisError("unsafe_embedded_path", f"{context}: empty or traversal part")
    try:
        utf16_units = len(component.encode("utf-16-le")) // 2
    except UnicodeEncodeError as exc:
        raise AnalysisError(
            "unsafe_embedded_path",
            f"{context}: contains an invalid Unicode surrogate",
        ) from exc
    if utf16_units > 255:
        raise AnalysisError(
            "unsafe_embedded_path",
            f"{context}: path component exceeds 255 UTF-16 code units",
        )
    if component.endswith((" ", ".")):
        raise AnalysisError(
            "unsafe_embedded_path",
            f"{context}: trailing dots or spaces are unsafe on Windows",
        )
    if any(character in WINDOWS_INVALID_CHARACTERS for character in component):
        raise AnalysisError(
            "unsafe_embedded_path",
            f"{context}: contains a Windows-invalid path character",
        )
    if any(ord(character) < 0x20 for character in component):
        raise AnalysisError(
            "unsafe_embedded_path",
            f"{context}: contains a control character",
        )
    device_stem = component.split(".", 1)[0].rstrip(" .").upper()
    if device_stem in WINDOWS_RESERVED_NAMES:
        raise AnalysisError(
            "unsafe_embedded_path",
            f"{context}: uses reserved Windows device name {device_stem}",
        )


def safe_embedded_relative_path(source_path: str) -> PurePosixPath:
    if not source_path or "\x00" in source_path:
        raise AnalysisError(
            "unsafe_embedded_path",
            "embedded path is empty or contains NUL",
        )
    if source_path.endswith(("\\", "/")):
        raise AnalysisError(
            "unsafe_embedded_path",
            f"embedded path ends with a directory separator: {source_path!r}",
        )
    windows_path = PureWindowsPath(source_path)
    if windows_path.drive or windows_path.root or windows_path.is_absolute():
        raise AnalysisError(
            "unsafe_embedded_path",
            f"embedded path is absolute, rooted, drive-qualified, or UNC: {source_path!r}",
        )
    parts = list(windows_path.parts)
    while parts and parts[0] in {".", ".."}:
        parts.pop(0)
    if not parts:
        raise AnalysisError(
            "unsafe_embedded_path",
            f"embedded path has no filename after normalization: {source_path!r}",
        )
    for index, part in enumerate(parts):
        validate_windows_component(part, f"embedded path part[{index}] in {source_path!r}")
    relative_path = PurePosixPath(*parts)
    if len(relative_path.as_posix()) > 1024:
        raise AnalysisError(
            "unsafe_embedded_path",
            f"normalized embedded path exceeds 1024 characters: {source_path!r}",
        )
    return relative_path


def validate_section_or_key(text: str, kind: str, context: str) -> None:
    if not text:
        raise AnalysisError(
            "unrepresentable_text_record",
            f"{context}: empty {kind} cannot be represented unambiguously",
        )
    if "\x00" in text or "\r" in text or "\n" in text:
        raise AnalysisError(
            "unrepresentable_text_record",
            f"{context}: {kind} contains NUL or a line break",
        )
    if kind == "section" and "]" in text:
        raise AnalysisError(
            "unrepresentable_text_record",
            f"{context}: section name contains ']'",
        )
    if kind == "key" and "=" in text:
        raise AnalysisError(
            "unrepresentable_text_record",
            f"{context}: key contains '='",
        )


def render_logical_file(logical_file: Any) -> bytes:
    chunks: list[str] = []
    for section in logical_file.sections:
        section_context = (
            f"file[{logical_file.file_index}] section[{section.section_index}]"
        )
        validate_section_or_key(section.name.text, "section", section_context)
        chunks.append(f"[{section.name.text}]\n")
        for entry in section.entries:
            entry_context = f"{section_context} entry[{entry.entry_index}]"
            validate_section_or_key(entry.key.text, "key", entry_context)
            chunks.append(f"{entry.key.text}={entry.value.text}\n")
        chunks.append("\n")
    return "".join(chunks).encode("utf-8")


def extraction_manifest_prefix(input_name: str, requested_prefix: str | None) -> str:
    if requested_prefix is not None:
        return requested_prefix
    prefix = input_name[:-4] if input_name.casefold().endswith(".bin") else input_name
    prefix = prefix.upper()
    if not SAFE_PREFIX_RE.fullmatch(prefix):
        raise AnalysisError(
            "unsafe_manifest_prefix",
            "could not derive a safe manifest prefix; pass --manifest-prefix",
        )
    return prefix


def build_extraction_outputs(
    document: Any,
    source: dict[str, Any],
    manifest_prefix: str,
    extractor_sha256: str,
    parser_sha256: str,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    outputs: dict[str, bytes] = {}
    rows: list[dict[str, Any]] = []
    casefold_destinations: dict[str, str] = {}
    extension_counts: Counter[str] = Counter()

    for logical_file in document.files:
        relative_path = safe_embedded_relative_path(logical_file.path.text)
        relative_name = relative_path.as_posix()
        collision_key = relative_name.casefold()
        if collision_key in casefold_destinations:
            raise AnalysisError(
                "embedded_path_collision",
                (
                    f"{logical_file.path.text!r} and "
                    f"{casefold_destinations[collision_key]!r} normalize to the same "
                    f"case-insensitive destination {relative_name!r}"
                ),
            )
        casefold_destinations[collision_key] = logical_file.path.text

        rendered = render_logical_file(logical_file)
        outputs[relative_name] = rendered
        extension = PureWindowsPath(logical_file.path.text).suffix.casefold()
        extension_counts[extension or "(none)"] += 1
        entries = [
            entry
            for section in logical_file.sections
            for entry in section.entries
        ]
        exact_key_groups = 0
        casefold_key_groups = 0
        for section in logical_file.sections:
            exact_counts = Counter(entry.key.text for entry in section.entries)
            folded_counts = Counter(entry.key.text.casefold() for entry in section.entries)
            exact_key_groups += sum(count > 1 for count in exact_counts.values())
            casefold_key_groups += sum(count > 1 for count in folded_counts.values())
        rows.append(
            {
                "file_index": logical_file.file_index,
                "embedded_source_path": logical_file.path.text,
                "output_relative_path": relative_name,
                "extension": extension,
                "section_count": len(logical_file.sections),
                "entry_count": len(entries),
                "exact_case_duplicate_key_groups": exact_key_groups,
                "case_insensitive_duplicate_key_groups": casefold_key_groups,
                "zero_entry_section_count": sum(
                    not section.entries for section in logical_file.sections
                ),
                "empty_value_count": sum(entry.value.text == "" for entry in entries),
                "multiline_value_count": sum(
                    "\r" in entry.value.text or "\n" in entry.value.text
                    for entry in entries
                ),
                "embedded_lf_count": sum(
                    entry.value.text.count("\n") for entry in entries
                ),
                "comment_prefix_key_count": sum(
                    entry.key.text.startswith((";", "#")) for entry in entries
                ),
                "bracketed_key_occurrence_count": sum(
                    "[" in entry.key.text and "]" in entry.key.text for entry in entries
                ),
                "value_with_equals_count": sum(
                    "=" in entry.value.text for entry in entries
                ),
                "leading_whitespace_value_count": sum(
                    bool(entry.value.text)
                    and entry.value.text[0].isspace()
                    for entry in entries
                ),
                "trailing_whitespace_value_count": sum(
                    bool(entry.value.text)
                    and entry.value.text[-1].isspace()
                    for entry in entries
                ),
                "serialized_offset": logical_file.offset,
                "serialized_end_offset": logical_file.end_offset,
                "serialized_region_sha256": sha256_bytes(
                    document.data[logical_file.offset : logical_file.end_offset]
                ),
                "output_size_bytes": len(rendered),
                "output_sha256": sha256_bytes(rendered),
            }
        )

    manifest_name = f"{manifest_prefix}{MANIFEST_SUFFIX}"
    manifest_collision = manifest_name.casefold()
    if manifest_collision in casefold_destinations:
        raise AnalysisError(
            "manifest_path_collision",
            f"manifest name collides with embedded output: {manifest_name}",
        )

    manifest = {
        "schema_version": EXTRACTION_SCHEMA_VERSION,
        "status": "complete",
        "source": source,
        "tools": {
            "extractor": {
                "name": Path(__file__).name,
                "sha256": extractor_sha256,
            },
            "parser": {
                "name": "analyze_coalesced_bin.py",
                "sha256": parser_sha256,
            },
        },
        "format": {
            "representation": "sectioned key=value text reconstructed from ordered records",
            "encoding": "UTF-8 without BOM",
            "generated_line_separator": "LF",
            "embedded_value_line_breaks": "preserved verbatim",
            "duplicate_keys": "preserved in source order",
            "empty_sections": "preserved",
            "original_layout_byte_identical": False,
            "conventional_ini_round_trip_safe": False,
            "limitations": (
                "Original standalone comments, formatting whitespace, quoting choices, and "
                "include/coalescing provenance are not distinct records in the cache. Keys "
                "beginning ';' or '#' and multiline values are written verbatim, so a "
                "conventional INI parser may reinterpret them."
            ),
        },
        "counts": {
            "logical_files": len(rows),
            "sections": sum(row["section_count"] for row in rows),
            "entries": sum(row["entry_count"] for row in rows),
            "zero_section_files": sum(row["section_count"] == 0 for row in rows),
            "zero_entry_sections": sum(
                row["zero_entry_section_count"] for row in rows
            ),
            "empty_values": sum(row["empty_value_count"] for row in rows),
            "multiline_values": sum(row["multiline_value_count"] for row in rows),
            "embedded_lf_characters": sum(row["embedded_lf_count"] for row in rows),
            "comment_prefix_keys": sum(
                row["comment_prefix_key_count"] for row in rows
            ),
            "bracketed_key_occurrences": sum(
                row["bracketed_key_occurrence_count"] for row in rows
            ),
            "values_containing_equals": sum(
                row["value_with_equals_count"] for row in rows
            ),
            "leading_whitespace_values": sum(
                row["leading_whitespace_value_count"] for row in rows
            ),
            "trailing_whitespace_values": sum(
                row["trailing_whitespace_value_count"] for row in rows
            ),
            "files_by_extension": dict(sorted(extension_counts.items())),
            "output_bytes_excluding_manifest": sum(
                row["output_size_bytes"] for row in rows
            ),
        },
        "files": rows,
    }
    outputs[manifest_name] = json_bytes(manifest)
    return outputs, manifest


def validate_output_map(outputs: dict[str, bytes]) -> list[PurePosixPath]:
    relative_paths: list[PurePosixPath] = []
    seen_casefold: set[str] = set()
    casefold_parts_by_name: dict[str, tuple[str, ...]] = {}
    for name, data in outputs.items():
        if not isinstance(name, str) or not isinstance(data, bytes):
            raise AnalysisError(
                "unsafe_output_map",
                "output map requires string relative paths and byte payloads",
            )
        if "\\" in name:
            raise AnalysisError(
                "unsafe_output_map",
                f"output path must use normalized '/' separators: {name!r}",
            )
        relative_path = PurePosixPath(name)
        if relative_path.is_absolute() or not relative_path.parts:
            raise AnalysisError("unsafe_output_map", f"unsafe output path: {name!r}")
        for index, part in enumerate(relative_path.parts):
            validate_windows_component(part, f"output path part[{index}] in {name!r}")
        collision_key = relative_path.as_posix().casefold()
        if collision_key in seen_casefold:
            raise AnalysisError(
                "output_path_collision",
                f"case-insensitive output collision: {name!r}",
            )
        seen_casefold.add(collision_key)
        casefold_parts_by_name[name] = tuple(
            part.casefold() for part in relative_path.parts
        )
        relative_paths.append(relative_path)
    complete_paths = set(casefold_parts_by_name.values())
    for name, parts in casefold_parts_by_name.items():
        for depth in range(1, len(parts)):
            if parts[:depth] in complete_paths:
                raise AnalysisError(
                    "output_path_hierarchy_collision",
                    f"an output file is also an ancestor directory of {name!r}",
                )
    return relative_paths


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
            f"could not inspect output target for reparse metadata: {path}: {exc}",
        ) from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def stable_target_state(path: Path) -> tuple[Any, ...]:
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
            "output_state_check_failed",
            f"could not safely fingerprint output target {path}: {exc}",
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
            "output_changed_during_preflight",
            f"output target changed while being fingerprinted: {path}",
        )
    return ("file", *after_identity, digest.hexdigest().upper())


def assert_no_protected_alias(
    target: Path,
    protected_paths: Sequence[tuple[Path, str]],
) -> None:
    try:
        resolved_target = target.resolve(strict=False)
    except OSError as exc:
        raise AnalysisError(
            "protected_alias_check_failed",
            f"could not resolve output target {target}: {exc}",
        ) from exc
    for protected_path, alias_code in protected_paths:
        aliases_protected_path = resolved_target == protected_path
        if not aliases_protected_path and target.exists():
            try:
                aliases_protected_path = os.path.samefile(target, protected_path)
            except OSError as exc:
                raise AnalysisError(
                    "protected_alias_check_failed",
                    f"could not compare {target} with protected path {protected_path}: {exc}",
                ) from exc
        if aliases_protected_path:
            raise AnalysisError(
                alias_code,
                f"refusing extraction target that aliases a protected path: {target}",
            )


def destination_path(output_root: Path, relative_path: PurePosixPath) -> Path:
    root_resolved = output_root.resolve(strict=False)
    target = output_root.joinpath(*relative_path.parts)
    target_resolved = target.resolve(strict=False)
    try:
        target_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise AnalysisError(
            "output_escape",
            f"output destination resolves outside extraction root: {relative_path.as_posix()}",
        ) from exc
    return target


def assert_commit_environment_safe(
    output_root: Path,
    relative_path: PurePosixPath,
    target: Path,
    protected_paths: Sequence[tuple[Path, str]],
) -> None:
    recomputed = destination_path(output_root, relative_path)
    if recomputed != target:
        raise AnalysisError(
            "output_destination_changed",
            f"output destination changed after preflight: {relative_path.as_posix()}",
        )
    assert_no_protected_alias(target, protected_paths)
    parent = output_root
    for part in relative_path.parts[:-1]:
        parent = parent / part
        if is_reparse_point(parent):
            raise AnalysisError(
                "reparse_parent_before_commit",
                f"output parent became a reparse point: {parent}",
            )
        if not parent.is_dir():
            raise AnalysisError(
                "invalid_parent_before_commit",
                f"output parent is no longer a directory: {parent}",
            )
    if is_reparse_point(target):
        raise AnalysisError(
            "reparse_target_before_commit",
            f"output target became a reparse point: {target}",
        )


def assert_output_bytes(path: Path, expected: bytes) -> None:
    if is_reparse_point(path) or not path.is_file():
        raise AnalysisError(
            "output_verification_failed",
            f"output is missing, non-file, or a reparse point: {path}",
        )
    try:
        if path.stat().st_size != len(expected) or path.read_bytes() != expected:
            raise AnalysisError(
                "output_verification_failed",
                f"output bytes differ from the planned reconstruction: {path}",
            )
    except OSError as exc:
        raise AnalysisError(
            "output_verification_failed",
            f"could not verify output {path}: {exc}",
        ) from exc


def extraction_output_plan(
    output_root: Path,
    outputs: dict[str, bytes],
    force: bool,
    protected_source: Path | None = None,
    additional_protected_paths: Sequence[Path] = (),
    _state_out: dict[str, tuple[Any, ...]] | None = None,
) -> dict[str, str]:
    relative_paths = validate_output_map(outputs)
    if output_root.exists() and not output_root.is_dir():
        raise AnalysisError(
            "invalid_output_root",
            f"extraction root exists but is not a directory: {output_root}",
        )
    protected_paths = [
        (path.resolve(strict=True), "output_aliases_protected_path")
        for path in additional_protected_paths
    ]
    if protected_source is not None:
        protected_paths.append(
            (protected_source.resolve(strict=True), "output_aliases_input")
        )
    targets: dict[str, Path] = {}
    resolved_destinations: dict[str, str] = {}
    for relative_path in relative_paths:
        name = relative_path.as_posix()
        target = destination_path(output_root, relative_path)
        try:
            resolved_key = str(target.resolve(strict=False)).casefold()
        except OSError as exc:
            raise AnalysisError(
                "output_resolution_failed",
                f"could not resolve output destination {target}: {exc}",
            ) from exc
        if resolved_key in resolved_destinations:
            raise AnalysisError(
                "resolved_output_collision",
                (
                    f"{name!r} and {resolved_destinations[resolved_key]!r} resolve "
                    "to the same destination"
                ),
            )
        resolved_destinations[resolved_key] = name
        targets[name] = target
    plan: dict[str, str] = {}
    for relative_path in relative_paths:
        name = relative_path.as_posix()
        target = targets[name]
        assert_no_protected_alias(target, protected_paths)
        target_state = stable_target_state(target)
        if _state_out is not None:
            _state_out[name] = target_state
        parent = output_root
        for part in relative_path.parts[:-1]:
            parent = parent / part
            if is_reparse_point(parent):
                plan[name] = "would_refuse_reparse_parent"
                break
            if parent.exists() and not parent.is_dir():
                plan[name] = "would_refuse_non_directory_parent"
                break
        if name in plan:
            continue
        if target_state[0] == "reparse":
            plan[name] = "would_refuse_reparse_target"
        elif target_state[0] == "missing":
            plan[name] = "would_write"
        elif target_state[0] != "file":
            plan[name] = "would_refuse_non_file"
        elif (
            target_state[2] == len(outputs[name])
            and target_state[-1] == sha256_bytes(outputs[name])
        ):
            plan[name] = "unchanged"
        elif force:
            plan[name] = "would_overwrite"
        else:
            plan[name] = "would_refuse_different"
    return plan


def write_extraction_outputs(
    output_root: Path,
    outputs: dict[str, bytes],
    force: bool,
    protected_source: Path,
    protected_source_sha256: str,
    protected_source_max_bytes: int,
    additional_protected_paths: Sequence[Path] = (),
    manifest_name: str | None = None,
) -> dict[str, str]:
    preflight_states: dict[str, tuple[Any, ...]] = {}
    plan = extraction_output_plan(
        output_root,
        outputs,
        force,
        protected_source=protected_source,
        additional_protected_paths=additional_protected_paths,
        _state_out=preflight_states,
    )
    refusals = {
        name: status for name, status in plan.items() if status.startswith("would_refuse")
    }
    if refusals:
        detail = ", ".join(f"{name} ({status})" for name, status in refusals.items())
        raise AnalysisError(
            "output_collision",
            f"refusing extraction changes without --force or a safe target: {detail}",
        )

    output_root.mkdir(parents=True, exist_ok=True)
    if manifest_name is None:
        candidates = [
            name
            for name in outputs
            if len(PurePosixPath(name).parts) == 1 and name.endswith(MANIFEST_SUFFIX)
        ]
        if len(candidates) != 1:
            raise AnalysisError(
                "invalid_manifest_count",
                f"expected exactly one top-level extraction manifest, found {len(candidates)}",
            )
        manifest_name = candidates[0]
    if manifest_name not in outputs or len(PurePosixPath(manifest_name).parts) != 1:
        raise AnalysisError(
            "invalid_manifest_name",
            f"exact extraction manifest is absent or not top-level: {manifest_name!r}",
        )
    ordered_names = [name for name in outputs if name != manifest_name] + [manifest_name]
    protected_paths = [
        (path.resolve(strict=True), "output_aliases_protected_path")
        for path in additional_protected_paths
    ]
    protected_paths.append(
        (protected_source.resolve(strict=True), "output_aliases_input")
    )
    targets = {
        name: destination_path(output_root, PurePosixPath(name)) for name in ordered_names
    }
    initial_states = preflight_states
    for name, target in targets.items():
        if stable_target_state(target) != initial_states[name]:
            raise AnalysisError(
                "output_changed_since_preflight",
                f"output target changed immediately after preflight: {target}",
            )
    statuses: dict[str, str] = {}
    staged: list[tuple[str, Path, Path, str]] = []
    try:
        for name in ordered_names:
            if plan[name] == "unchanged":
                statuses[name] = "unchanged"
                continue
            target = targets[name]
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    prefix=(
                        f".coalesced-{sha256_bytes(name.encode('utf-8'))[:12]}-"
                    ),
                    suffix=".part",
                    dir=target.parent,
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    temporary.write(outputs[name])
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

        protected_data, _ = read_bounded_source(
            protected_source,
            protected_source_max_bytes,
        )
        if sha256_bytes(protected_data) != protected_source_sha256:
            raise AnalysisError(
                "source_changed_during_extraction",
                "input changed before extraction commit",
            )

        for name in ordered_names:
            target = targets[name]
            assert_commit_environment_safe(
                output_root,
                PurePosixPath(name),
                target,
                protected_paths,
            )
            if stable_target_state(target) != initial_states[name]:
                raise AnalysisError(
                    "output_changed_since_preflight",
                    f"output target changed after preflight: {target}",
                )

        for name, target, temporary_path, status in staged:
            assert_commit_environment_safe(
                output_root,
                PurePosixPath(name),
                target,
                protected_paths,
            )
            if stable_target_state(target) != initial_states[name]:
                raise AnalysisError(
                    "output_changed_since_preflight",
                    f"output target changed immediately before commit: {target}",
                )
            if name == manifest_name:
                for primary_name in ordered_names:
                    if primary_name == manifest_name:
                        continue
                    assert_commit_environment_safe(
                        output_root,
                        PurePosixPath(primary_name),
                        targets[primary_name],
                        protected_paths,
                    )
                    assert_output_bytes(targets[primary_name], outputs[primary_name])
            os.replace(temporary_path, target)
            statuses[name] = status

        for name in ordered_names:
            assert_commit_environment_safe(
                output_root,
                PurePosixPath(name),
                targets[name],
                protected_paths,
            )
            assert_output_bytes(targets[name], outputs[name])
    finally:
        for _, _, temporary_path, _ in staged:
            if temporary_path.exists():
                temporary_path.unlink()
    return statuses


def manifest_prefix_type(value: str) -> str:
    if not SAFE_PREFIX_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "manifest prefix must be a 1-128 character safe filename component"
        )
    return value


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_path", type=Path)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expect-sha256", type=expected_sha256_type)
    parser.add_argument("--manifest-prefix", type=manifest_prefix_type)
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-records", type=int, default=DEFAULT_MAX_RECORDS)
    parser.add_argument("--max-string-units", type=int, default=DEFAULT_MAX_STRING_UNITS)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
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
    data, initial_stat = read_bounded_source(input_path, args.max_input_bytes)
    source = source_fingerprint(input_path, data)
    if args.expect_sha256 and source["sha256"] != args.expect_sha256:
        raise AnalysisError(
            "expected_hash_mismatch",
            f"expected {args.expect_sha256}, got {source['sha256']}",
        )

    document = parse_coalesced(
        data,
        ParseLimits(
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
            max_string_units=args.max_string_units,
        ),
    )
    prefix = extraction_manifest_prefix(input_path.name, args.manifest_prefix)
    extractor_sha256 = sha256_bytes(Path(__file__).read_bytes())
    parser_path = Path(__file__).with_name("analyze_coalesced_bin.py")
    parser_sha256 = sha256_bytes(parser_path.read_bytes())
    outputs, manifest = build_extraction_outputs(
        document,
        source,
        prefix,
        extractor_sha256,
        parser_sha256,
    )
    output_root = args.output_directory.resolve()
    plan = extraction_output_plan(
        output_root,
        outputs,
        args.force,
        protected_source=input_path,
        additional_protected_paths=(Path(__file__).resolve(), parser_path.resolve()),
    )

    if args.dry_run:
        result = {
            "status": "dry_run",
            "source": source,
            "output_directory": str(output_root),
            "counts": manifest["counts"],
            "output_plan": plan,
        }
    else:
        statuses = write_extraction_outputs(
            output_root,
            outputs,
            args.force,
            protected_source=input_path,
            protected_source_sha256=source["sha256"],
            protected_source_max_bytes=args.max_input_bytes,
            additional_protected_paths=(Path(__file__).resolve(), parser_path.resolve()),
            manifest_name=f"{prefix}{MANIFEST_SUFFIX}",
        )
        result = {
            "status": "complete",
            "source": source,
            "output_directory": str(output_root),
            "counts": manifest["counts"],
            "outputs": statuses,
        }

    verification_data, final_stat = read_bounded_source(
        input_path,
        args.max_input_bytes,
    )
    if (
        initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        or sha256_bytes(verification_data) != source["sha256"]
    ):
        raise AnalysisError(
            "source_changed_during_extraction",
            "input changed during extraction",
        )
    print(
        json.dumps(
            result,
            indent=2 if args.dry_run else None,
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
