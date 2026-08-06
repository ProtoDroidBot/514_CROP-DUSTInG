from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


MODULE_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = MODULE_DIRECTORY.parent
sys.path.insert(0, str(MODULE_DIRECTORY))

from analyze_coalesced_bin import (  # noqa: E402
    AnalysisError,
    DEFAULT_MAX_RECORDS,
    FormatError,
    ParseLimits,
    build_artifacts,
    build_content_analysis,
    build_entry_rows,
    build_file_rows,
    build_profile_evidence,
    build_summary,
    build_validation,
    casefold_sorted,
    deterministic_gzip,
    file_category,
    main,
    output_plan,
    parse_coalesced,
    render_report,
    sha256_bytes,
    source_fingerprint,
    write_artifacts,
)
import analyze_coalesced_bin as analyzer_module  # noqa: E402


def i32(value: int) -> bytes:
    return struct.pack(">i", value)


def fstring(value: str, encoding: str = "unicode") -> bytes:
    if encoding == "zero":
        if value:
            raise ValueError("zero-length FString must be empty")
        return i32(0)
    if encoding == "unicode":
        payload = value.encode("utf-16-le") + b"\x00\x00"
        return i32(-(len(payload) // 2)) + payload
    if encoding == "ansi":
        payload = value.encode("latin-1") + b"\x00"
        return i32(len(payload)) + payload
    raise ValueError(f"unknown FString encoding {encoding}")


def build_fixture() -> bytes:
    return b"".join(
        [
            i32(1),
            fstring(r"..\..\Game\Config\Test.ini"),
            i32(2),
            fstring("Section"),
            i32(4),
            fstring("Repeated", "ansi"),
            fstring("one"),
            fstring("Repeated", "ansi"),
            fstring("two"),
            fstring("EmptyWide"),
            fstring("", "unicode"),
            fstring("EmptyZero"),
            fstring("", "zero"),
            fstring("EmptySection", "ansi"),
            i32(0),
        ]
    )


class ParserTests(unittest.TestCase):
    def test_valid_mixed_encoding_and_duplicate_order(self) -> None:
        data = build_fixture()
        document = parse_coalesced(data)
        self.assertEqual(document.parsed_bytes, len(data))
        self.assertEqual(document.declared_file_count, 1)
        self.assertEqual(len(document.files[0].sections), 2)
        entries = document.files[0].sections[0].entries
        self.assertEqual([entry.key.text for entry in entries], [
            "Repeated",
            "Repeated",
            "EmptyWide",
            "EmptyZero",
        ])
        self.assertEqual([entry.value.text for entry in entries], ["one", "two", "", ""])
        self.assertEqual(document.ansi_string_count, 3)
        self.assertEqual(document.empty_string_count, 1)
        rows = build_entry_rows(document)
        self.assertEqual([row["key_occurrence"] for row in rows], [1, 2, 1, 1])
        self.assertEqual(rows[2]["value_serialized_length"], -1)
        self.assertEqual(rows[3]["value_serialized_length"], 0)

    def test_every_truncation_is_controlled(self) -> None:
        data = build_fixture()
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                with self.assertRaises(FormatError):
                    parse_coalesced(data[:cut])

    def test_trailing_data_is_rejected(self) -> None:
        with self.assertRaises(FormatError) as raised:
            parse_coalesced(build_fixture() + b"garbage")
        self.assertEqual(raised.exception.code, "trailing_bytes")
        self.assertEqual(raised.exception.offset, len(build_fixture()))

    def test_negative_and_infeasible_counts_are_rejected(self) -> None:
        with self.assertRaises(FormatError) as negative:
            parse_coalesced(i32(-1))
        self.assertEqual(negative.exception.code, "negative_container_count")

        with self.assertRaises(FormatError) as infeasible:
            parse_coalesced(i32(100) + b"\x00" * 8)
        self.assertEqual(infeasible.exception.code, "infeasible_container_count")

    def test_int32_min_fstring_length_is_rejected(self) -> None:
        data = i32(1) + i32(-(1 << 31)) + b"\x00" * 4
        with self.assertRaises(FormatError) as raised:
            parse_coalesced(data)
        self.assertEqual(raised.exception.code, "fstring_length_overflow")

    def test_missing_terminators_are_rejected(self) -> None:
        unicode_blob = i32(1) + i32(-2) + "A".encode("utf-16-le") + b"B\x00" + i32(0)
        with self.assertRaises(FormatError) as unicode_error:
            parse_coalesced(unicode_blob)
        self.assertEqual(unicode_error.exception.code, "missing_utf16_terminator")

        ansi_blob = i32(1) + i32(2) + b"AB" + i32(0)
        with self.assertRaises(FormatError) as ansi_error:
            parse_coalesced(ansi_blob)
        self.assertEqual(ansi_error.exception.code, "missing_ansi_terminator")

    def test_invalid_utf16_is_rejected(self) -> None:
        # An unpaired high surrogate followed by the required NUL terminator.
        data = i32(1) + i32(-2) + b"\x00\xD8\x00\x00" + i32(0)
        with self.assertRaises(FormatError) as raised:
            parse_coalesced(data)
        self.assertEqual(raised.exception.code, "invalid_utf16")

    def test_edat_magic_is_rejected(self) -> None:
        with self.assertRaises(FormatError) as raised:
            parse_coalesced(b"NPD\x00" + b"\x00" * 128)
        self.assertEqual(raised.exception.code, "edat_input_unsupported")

    def test_input_and_aggregate_limits_are_enforced(self) -> None:
        with self.assertRaises(FormatError) as size_error:
            parse_coalesced(build_fixture(), ParseLimits(max_input_bytes=8))
        self.assertEqual(size_error.exception.code, "input_size_limit")

        with self.assertRaises(FormatError) as record_error:
            parse_coalesced(build_fixture(), ParseLimits(max_records=2))
        self.assertEqual(record_error.exception.code, "aggregate_record_limit")

        self.assertEqual(parse_coalesced(build_fixture(), ParseLimits(max_records=7)).parsed_bytes, len(build_fixture()))
        with self.assertRaises(FormatError):
            parse_coalesced(build_fixture(), ParseLimits(max_records=6))
        self.assertLessEqual(DEFAULT_MAX_RECORDS, 50_000)


class ArtifactTests(unittest.TestCase):
    def make_artifacts(self) -> dict[str, bytes]:
        data = build_fixture()
        document = parse_coalesced(data)
        source = source_fingerprint(Path("TEST.BIN"), data)
        files = build_file_rows(document)
        entries = build_entry_rows(document)
        profile = build_profile_evidence(document)
        summary = build_summary(
            document,
            source,
            "A" * 64,
            files,
            entries,
            profile,
        )
        validation = build_validation(
            document,
            source,
            files,
            entries,
            profile,
            "generic",
            False,
            source["sha256"],
        )
        report = render_report(summary, validation, files, "TEST.BIN", "TEST")
        return build_artifacts(
            summary,
            validation,
            files,
            entries,
            report,
            "TEST",
        )

    def test_artifact_bytes_and_gzip_are_deterministic(self) -> None:
        first = self.make_artifacts()
        second = self.make_artifacts()
        self.assertEqual(first, second)
        self.assertEqual(deterministic_gzip(b"example\n"), deterministic_gzip(b"example\n"))
        manifest = json.loads(first["TEST_artifact_manifest.json"])
        for row in manifest["artifacts"]:
            payload = first[row["name"]]
            self.assertEqual(row["size_bytes"], len(payload))
            self.assertEqual(row["sha256"], sha256_bytes(payload))
        entry_lines = gzip.decompress(first["TEST_entries.jsonl.gz"]).decode("utf-8").splitlines()
        self.assertEqual(len(entry_lines), 4)
        self.assertEqual(
            [json.loads(line)["global_entry_index"] for line in entry_lines],
            [0, 1, 2, 3],
        )
        self.assertIn("The `0` localization records", first["TEST_report.md"].decode("utf-8"))

    def test_casefold_sort_is_cross_process_deterministic(self) -> None:
        code = (
            "import sys;"
            f"sys.path.insert(0,{str(MODULE_DIRECTORY)!r});"
            "from analyze_coalesced_bin import casefold_sorted;"
            "print(casefold_sorted({'alpha','ALPHA','Beta','beta'}))"
        )
        outputs = []
        for seed in ("1", "77"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            outputs.append(
                subprocess.check_output(
                    [sys.executable, "-B", "-c", code],
                    env=environment,
                    text=True,
                )
            )
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(
            casefold_sorted({"alpha", "ALPHA", "Beta", "beta"}),
            ["ALPHA", "alpha", "Beta", "beta"],
        )

    def test_idempotent_writes_and_collision_refusal(self) -> None:
        artifacts = self.make_artifacts()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            first = write_artifacts(output, artifacts, force=False)
            self.assertTrue(all(status == "written" for status in first.values()))
            second = write_artifacts(output, artifacts, force=False)
            self.assertTrue(all(status == "unchanged" for status in second.values()))

            changed = dict(artifacts)
            changed["TEST_summary.json"] += b"different"
            with self.assertRaises(AnalysisError) as raised:
                write_artifacts(output, changed, force=False)
            self.assertEqual(raised.exception.code, "output_collision")
            self.assertEqual((output / "TEST_summary.json").read_bytes(), artifacts["TEST_summary.json"])

    def test_writer_rejects_unsafe_names_and_source_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            source.write_bytes(b"source")
            with self.assertRaises(AnalysisError) as unsafe:
                output_plan(root, {"../escape": b"x"}, False)
            self.assertEqual(unsafe.exception.code, "unsafe_artifact_name")
            with self.assertRaises(AnalysisError) as alias:
                write_artifacts(
                    root,
                    {"source.bin": b"replacement"},
                    True,
                    protected_source=source,
                )
            self.assertEqual(alias.exception.code, "output_aliases_input")
            self.assertEqual(source.read_bytes(), b"source")

            hardlink = root / "source-hardlink.bin"
            try:
                os.link(source, hardlink)
            except OSError:
                return
            with self.assertRaises(AnalysisError) as hardlink_alias:
                write_artifacts(
                    root,
                    {hardlink.name: b"replacement"},
                    True,
                    protected_source=source,
                )
            self.assertEqual(hardlink_alias.exception.code, "output_aliases_input")
            self.assertEqual(source.read_bytes(), b"source")

    def test_manifest_is_committed_last_and_staged_files_are_cleaned(self) -> None:
        old = {
            "A.json": b"old-a",
            "B.json": b"old-b",
            "X_artifact_manifest.json": b"old-manifest",
        }
        new = {
            "A.json": b"new-a",
            "B.json": b"new-b",
            "X_artifact_manifest.json": b"new-manifest",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_artifacts(root, old, False)
            real_replace = os.replace
            replacements = []

            def fail_second_replace(source: object, target: object) -> None:
                replacements.append(Path(target).name)
                if len(replacements) == 2:
                    raise OSError("injected commit failure")
                real_replace(source, target)

            with mock.patch(
                "analyze_coalesced_bin.os.replace",
                side_effect=fail_second_replace,
            ):
                with self.assertRaises(OSError):
                    write_artifacts(root, new, True)
            self.assertEqual(replacements, ["A.json", "B.json"])
            self.assertEqual((root / "A.json").read_bytes(), b"new-a")
            self.assertEqual((root / "B.json").read_bytes(), b"old-b")
            self.assertEqual(
                (root / "X_artifact_manifest.json").read_bytes(),
                b"old-manifest",
            )
            self.assertEqual(list(root.glob("*.part")), [])

    def test_artifact_staging_failure_cleans_temporary_file(self) -> None:
        artifacts = self.make_artifacts()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch(
                "analyze_coalesced_bin.os.fsync",
                side_effect=OSError("injected fsync failure"),
            ):
                with self.assertRaises(OSError):
                    write_artifacts(root, artifacts, False)
            self.assertEqual(list(root.glob("*.part")), [])

    def test_artifact_created_after_plan_is_not_overwritten(self) -> None:
        artifacts = self.make_artifacts()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raced_target = root / "TEST_summary.json"
            real_plan = analyzer_module.output_plan

            def plan_then_race(*args, **kwargs):
                result = real_plan(*args, **kwargs)
                raced_target.parent.mkdir(parents=True, exist_ok=True)
                raced_target.write_bytes(b"created after plan")
                return result

            with mock.patch(
                "analyze_coalesced_bin.output_plan",
                side_effect=plan_then_race,
            ):
                with self.assertRaises(AnalysisError) as raised:
                    write_artifacts(root, artifacts, False)
            self.assertEqual(raised.exception.code, "artifact_changed_since_preflight")
            self.assertEqual(raced_target.read_bytes(), b"created after plan")
            self.assertFalse((root / "TEST_artifact_manifest.json").exists())

    def test_dry_run_writes_nothing(self) -> None:
        data = build_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "TEST.BIN"
            output = root / "not-created"
            source.write_bytes(data)
            before = (source.stat().st_size, source.stat().st_mtime_ns, sha256_bytes(data))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(
                    [
                        str(source),
                        "--profile",
                        "generic",
                        "--output-directory",
                        str(output),
                        "--dry-run",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertFalse(output.exists())
            after_data = source.read_bytes()
            after = (
                source.stat().st_size,
                source.stat().st_mtime_ns,
                sha256_bytes(after_data),
            )
            self.assertEqual(before, after)
            self.assertIn('"status": "dry_run"', stdout.getvalue())

    def test_edat_suffix_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "COALESCED_INT.BIN.EDAT"
            output = root / "artifacts"
            source.write_bytes(build_fixture())
            with self.assertRaises(AnalysisError) as raised:
                main([str(source), "--output-directory", str(output), "--force"])
            self.assertEqual(raised.exception.code, "edat_input_unsupported")
            self.assertFalse(output.exists())

    def test_cli_input_limit_is_checked_before_output(self) -> None:
        data = build_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "TEST.BIN"
            output = root / "artifacts"
            source.write_bytes(data)
            with self.assertRaises(AnalysisError) as raised:
                main(
                    [
                        str(source),
                        "--output-directory",
                        str(output),
                        "--max-input-bytes",
                        str(len(data) - 1),
                    ]
                )
            self.assertEqual(raised.exception.code, "input_size_limit")
            self.assertFalse(output.exists())

    def test_output_target_cannot_alias_input_even_with_force(self) -> None:
        data = build_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "X_summary.json"
            source.write_bytes(data)
            with self.assertRaises(AnalysisError) as raised:
                main(
                    [
                        str(source),
                        "--output-directory",
                        str(root),
                        "--artifact-prefix",
                        "X",
                        "--force",
                    ]
                )
            self.assertEqual(raised.exception.code, "output_aliases_input")
            self.assertEqual(source.read_bytes(), data)

    def test_unchecked_expected_hash_is_not_reported_as_a_match(self) -> None:
        data = build_fixture()
        document = parse_coalesced(data)
        source = source_fingerprint(Path("TEST.BIN"), data)
        files = build_file_rows(document)
        entries = build_entry_rows(document)
        validation = build_validation(
            document,
            source,
            files,
            entries,
            build_profile_evidence(document),
            "generic",
            False,
            None,
        )
        self.assertIsNone(validation["matches_expected_fixture_hash"])
        expected_check = next(
            check for check in validation["checks"] if check["name"] == "expected_sha256"
        )
        self.assertEqual(expected_check["status"], "not_checked")

    def test_credential_like_key_is_reported_only_as_a_candidate(self) -> None:
        data = b"".join(
            [
                i32(1),
                fstring(r"..\..\Game\Config\Secrets.ini"),
                i32(1),
                fstring("Service"),
                i32(1),
                fstring("Password"),
                fstring("hunter2"),
            ]
        )
        document = parse_coalesced(data)
        disclosure = build_content_analysis(
            document,
            build_entry_rows(document),
        )["network_and_disclosure_review"]
        self.assertTrue(disclosure["credential_candidate_detected_by_patterns"])
        self.assertEqual(
            disclosure["credential_assignment_or_token_hits"][0]["reasons"],
            ["credential_like_key_with_nonempty_value"],
        )


class RealFixtureIntegrationTests(unittest.TestCase):
    def test_repository_fixture(self) -> None:
        fixture = REPOSITORY_ROOT / "COALESCED_INT.BIN"
        if not fixture.is_file():
            self.skipTest("repository COALESCED_INT.BIN fixture is absent")
        data = fixture.read_bytes()
        document = parse_coalesced(data)
        self.assertEqual(len(data), 821_932)
        self.assertEqual(
            sha256_bytes(data),
            "3902C84984DFD62BD7B50185D9AE59F7E73E42F81D3C5D47DD7F2B102DF3931B",
        )
        self.assertEqual(len(document.files), 24)
        self.assertEqual(sum(len(item.sections) for item in document.files), 323)
        self.assertEqual(
            sum(len(section.entries) for item in document.files for section in item.sections),
            5_699,
        )
        self.assertEqual(document.parsed_bytes, 0xC8AAC)
        self.assertEqual(document.files[0].path.text, r"..\..\DustGame\Config\DustCamera.ini")
        first = document.files[0].sections[0].entries[0]
        self.assertEqual((first.key.text, first.value.text), ("mFadingTime", "5"))
        self.assertEqual(document.empty_string_count, 16)
        self.assertEqual(document.ansi_string_count, 0)
        self.assertEqual(file_category(document.files[0].path.text), "configuration")
        file_rows = build_file_rows(document)
        entry_rows = build_entry_rows(document)
        profile = build_profile_evidence(document)
        summary = build_summary(
            document,
            source_fingerprint(fixture, data),
            "A" * 64,
            file_rows,
            entry_rows,
            profile,
        )
        self.assertTrue(profile["matched"])
        self.assertTrue(summary["byte_accounting"]["reconciles"])
        self.assertEqual(summary["counts"]["duplicate_key_groups"], 99)
        self.assertEqual(
            summary["counts"]["duplicate_key_entries_beyond_first"],
            3_233,
        )
        self.assertEqual(
            summary["counts"]["case_insensitive_duplicate_key_groups"],
            99,
        )
        self.assertEqual(
            summary["counts"][
                "case_insensitive_duplicate_key_entries_beyond_first"
            ],
            3_234,
        )
        localization = summary["content_analysis"]["localization"]
        self.assertEqual(localization["rows_with_control_tokens"], 73)
        launch_general = [
            row
            for row in localization["largest_sections"]
            if row["file_leaf"] == "Launch.int" and row["section"] == "General"
        ]
        self.assertEqual(len(launch_general), 2)
        self.assertEqual([row["entry_count"] for row in launch_general], [4, 4])
        casefold_namespaces = summary["content_analysis"]["configuration"][
            "section_namespace_entry_counts_case_insensitive"
        ]
        ipdrv = next(
            row for row in casefold_namespaces if row["namespace_casefold"] == "ipdrv"
        )
        self.assertEqual(ipdrv["entry_count"], 86)
        self.assertEqual(ipdrv["variants"], ["IPDrv", "IpDrv"])
        disclosure = summary["content_analysis"]["network_and_disclosure_review"]
        self.assertIn(6_668, disclosure["configured_ports"])
        self.assertNotIn(1, disclosure["configured_ports"])
        self.assertIn("sip:confctl-2", disclosure["service_identifiers"])
        self.assertFalse(disclosure["credential_candidate_detected_by_patterns"])


if __name__ == "__main__":
    unittest.main()
