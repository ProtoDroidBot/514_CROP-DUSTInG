from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_DIRECTORY = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = MODULE_DIRECTORY.parent
sys.path.insert(0, str(MODULE_DIRECTORY))

from analyze_coalesced_bin import (  # noqa: E402
    AnalysisError,
    build_entry_rows,
    parse_coalesced,
    sha256_bytes,
    source_fingerprint,
)
from extract_coalesced_files import (  # noqa: E402
    MANIFEST_SUFFIX,
    build_extraction_outputs,
    extraction_output_plan,
    main,
    render_logical_file,
    safe_embedded_relative_path,
    write_extraction_outputs,
)
import extract_coalesced_files as extractor_module  # noqa: E402


def i32(value: int) -> bytes:
    return struct.pack(">i", value)


def fstring(value: str) -> bytes:
    payload = value.encode("utf-16-le") + b"\x00\x00"
    return i32(-(len(payload) // 2)) + payload


def build_document(
    files: list[tuple[str, list[tuple[str, list[tuple[str, str]]]]]],
) -> bytes:
    chunks = [i32(len(files))]
    for source_path, sections in files:
        chunks.extend([fstring(source_path), i32(len(sections))])
        for section_name, entries in sections:
            chunks.extend([fstring(section_name), i32(len(entries))])
            for key, value in entries:
                chunks.extend([fstring(key), fstring(value)])
    return b"".join(chunks)


def sample_document() -> bytes:
    return build_document(
        [
            (
                r"..\..\Game\Config\Sample.cfg",
                [
                    (
                        "First",
                        [
                            ("Repeated", "one"),
                            ("Repeated", "two"),
                            ("Multiline", "line1\nline2"),
                        ],
                    ),
                    ("Empty", []),
                ],
            ),
            (
                r"..\..\Game\Localization\INT\NoExtension",
                [("Text", [("Greeting", "DUST 514®")])],
            ),
        ]
    )


def outputs_for(data: bytes, source_name: str = "TEST.BIN") -> tuple[dict[str, bytes], dict]:
    document = parse_coalesced(data)
    return build_extraction_outputs(
        document,
        source_fingerprint(Path(source_name), data),
        "TEST",
        "A" * 64,
        "B" * 64,
    )


class PathAndRenderingTests(unittest.TestCase):
    def test_safe_path_normalization_is_extension_agnostic(self) -> None:
        self.assertEqual(
            safe_embedded_relative_path(r"..\..\Game\Config\Sample.cfg").as_posix(),
            "Game/Config/Sample.cfg",
        )
        self.assertEqual(
            safe_embedded_relative_path(r"Game\Data\NoExtension").as_posix(),
            "Game/Data/NoExtension",
        )

    def test_unsafe_embedded_paths_are_rejected(self) -> None:
        unsafe = [
            r"C:\Game\Config\A.ini",
            r"\\server\share\A.ini",
            r"..\..\Game\..\escape.ini",
            r"..\..\Game\CON.txt",
            r"..\..\Game\CONIN$.txt",
            r"..\..\Game\AUX .txt",
            "..\\..\\Game\\COM¹.cfg",
            "..\\..\\Game\\LPT²",
            r"..\..\Game\bad:name.ini",
            "..\\..\\Game\\trailing. ",
            "..\\..\\Game\\",
            "..\\..\\Game\\" + ("😀" * 128) + ".ini",
            r"..\..",
        ]
        for value in unsafe:
            with self.subTest(value=value):
                with self.assertRaises(AnalysisError) as raised:
                    safe_embedded_relative_path(value)
                self.assertEqual(raised.exception.code, "unsafe_embedded_path")

    def test_render_preserves_order_duplicates_empty_sections_and_values(self) -> None:
        document = parse_coalesced(sample_document())
        rendered = render_logical_file(document.files[0])
        self.assertEqual(
            rendered,
            (
                "[First]\n"
                "Repeated=one\n"
                "Repeated=two\n"
                "Multiline=line1\nline2\n"
                "\n"
                "[Empty]\n"
                "\n"
            ).encode("utf-8"),
        )

    def test_unrepresentable_section_or_key_is_rejected(self) -> None:
        for section, key in (("Bad]Section", "Key"), ("Section", "Bad=Key")):
            data = build_document(
                [(r"..\..\Game\A.ini", [(section, [(key, "value")])])]
            )
            with self.subTest(section=section, key=key):
                with self.assertRaises(AnalysisError) as raised:
                    outputs_for(data)
                self.assertEqual(raised.exception.code, "unrepresentable_text_record")

    def test_case_insensitive_destination_collision_is_rejected(self) -> None:
        data = build_document(
            [
                (r"..\..\Game\File.ini", [("A", [])]),
                (r"..\..\game\FILE.INI", [("B", [])]),
            ]
        )
        with self.assertRaises(AnalysisError) as raised:
            outputs_for(data)
        self.assertEqual(raised.exception.code, "embedded_path_collision")

    def test_embedded_file_cannot_collide_with_extraction_manifest(self) -> None:
        data = build_document(
            [(r"..\..\TEST_extraction_manifest.json", [("Section", [])])]
        )
        with self.assertRaises(AnalysisError) as raised:
            outputs_for(data)
        self.assertEqual(raised.exception.code, "manifest_path_collision")

    def test_output_file_cannot_also_be_an_ancestor_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(AnalysisError) as raised:
                extraction_output_plan(
                    root,
                    {"A": b"file", "A/B.cfg": b"child"},
                    False,
                )
            self.assertEqual(
                raised.exception.code,
                "output_path_hierarchy_collision",
            )
            self.assertEqual(list(root.iterdir()), [])


class OutputSafetyTests(unittest.TestCase):
    def test_outputs_and_manifest_are_deterministic(self) -> None:
        first, first_manifest = outputs_for(sample_document())
        second, second_manifest = outputs_for(sample_document())
        self.assertEqual(first, second)
        self.assertEqual(first_manifest, second_manifest)
        self.assertIn("Game/Config/Sample.cfg", first)
        self.assertIn("Game/Localization/INT/NoExtension", first)
        self.assertIn(f"TEST{MANIFEST_SUFFIX}", first)
        self.assertEqual(
            first_manifest["counts"]["files_by_extension"],
            {"(none)": 1, ".cfg": 1},
        )
        for row in first_manifest["files"]:
            self.assertEqual(
                sha256_bytes(first[row["output_relative_path"]]),
                row["output_sha256"],
            )

    def test_nested_writes_are_idempotent_and_refuse_differences(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "extracted"
            source.write_bytes(data)
            source_hash = sha256_bytes(data)
            first = write_extraction_outputs(
                destination,
                outputs,
                False,
                source,
                source_hash,
                len(data) + 1,
            )
            self.assertTrue(all(status == "written" for status in first.values()))
            second = write_extraction_outputs(
                destination,
                outputs,
                False,
                source,
                source_hash,
                len(data) + 1,
            )
            self.assertTrue(all(status == "unchanged" for status in second.values()))

            target = destination / "Game" / "Config" / "Sample.cfg"
            target.write_bytes(b"user-owned difference")
            with self.assertRaises(AnalysisError) as raised:
                write_extraction_outputs(
                    destination,
                    outputs,
                    False,
                    source,
                    source_hash,
                    len(data) + 1,
                )
            self.assertEqual(raised.exception.code, "output_collision")
            self.assertEqual(target.read_bytes(), b"user-owned difference")

            forced = write_extraction_outputs(
                destination,
                outputs,
                True,
                source,
                source_hash,
                len(data) + 1,
            )
            self.assertEqual(forced["Game/Config/Sample.cfg"], "overwritten")
            self.assertEqual(target.read_bytes(), outputs["Game/Config/Sample.cfg"])

    def test_staging_failure_cleans_temporary_files(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "extracted"
            source.write_bytes(data)
            with mock.patch(
                "extract_coalesced_files.os.fsync",
                side_effect=OSError("injected fsync failure"),
            ):
                with self.assertRaises(OSError):
                    write_extraction_outputs(
                        destination,
                        outputs,
                        False,
                        source,
                        sha256_bytes(data),
                        len(data) + 1,
                    )
            self.assertEqual(
                list(destination.rglob("*.part")) if destination.exists() else [],
                [],
            )

    def test_target_created_after_preflight_is_not_overwritten(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "extracted"
            source.write_bytes(data)
            raced_target = destination / "Game" / "Config" / "Sample.cfg"
            real_read = extractor_module.read_bounded_source

            def race_after_staging(path: Path, limit: int):
                raced_target.parent.mkdir(parents=True, exist_ok=True)
                raced_target.write_bytes(b"concurrent writer")
                return real_read(path, limit)

            with mock.patch(
                "extract_coalesced_files.read_bounded_source",
                side_effect=race_after_staging,
            ):
                with self.assertRaises(AnalysisError) as raised:
                    write_extraction_outputs(
                        destination,
                        outputs,
                        False,
                        source,
                        sha256_bytes(data),
                        len(data) + 1,
                    )
            self.assertEqual(raised.exception.code, "output_changed_since_preflight")
            self.assertEqual(raced_target.read_bytes(), b"concurrent writer")
            self.assertFalse(
                (destination / f"TEST{MANIFEST_SUFFIX}").exists()
            )
            self.assertEqual(list(destination.rglob("*.part")), [])

    def test_target_created_between_plan_and_state_capture_is_not_overwritten(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "extracted"
            source.write_bytes(data)
            raced_target = destination / "Game" / "Config" / "Sample.cfg"
            real_plan = extractor_module.extraction_output_plan

            def plan_then_race(*args, **kwargs):
                result = real_plan(*args, **kwargs)
                raced_target.parent.mkdir(parents=True, exist_ok=True)
                raced_target.write_bytes(b"created after plan")
                return result

            with mock.patch(
                "extract_coalesced_files.extraction_output_plan",
                side_effect=plan_then_race,
            ):
                with self.assertRaises(AnalysisError) as raised:
                    write_extraction_outputs(
                        destination,
                        outputs,
                        False,
                        source,
                        sha256_bytes(data),
                        len(data) + 1,
                    )
            self.assertEqual(raised.exception.code, "output_changed_since_preflight")
            self.assertEqual(raced_target.read_bytes(), b"created after plan")
            self.assertFalse((destination / f"TEST{MANIFEST_SUFFIX}").exists())

    def test_embedded_manifest_suffix_filename_is_not_control_metadata(self) -> None:
        data = build_document(
            [
                (
                    r"..\..\Game\foo_extraction_manifest.json",
                    [("Section", [("Key", "Value")])],
                )
            ]
        )
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "extracted"
            source.write_bytes(data)
            statuses = write_extraction_outputs(
                destination,
                outputs,
                False,
                source,
                sha256_bytes(data),
                len(data) + 1,
                manifest_name=f"TEST{MANIFEST_SUFFIX}",
            )
            self.assertEqual(
                statuses["Game/foo_extraction_manifest.json"],
                "written",
            )
            self.assertTrue((destination / f"TEST{MANIFEST_SUFFIX}").is_file())

    def test_source_alias_is_rejected_even_with_force(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "Game" / "Config" / "Sample.cfg"
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            with self.assertRaises(AnalysisError) as raised:
                extraction_output_plan(root, outputs, True, protected_source=source)
            self.assertEqual(raised.exception.code, "output_aliases_input")
            self.assertEqual(source.read_bytes(), data)

    def test_hardlink_alias_to_source_is_rejected(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            source.write_bytes(data)
            alias = root / "extracted" / "Game" / "Config" / "Sample.cfg"
            alias.parent.mkdir(parents=True)
            try:
                os.link(source, alias)
            except OSError:
                self.skipTest("hardlinks are unavailable")
            with self.assertRaises(AnalysisError) as raised:
                extraction_output_plan(
                    root / "extracted",
                    outputs,
                    True,
                    protected_source=source,
                )
            self.assertEqual(raised.exception.code, "output_aliases_input")
            self.assertEqual(source.read_bytes(), data)

    def test_non_directory_parent_is_refused_during_preflight(self) -> None:
        outputs, _ = outputs_for(sample_document())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Game").write_bytes(b"not a directory")
            plan = extraction_output_plan(root, outputs, False)
            self.assertEqual(
                plan["Game/Config/Sample.cfg"],
                "would_refuse_non_directory_parent",
            )

    def test_existing_symlink_cannot_redirect_output_outside_root(self) -> None:
        data = sample_document()
        outputs, _ = outputs_for(data)
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            link = root / "Game"
            try:
                link.symlink_to(Path(outside), target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaises(AnalysisError) as raised:
                extraction_output_plan(root, outputs, False)
            self.assertEqual(raised.exception.code, "output_escape")

    def test_resolved_destination_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "B").mkdir()
            link = root / "A"
            try:
                link.symlink_to(root / "B", target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaises(AnalysisError) as raised:
                extraction_output_plan(
                    root,
                    {"A/x.cfg": b"first", "B/x.cfg": b"second"},
                    False,
                )
            self.assertEqual(raised.exception.code, "resolved_output_collision")

    def test_dry_run_and_edat_rejection_write_nothing(self) -> None:
        data = sample_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "TEST.BIN"
            destination = root / "not-created"
            source.write_bytes(data)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            str(source),
                            "--output-directory",
                            str(destination),
                            "--dry-run",
                        ]
                    ),
                    0,
                )
            self.assertFalse(destination.exists())
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "dry_run")

            edat = root / "COALESCED_INT.BIN.EDAT"
            edat.write_bytes(data)
            with self.assertRaises(AnalysisError) as raised:
                main(
                    [
                        str(edat),
                        "--output-directory",
                        str(destination),
                        "--force",
                    ]
                )
            self.assertEqual(raised.exception.code, "edat_input_unsupported")
            self.assertFalse(destination.exists())

            npd_magic = root / "NPD_MAGIC.BIN"
            npd_magic.write_bytes(b"NPD\x00" + b"\x00" * 64)
            with self.assertRaises(AnalysisError) as magic_error:
                main(
                    [
                        str(npd_magic),
                        "--output-directory",
                        str(destination),
                    ]
                )
            self.assertEqual(magic_error.exception.code, "edat_input_unsupported")
            self.assertFalse(destination.exists())

    def test_expected_hash_mismatch_writes_nothing(self) -> None:
        data = sample_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "TEST.BIN"
            destination = root / "extracted"
            source.write_bytes(data)
            with self.assertRaises(AnalysisError) as raised:
                main(
                    [
                        str(source),
                        "--expect-sha256",
                        "0" * 64,
                        "--output-directory",
                        str(destination),
                    ]
                )
            self.assertEqual(raised.exception.code, "expected_hash_mismatch")
            self.assertFalse(destination.exists())
            self.assertEqual(source.read_bytes(), data)


class RealFixtureExtractionTests(unittest.TestCase):
    def test_repository_fixture_outputs_all_logical_files(self) -> None:
        fixture = REPOSITORY_ROOT / "COALESCED_INT.BIN"
        if not fixture.is_file():
            self.skipTest("repository COALESCED_INT.BIN fixture is absent")
        data = fixture.read_bytes()
        document = parse_coalesced(data)
        outputs, manifest = build_extraction_outputs(
            document,
            source_fingerprint(fixture, data),
            "COALESCED_INT",
            "A" * 64,
            "B" * 64,
        )
        self.assertEqual(len(outputs), 25)
        self.assertEqual(manifest["counts"]["logical_files"], 24)
        self.assertEqual(manifest["counts"]["sections"], 323)
        self.assertEqual(manifest["counts"]["entries"], 5_699)
        self.assertEqual(
            manifest["counts"]["files_by_extension"],
            {".ini": 12, ".int": 12},
        )
        self.assertEqual(manifest["counts"]["zero_section_files"], 1)
        self.assertEqual(manifest["counts"]["zero_entry_sections"], 9)
        self.assertEqual(manifest["counts"]["empty_values"], 16)
        self.assertEqual(manifest["counts"]["multiline_values"], 8)
        self.assertEqual(manifest["counts"]["embedded_lf_characters"], 13)
        self.assertEqual(manifest["counts"]["comment_prefix_keys"], 23)
        self.assertEqual(manifest["counts"]["bracketed_key_occurrences"], 47)
        self.assertEqual(manifest["counts"]["values_containing_equals"], 2_619)
        self.assertEqual(manifest["counts"]["leading_whitespace_values"], 1)
        self.assertEqual(manifest["counts"]["trailing_whitespace_values"], 13)
        camera = outputs["DustGame/Config/DustCamera.ini"]
        self.assertTrue(
            camera.startswith(
                b"[DustGame.DustPlayerCameraNew]\nmFadingTime=5\n\n"
            )
        )
        self.assertIn(
            "DUST 514®".encode("utf-8"),
            outputs["DustGame/Localization/INT/PS3.int"],
        )
        self.assertEqual(outputs["Engine/Localization/INT/GFxUI.int"], b"")
        golden_outputs = {
            "Engine/Localization/INT/GFxUI.int": (
                0,
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "DustGame/Config/DustForStatic.ini": (
                130,
                "F7A66B4457AB1CE760C6ECC821AFDF37F408E3BB09BB28AAD90217D23C9BF52E",
            ),
            "DustGame/Localization/INT/PS3.int": (
                1_804,
                "A2A9608F90EB1890F34588F97C54F628CE78C720F070F58A58584B7DCC71F306",
            ),
            "DustGame/Config/DustInput_Shipping.ini": (
                118_795,
                "C6986B9D7F0E49024DD86D3A79818B1A330F75446D6E488D0A640B12C5E0A291",
            ),
        }
        for output_path, (expected_size, expected_hash) in golden_outputs.items():
            with self.subTest(output_path=output_path):
                self.assertEqual(len(outputs[output_path]), expected_size)
                self.assertEqual(sha256_bytes(outputs[output_path]), expected_hash)
        manifest_paths = {row["output_relative_path"] for row in manifest["files"]}
        self.assertEqual(
            manifest_paths,
            set(outputs) - {f"COALESCED_INT{MANIFEST_SUFFIX}"},
        )
        self.assertEqual(len(build_entry_rows(document)), 5_699)


if __name__ == "__main__":
    unittest.main()
