# Decrypted coalesced-configuration analysis

This component analyzes already-decrypted Unreal Engine coalesced configuration
payloads such as the repository-root `COALESCED_INT.BIN`. It is deliberately
separate from the Ghidra `EBOOT.elf` Steps 1-9 workflow:

- `Invoke-EbootAnalysisWorkflow.ps1` does not call this analyzer.
- This component has no Ghidra project, lock, checkpoint, or mutation dependency.
- It never reads, decrypts, validates, or rewrites a sibling EDAT.
- It never changes the source `.BIN`.

## Current verified result

The `NPUB30643/var1/0319` plaintext fixture is a DUST 514 PS3 Unreal Engine
coalesced configuration and English/`INT` localization cache.

| Property | Verified value |
| --- | --- |
| Source size | `821932` bytes (`0xC8AAC`) |
| SHA-256 | `3902C84984DFD62BD7B50185D9AE59F7E73E42F81D3C5D47DD7F2B102DF3931B` |
| Logical files | `24` (`12` configuration and `12` localization) |
| Sections | `323` |
| Ordered key/value entries | `5699` |
| Parsed end | `0xC8AAC`, with zero trailing bytes |

The parser preserves file, section, and entry order. It does not flatten a
section into a dictionary because repeated Unreal configuration keys carry
array/multimap semantics. The current fixture contains 99 repeated-key groups:
3,233 additional occurrences by exact-case matching and 3,234 by
case-insensitive Unreal-style key matching.

## Reproduce

Use Python 3.10 or newer. On this workstation `python` is not currently on
`PATH`; validation used
`C:\Users\sebor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`.
Substitute that executable for `python` in the examples when reproducing here.
A dry run performs all parsing, profile detection,
hash validation, content analysis, and artifact rendering in memory without
creating an output directory:

```powershell
python .\coalesced\analyze_coalesced_bin.py .\COALESCED_INT.BIN `
    --profile dust514-ps3-int `
    --require-profile `
    --expect-sha256 3902C84984DFD62BD7B50185D9AE59F7E73E42F81D3C5D47DD7F2B102DF3931B `
    --output-directory .\coalesced\artifacts\NPUB30643\var1\0319 `
    --dry-run
```

Generate or verify the deterministic artifacts by removing `--dry-run`:

```powershell
python .\coalesced\analyze_coalesced_bin.py .\COALESCED_INT.BIN `
    --profile dust514-ps3-int `
    --require-profile `
    --expect-sha256 3902C84984DFD62BD7B50185D9AE59F7E73E42F81D3C5D47DD7F2B102DF3931B `
    --output-directory .\coalesced\artifacts\NPUB30643\var1\0319
```

Existing byte-identical artifacts are reported as `unchanged`. A different
existing artifact is refused unless `--force` is explicitly supplied. The
analyzer preflights every target before writing and uses an atomic temporary
file in the destination directory. All temporary files are staged before any
replacement and the manifest is committed last. The multi-file replacement is
not transactional; if the operating system fails during commit, verifying the
old manifest detects a mixed generation.

Run the standard-library test suite with:

```powershell
python -m unittest discover -s .\coalesced\tests -v
```

## Binary model

The observed grammar is:

```text
signed BE int32 file_count
repeat file_count:
    FString embedded_source_path
    signed BE int32 section_count
    repeat section_count:
        FString section_name
        signed BE int32 entry_count
        repeat entry_count:
            FString key
            FString value
```

A negative FString length is a UTF-16 code-unit count including the final NUL;
the payload in this file is UTF-16LE. The parser convention for a positive
length is a NUL-terminated single-byte payload decoded losslessly as Latin-1,
but this fixture contains zero positive-length strings. Zero is the empty-string
encoding. The parser requires valid terminators, strict UTF-16, bounded counts
and lengths, aggregate record limits, and exact EOF.

## Artifacts

`artifacts/NPUB30643/var1/0319/` contains:

- `COALESCED_INT_summary.json` - source identity, serialization facts, counts,
  duplicate-key analysis, value/localization statistics, cross-file comparisons,
  and a pattern-based disclosure review.
- `COALESCED_INT_validation.json` - exact-EOF, byte-accounting, row-count,
  UE3-shape, DUST/PS3/INT-profile, and expected-hash checks.
- `COALESCED_INT_source_files.jsonl` - one ordered row per embedded source file,
  including section summaries and the SHA-256 of its serialized byte range.
- `COALESCED_INT_entries.jsonl.gz` - the canonical ordered key/value dataset,
  including all ordinals, duplicate occurrence numbers, encodings, lengths, and
  source offsets. Gzip output is deterministic (`mtime=0`).
- `COALESCED_INT_report.md` - human-readable findings and limitations.
- `COALESCED_INT_artifact_manifest.json` - size and SHA-256 for every primary
  artifact.

No embedded files are reconstructed by default. Their serialized paths begin
with `..\..`; the analyzer records those strings verbatim and never treats them
as output paths.

## Extract logical files

Extraction is an explicit second operation, implemented by the separate
`extract_coalesced_files.py` command. It parses the source `.BIN` directly with
the bounded parser; it does not consume possibly stale report artifacts and is
not called by either Ghidra/EBOOT workflow script.

Preview all destinations without writing:

```powershell
python .\coalesced\extract_coalesced_files.py .\COALESCED_INT.BIN `
    --expect-sha256 3902C84984DFD62BD7B50185D9AE59F7E73E42F81D3C5D47DD7F2B102DF3931B `
    --output-directory .\coalesced\extracted\NPUB30643\var1\0319 `
    --dry-run
```

Remove `--dry-run` to write the tree. The current fixture produces all 24
logical files beneath their normalized paths: 12 `.ini` and 12 `.int`. The
extractor has no extension whitelist; a different valid coalesced payload can
emit other extensions or extensionless files.

Every embedded path is treated as untrusted. The extractor removes only leading
`.`/`..` components and rejects absolute/UNC/drive paths, internal traversal,
Windows-invalid or reserved components, trailing dots/spaces, destinations that
resolve outside the requested root, and case-insensitive collisions. It
preflights every output, refuses different existing files unless `--force` is
explicit, stages temporary files before commit, and commits
`COALESCED_INT_extraction_manifest.json` last. It never clears unrelated files.
The multi-file commit is not transactional; an interrupted commit leaves the old
manifest in place so hash verification exposes any mixed generation.

The reconstructed files use UTF-8 without a BOM and generated LF separators.
Section order, entry order, duplicate keys, empty sections, empty values,
non-ASCII characters, and embedded value line breaks/whitespace are preserved.
They are semantic reconstructions, not original file-byte recovery: original
layout and standalone comments were not serialized. In this fixture 23 keys
begin `;` or `#`, and eight values are multiline, so a conventional INI parser
may reinterpret a literal extracted file. The analysis JSONL remains the
canonical lossless record representation of the coalesced cache.

## EDAT boundary

An input whose name ends in `.EDAT` or whose bytes start with `NPD\0` is rejected
even when `--force` is present. EDAT metadata, keys, decryption, and plaintext
comparison will be a separate future activity. The present report therefore
does not claim a cryptographic byte-for-byte match with an EDAT payload.

## Limits of interpretation

The cache contains editor, cooker, server, and development defaults in addition
to PS3 client settings. Presence does not prove that every setting was active at
runtime. Original standalone comments, formatting whitespace, quoting choices,
includes, and pre-coalescing provenance are not represented as distinct syntax.
Whitespace and comment-like text embedded inside serialized values is preserved,
so the ordered entry artifact is lossless for the cache but not a byte-identical
reconstruction of the original source files.

The `NPUB30643/var1/0319` artifact-directory labels are external provenance; the
raw strings do not contain that title ID, region label, or version. The plaintext
structure does not independently prove that a decryption operation occurred.

The disclosure review is a bounded pattern scan, not a complete security audit.
It identifies internal IPs, database aliases/catalogs, ports, URLs, service
identifiers, and bounded credential-candidate shapes while retaining the full
ordered evidence in the entry artifact. It does not determine whether any
candidate would be usable.
