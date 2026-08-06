# COALESCED_INT.BIN coalesced-payload analysis

## Outcome

The 821,932-byte source parsed exactly to EOF as an Unreal Engine coalesced configuration/localization cache. The parser recovered 24 logical files, 323 sections, and 5,699 ordered key/value entries without flattening duplicate keys.

The DUST 514 PS3 INT profile matched. This profile result is separate from structural validity.

This analysis covers only the plaintext `.BIN` payload supplied as decrypted. Its parseability establishes plaintext structure, not the history of how it was obtained. NPD/EDAT inspection, key handling, and decryption are explicitly out of scope.

## Source identity

| Property | Value |
| --- | --- |
| Name | `COALESCED_INT.BIN` |
| Size | `821932` (`0xC8AAC`) |
| SHA-256 | `3902C84984DFD62BD7B50185D9AE59F7E73E42F81D3C5D47DD7F2B102DF3931B` |
| MD5 | `610C49481B2674FB12E642BF68439ABC` |
| Validation | `passed` |

## Serialization

- Container and string-length fields are signed 32-bit big-endian integers.
- Negative FString lengths select NUL-terminated UTF-16LE payloads; positive   lengths select NUL-terminated single-byte payloads.
- `11,729` strings are UTF-16LE, `0` are single-byte, and `16` use the zero-length encoding.
- The positive-length single-byte branch is a supported parser convention but was   observed `0` times in this payload.
- The ordered model is file → section → key/value entries. Repeated keys are   retained because UE configuration arrays commonly depend on them.

## Logical file inventory

| # | Embedded source path | Category | Sections | Entries | Serialized bytes |
| ---: | --- | --- | ---: | ---: | ---: |
| 0 | `..\..\DustGame\Config\DustCamera.ini` | configuration | 7 | 25 | 1990 |
| 1 | `..\..\DustGame\Config\DustEngine-DedicatedServerCook.ini` | configuration | 70 | 996 | 84442 |
| 2 | `..\..\DustGame\Config\DustEnlighten.ini` | configuration | 8 | 61 | 5460 |
| 3 | `..\..\DustGame\Config\DustForStatic.ini` | configuration | 2 | 4 | 384 |
| 4 | `..\..\DustGame\Config\DustInput_Shipping.ini` | configuration | 12 | 1230 | 247552 |
| 5 | `..\..\DustGame\Config\DustInstallation.ini` | configuration | 7 | 17 | 1420 |
| 6 | `..\..\DustGame\Config\DustSvc.ini` | configuration | 4 | 6 | 590 |
| 7 | `..\..\DustGame\Config\DustVehicle.ini` | configuration | 5 | 6 | 592 |
| 8 | `..\..\DustGame\Config\DustWeapon.ini` | configuration | 9 | 11 | 1202 |
| 9 | `..\..\DustGame\Config\PS3-DustEngine.ini` | configuration | 73 | 1005 | 85298 |
| 10 | `..\..\DustGame\Config\PS3-DustGame.ini` | configuration | 42 | 276 | 38374 |
| 11 | `..\..\DustGame\Config\PS3-DustInput.ini` | configuration | 12 | 1231 | 247572 |
| 12 | `..\..\Engine\Localization\INT\Core.int` | localization | 7 | 113 | 16914 |
| 13 | `..\..\Engine\Localization\INT\Engine.int` | localization | 35 | 157 | 17250 |
| 14 | `..\..\Engine\Localization\INT\Enlighten.int` | localization | 1 | 102 | 14476 |
| 15 | `..\..\Engine\Localization\INT\GFxUI.int` | localization | 0 | 0 | 88 |
| 16 | `..\..\Engine\Localization\INT\Launch.int` | localization | 2 | 10 | 1610 |
| 17 | `..\..\Engine\Localization\INT\OnlineSubsystemGameSpy.int` | localization | 1 | 3 | 390 |
| 18 | `..\..\Engine\Localization\INT\Startup.int` | localization | 5 | 24 | 3668 |
| 19 | `..\..\Engine\Localization\INT\Subtitles.int` | localization | 1 | 1 | 174 |
| 20 | `..\..\DustGame\Localization\INT\DustGame.int` | localization | 15 | 401 | 48144 |
| 21 | `..\..\DustGame\Localization\INT\Engine.int` | localization | 1 | 2 | 222 |
| 22 | `..\..\DustGame\Localization\INT\Launch.int` | localization | 1 | 4 | 322 |
| 23 | `..\..\DustGame\Localization\INT\PS3.int` | localization | 3 | 14 | 3794 |

## Identity evidence

Marker score: `6/6`; required-path score: `6/6`.

| Marker | File / section / key | Expected value | Result |
| --- | --- | --- | --- |
| `game_name` | `PS3-DustEngine.ini` / `URL` / `GameName` | `Dust 514` | matched |
| `ps3_client` | `PS3-DustEngine.ini` / `Engine.Engine` / `Client` | `PS3Drv.PS3Client` | matched |
| `engine_language` | `PS3-DustEngine.ini` / `Engine.Engine` / `Language` | `INT` | matched |
| `language_name` | `Core.int` / `Language` / `Language` | `English (International)` | matched |
| `language_id` | `Core.int` / `Language` / `LangId` | `9` | matched |
| `save_game_title` | `PS3.int` / `General` / `SaveGameTitle` | `DUST 514®` | matched |

## Structural findings

- Configuration files: `12`; localization files: `12`.
- Exact-case duplicate-key groups: `99` (`3233` entries beyond the first).
- Case-insensitive duplicate-key groups: `99` (`3234` entries beyond the first).
- Exact duplicate key/value groups: `4` (`4` entries beyond the first).
- Empty values: `16`; multiline values: `8`; values containing non-ASCII characters: `19`.
- Longest value: `1170` characters at `DustInput_Shipping.ini` / `DustGame.DustPlayerInput` / `m_inputControllerConfigList`.
- Shannon entropy: `3.850657` bits/byte; NUL-byte fraction: `48.6186%`. The low entropy and complete textual parse show that the supplied payload itself is not an opaque compressed or encrypted container.
- Byte accounting reconciles: `821932` accounted bytes versus `821932` source bytes.

### Largest sections

| File | Section | Entries |
| --- | --- | ---: |
| `DustInput_Shipping.ini` | `DustGame.DustPlayerInput` | 836 |
| `PS3-DustInput.ini` | `DustGame.DustPlayerInput` | 836 |
| `DustInput_Shipping.ini` | `Engine.Console` | 193 |
| `PS3-DustInput.ini` | `Engine.Console` | 193 |
| `PS3-DustEngine.ini` | `Engine.Engine` | 173 |
| `DustEngine-DedicatedServerCook.ini` | `Engine.Engine` | 172 |
| `DustEngine-DedicatedServerCook.ini` | `SystemSettings` | 119 |
| `PS3-DustEngine.ini` | `SystemSettings` | 119 |
| `DustEngine-DedicatedServerCook.ini` | `DustEngine.StandAloneAssetsToCook` | 111 |
| `PS3-DustEngine.ini` | `DustEngine.StandAloneAssetsToCook` | 111 |
| `DustEngine-DedicatedServerCook.ini` | `Core.System` | 102 |
| `Enlighten.int` | `Enlighten` | 102 |

## Configuration content

All configuration values remain strings in the serialized cache. The following classification is syntactic and does not assign runtime types:

| Value shape | Entries |
| --- | ---: |
| `parenthesized_compound` | 2585 |
| `other_string` | 1240 |
| `integer` | 411 |
| `boolean` | 317 |
| `float` | 311 |
| `empty` | 4 |

Dominant section namespaces show that this matched DUST fixture spans gameplay, input, engine, rendering, editor/cook, networking, UI, audio, and texture-streaming settings.

| Case-insensitive section namespace | Exact-case variants | Entries |
| --- | --- | ---: |
| `dustgame` | `DustGame` | 1883 |
| `engine` | `Engine` | 1162 |
| `unrealed` | `UnrealEd` | 295 |
| `systemsettings` | `SystemSettings` | 238 |
| `dustengine` | `DustEngine` | 228 |
| `core` | `Core` | 200 |
| `customstats` | `CustomStats` | 134 |
| `ipdrv` | `IPDrv, IpDrv` | 86 |
| `memorysplitclassestotrack` | `MemorySplitClassesToTrack` | 74 |
| `gfxui` | `GFxUI` | 72 |
| `texturestreaming` | `TextureStreaming` | 58 |
| `configcoalescefilter` | `ConfigCoalesceFilter` | 40 |

## Localization content

The `12` localization records contain `831` entries and `34,073` value characters. `819` entries are nonempty and `12` are empty. The median value is `29` characters and the maximum is `421`.

Formatting evidence includes `96` rows with Unreal backtick placeholders, `73` with bracketed identifier control tokens, and `29` with brace interpolation.

| Largest localization section | File | Entries |
| --- | --- | ---: |
| `Enlighten` | `Engine/Localization/INT/Enlighten.int` | 102 |
| `Hud_Subtitles_LoadingTips` | `DustGame/Localization/INT/DustGame.int` | 99 |
| `Hud_Info` | `DustGame/Localization/INT/DustGame.int` | 94 |
| `Errors` | `Engine/Localization/INT/Core.int` | 77 |
| `Hud_Subtitles_Tutorial` | `DustGame/Localization/INT/DustGame.int` | 57 |
| `Errors` | `Engine/Localization/INT/Engine.int` | 37 |
| `Hud_TriggerHints` | `DustGame/Localization/INT/DustGame.int` | 29 |
| `Hud_WarPoints` | `DustGame/Localization/INT/DustGame.int` | 27 |
| `Hud_Hints` | `DustGame/Localization/INT/DustGame.int` | 22 |
| `Hud_Objectives` | `DustGame/Localization/INT/DustGame.int` | 20 |

## Cross-file comparisons

Comparisons use multisets of `(section, key, value)` occurrences so repeated configuration-array entries remain significant.

| First file | Second file | Shared | First-only | Second-only | Jaccard |
| --- | --- | ---: | ---: | ---: | ---: |
| `DustInput_Shipping.ini` | `PS3-DustInput.ini` | 1230 | 0 | 1 | 0.999188 |
| `DustEngine-DedicatedServerCook.ini` | `PS3-DustEngine.ini` | 943 | 53 | 62 | 0.891304 |

## Network and disclosure review

- Private IP endpoints present in serialized values: `10.1.10.83`, `10.3.4.132`.
- Database aliases: `dev-db`, `production-db`; catalog names: `EngineTaskPerf`, `PerfMem`.
- Ports found in endpoint values or port-named settings: `80`, `6668`, `7777`, `8777`, `9777`, `13000`, `14001`.
- Non-HTTP service identifiers: `sip:confctl-2`.
- Pattern scan found `0` credential-like-key, assignment, URI-userinfo, or long-hexadecimal candidates. No candidate was detected by these bounded patterns.

Private IPs, database aliases, and catalog names are potentially sensitive internal/development metadata. Listed ports may be generic engine defaults and are included as inventory context. This scan is pattern-based and is not a complete semantic security audit.

## Artifacts and limitations

- `COALESCED_INT_source_files.jsonl` records one row per logical file, including section summaries and serialized-region hashes.
- `COALESCED_INT_entries.jsonl.gz` is the canonical ordered entry set; it preserves duplicates, embedded newlines, non-ASCII text, encodings, and offsets.
- `COALESCED_INT_summary.json` and `COALESCED_INT_validation.json` separate observed facts, format validation, profile matching, and fixture-hash matching.
- Embedded `..\..` paths are recorded as data and are never joined to an output directory. No reconstructed INI/INT files are emitted.
- Original standalone comments, formatting whitespace, quoting choices, and include/coalescing provenance are not represented as distinct syntax. Whitespace and comment-like text embedded inside serialized values are preserved.
- Output-directory title, region, and version labels are caller-supplied external provenance; they are not inferred from the serialized payload.
- This run does not establish byte-for-byte identity with any EDAT wrapper because EDAT decryption was deliberately excluded.
