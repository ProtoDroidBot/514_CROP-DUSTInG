# Reproducing the DUST 514 RPCS3 EdgeZlib fallback patch

## Purpose

This document records how the DUST 514 loading/video-loop failure was isolated and how to reproduce the RPCS3 game patch that works around it.

The visible looping Bink video is not the underlying fault. The game is retaining or replaying its last loading movie while an asynchronous package load waits indefinitely for an EdgeZlib SPU decompression job. The workaround redirects jobs that would use EdgeZlib to a synchronous PPU zlib fallback already present in the game executable.

The patch does not modify movie playback, skip packages, fake a completion event, or replace decompressed data.

## Verified target

| Property | Verified value |
| --- | --- |
| Title | DUST 514 |
| Serial | `NPUB30643` |
| Application version | `03.19` |
| RPCS3 version used for final verification | `v0.0.42-19679-d509eb86` |
| Emulated firmware | `4.91` |
| EBOOT SHA-256 | `156558691375E7C3034DF98D7BB9B6DDE3EB2A55F023F68519549C027ED6C17A` |
| RPCS3 PPU executable hash | `PPU-ae3f946dfcb103b782f73f1cc5f90587e652f439` |
| Patch SHA-256 | `A72C0917B11B162F12B38EA157CC772CDA54B487897848556F249EF9D217BC15` |

The patch key is tied to the RPCS3 PPU hash and the YAML title/version filter. A different executable or application version must be analyzed independently; do not transplant the address blindly.

## Files in this workspace

- `EBOOT.elf` — analyzed executable.
- `NPUB30643_edgezlib_fallback_patch.yml` — working RPCS3 patch.
- `inventory/ghidra_scripts/PrintFunctionListing.java` — read-only Ghidra listing script used to verify instruction bytes and addresses.
- `ghidra_output_step3/dust.gpr` — analyzed Ghidra project used during this investigation.
- `rpcs3.DMP` and `rpcs3_static.DMP` — diagnostic process dumps. They are not required to reproduce the final patch.

## 1. Reproduce and identify the unpatched failure

1. Disable `Force PPU zlib fallback (EdgeZlib bypass)` in RPCS3's Game Patches manager.
2. Boot NPUB30643 and proceed through login and EULA acceptance.
3. Observe the loading/TIP screen or the last Bink video remaining on screen indefinitely.
4. Inspect `RPCS3.log` for `CHARACTERICONS_SF.XXX`.
5. Stop emulation after the screen has remained stuck. RPCS3 will then log the final file offset while closing open file descriptors.

The characteristic failure is:

```text
sys_fs_open(): .../COOKEDPS3/CHARACTERICONS_SF.XXX ...
...
sys_fs_close(...): .../CHARACTERICONS_SF.XXX ... Pos/Size: 64KB/0.569336MB (0x10000/0x91c00)
```

The close normally appears only when emulation is stopped. While the game is hung, the file remains open and no successor package load appears.

This exact `0x10000` boundary was reproduced across CPU/SPU decoder and scheduler configurations. Removing `EMPTY.BIK` merely changed the retained audiovisual symptom; it did not unblock the loader.

Useful PowerShell log query:

```powershell
$rpcs3Log = 'G:\rpcs3-v0.0.32-16396-f1ef3bdc_win64\log\RPCS3.log'
Select-String -LiteralPath $rpcs3Log -Pattern 'Applied patch|PPU executable hash|CHARACTERICONS_SF\.XXX'
```

## 2. Establish that the package data is not corrupt

The failing package is a valid UE3 compressed package. Its zlib streams can be enumerated and decompressed offline, including all 41 streams examined during this investigation. Other compressed packages, including `LOGINSCENE.XXX`, can also complete in RPCS3.

This evidence narrows the failure from malformed package data to the runtime path responsible for dispatching or completing a particular decompression request.

The `64KB` file offset is the async reader's input-buffer boundary. It is not evidence that byte `0x10000` in the package is intrinsically invalid.

## 3. Negative controls that narrowed the fault domain

The following changes did not resolve the original `CHARACTERICONS_SF.XXX` stall:

- PPU LLVM versus interpreter/static decoder choices.
- Multiple SPU decoder choices.
- RPCS3, alternative, and operating-system scheduler modes.
- Accurate cache-line store and reservation settings.
- SPU reservation busy waiting and PPU reservation priority changes.
- MFC shuffling-related settings.
- SPU GETLLAR spin optimization changes.
- Startup/movie command-line switches such as `-NoLoadStartupPackages`, `NoStartupMovies`, and `-nomovie`.

Two queue-depth canaries modified the game's EdgeZlib LFQueue depth at both its allocation-size and initialization sites:

- Depth 2 caused an earlier loader regression: `COMPACTBULKDATAINFO_SF.XXX` stopped at its first `64KB` buffer.
- Depth 1 allowed startup and `LOGINSCENE.XXX` to complete, but `CHARACTERICONS_SF.XXX` still stopped at exactly `0x10000/0x91c00`.

Those results ruled out the original queue capacity of 32 and overlapping outstanding descriptors as sufficient explanations. They also showed why further queue-size guessing was not a useful patch strategy.

## 4. Locate the EdgeZlib setup in Ghidra

Import `EBOOT.elf` as a PlayStation 3 ELF/PowerPC 64-bit big-endian executable. A PS3-aware Ghidra loader is useful for resolving compact function descriptors and imports.

Search for these strings:

```text
edgeZlibTaskSet
edgezlib_inflate_queue.cpp
Decompress
```

Relevant setup functions in this executable are:

| Address | Observed role |
| --- | --- |
| `0x00674484` | Creates `edgeZlibTaskSet`, event flag, LFQueue, and EdgeZlib SPURS task. |
| `0x009f3498` | Returns the LFQueue allocation size: `depth * 0x20 + 0x80`. |
| `0x009f37a4` | Initializes the SPURS LFQueue with 32-byte entries. |
| `0x009f3908` | Creates the embedded `edgezlib_inflate_ta` SPURS task. |

The setup caller passes one task to `FUN_00674484`. This eliminated the idea that an unexpectedly large task count was responsible for the stall.

## 5. Identify the decompression dispatcher and safe fallback

The decisive function is `FUN_00699608` at `0x00699608`. Its recovered control flow is equivalent to:

```c
bool Decompress(void *output, int output_size,
                const void *input, int input_size, int flags)
{
    validate_zlib_header(input);

    if (large_request || unsafe_alignment || input_output_overlap) {
        return PpuZlibFallback(output, output_size, input, input_size);
    }

    int completion_mask = EdgeZlibSubmit(input + 2, input_size - 6,
                                         output, output_size);
    if (completion_mask < 0) {
        return PpuZlibFallback(output, output_size, input, input_size);
    }

    EdgeZlibWait(completion_mask);
    return true;
}
```

The relevant concrete functions are:

| Address | Ghidra name | Role |
| --- | --- | --- |
| `0x00699608` | `FUN_00699608` | Chooses EdgeZlib or the synchronous fallback. |
| `0x00674728` | `FUN_00674728` | Allocates a completion bit and submits the EdgeZlib request. |
| `0x0067492c` | `FUN_0067492c` | Waits on the SPURS event flag and releases the completion bit. |
| `0x00086c0c` | `FUN_00086c0c` | Existing synchronous fallback wrapper. |
| `0x009f3aa8` | `FUN_009f3aa8` | Inflate implementation called by the fallback wrapper. |

`FUN_00086c0c` returns success when `FUN_009f3aa8` returns zero, so the fallback has the same boolean success convention expected by the caller.

This is a substantially safer patch point than the embedded SPU image. It preserves real decompression and uses an error-tested code path that the shipped game already selects for large, overlapping, unsafe, or failed EdgeZlib jobs.

## 6. Verify the exact instructions

The provided Ghidra script prints the complete instruction listing for a function. An example using the project in this workspace is:

```powershell
$ghidraRoot = 'G:\ghidra_12.1.2_PUBLIC_20260605-root\ghidra_12.1.2_PUBLIC'
$projectRoot = 'G:\dust514-ghidra_nonsense\ghidra_output_step3'
$scriptRoot = 'G:\dust514-ghidra_nonsense\inventory\ghidra_scripts'
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot'

& "$ghidraRoot\support\analyzeHeadless.bat" `
  $projectRoot dust `
  -process EBOOT.elf `
  -readOnly `
  -noanalysis `
  -scriptPath $scriptRoot `
  -postScript PrintFunctionListing.java 00699608
```

The important listing is:

```text
00699760  63830000  ori r3,r28,0x0
00699764  63a40000  ori r4,r29,0x0
00699768  63c50000  ori r5,r30,0x0
0069976c  63e60000  ori r6,r31,0x0
00699770  4b9ed49d  bl 0x00086c0c
00699774  48000044  b 0x006997b8
00699778  309ffffa  subic r4,r31,0x6
0069977c  307e0002  addic r3,r30,0x2
...
0069978c  4bfdaf9d  bl 0x00674728
00699798  4bfdb195  bl 0x0067492c
```

At `0x00699778`, execution has already passed all conditions that normally select the PPU fallback. This address is the first instruction of the EdgeZlib-only block. Branching backward to `0x00699760` preserves the original argument registers and executes the complete fallback call and return path.

The original ELF bytes can also be verified directly. The first executable load segment has `p_vaddr=0x10000` and `p_offset=0`, so virtual address `0x00699778` maps to file offset `0x00689778`:

```text
Original bytes: 30 9f ff fa
Original word:  0x309ffffa
Instruction:    subic r4,r31,6
```

## 7. Derive the replacement branch

For a relative PowerPC unconditional branch:

```text
source       = 0x00699778
target       = 0x00699760
displacement = target - source = -0x18
opcode       = 0x48000000 | (-0x18 & 0x03fffffc)
             = 0x4bffffe8
```

The replacement is therefore:

```text
Address:  0x00699778
Old BE32: 0x309ffffa
New BE32: 0x4bffffe8
Meaning:  b 0x00699760
```

## 8. Construct the RPCS3 patch

Create a YAML file with the following contents:

```yaml
Version: 1.2

PPU-ae3f946dfcb103b782f73f1cc5f90587e652f439:
  "Force PPU zlib fallback (EdgeZlib bypass)":
    Games:
      "DUST 514":
        NPUB30643: [ 03.19 ]
    Author: "Dust 514 RPCS3 research"
    Patch Version: 0.3
    Notes: "RPCS3-only diagnostic workaround. Routes decompression jobs that would use EdgeZlib/SPU through the game's existing synchronous PPU fallback. Enable only for NPUB30643 app version 03.19."
    Patch:
      - [ be32, 0x00699778, 0x4bffffe8 ] # b 0x00699760
```

The workspace copy is `NPUB30643_edgezlib_fallback_patch.yml`.

## 9. Install and enable the patch

1. Copy the YAML file to RPCS3's `patches` directory. The tested destination was:

   ```text
   G:\rpcs3-v0.0.32-16396-f1ef3bdc_win64\patches\NPUB30643_patch.yml
   ```

2. Open RPCS3's Game Patches manager.
3. Refresh/reload local patch files.
4. Enable `Force PPU zlib fallback (EdgeZlib bypass)` for DUST 514.
5. Boot the game.

The boot log must show exactly one applied replacement:

```text
PAT: Applied patch (... description='Force PPU zlib fallback (EdgeZlib bypass)' ...) (<- 1)
ppu_loader: PPU executable hash: PPU-ae3f946dfcb103b782f73f1cc5f90587e652f439 (<- 1)
```

If the count is zero, the new patch entry is not enabled or the PPU hash does not match. If the count is greater than one, an obsolete queue-depth patch or another patch may still be active.

## 10. Validate the result

Proceed through login and EULA acceptance. The decisive successful log sequence is:

```text
sys_fs_open(): .../CHARACTERICONS_SF.XXX ... Pos/Size: 0/0.569336MB (0x0/0x91c00)
sys_fs_close(...): .../CHARACTERICONS_SF.XXX ... Pos/Size: 0.569336MB/0.569336MB (0x91c00/0x91c00)
```

In the first successful run, the file opened at `0:01:38.028` and closed at `0:01:38.056`, approximately 28 milliseconds later. Later tests repeatedly completed the same package at `0x91c00/0x91c00`.

The game advanced beyond the post-EULA loading screen. The result was also reproduced after reverting the earlier experimental RPCS3 configuration changes, showing that the patch does not depend on custom decoder, reservation, scheduler, shader, or cache settings.

## Required runtime settings versus unnecessary experiments

The decompression workaround requires only the game patch. Normal RPCS3 CPU/SPU settings can be used.

Separate settings may still be required to reach the login/EULA flow in a revived-service environment:

- RPCS3 PSN status set to `RPCS3` rather than disconnected.
- A valid DUST service endpoint in `DUSTGAME/SAKE.INI`.

Those are network/login requirements and are not part of the decompression fix.

Movie-disable arguments and the experimental RPCS3 synchronization settings are not required.

## What the result proves—and what it does not

The successful bypass proves that the deadlock is confined to the EdgeZlib/SPU submission-and-completion route selected by `FUN_00699608`. It also proves that the package and the game's PPU inflate path are usable.

The experiment does not uniquely identify the failing RPCS3 core primitive. Remaining candidates include:

- SPU/PPU reservation visibility in the EdgeZlib task or completion bookkeeping.
- SPURS LFQueue synchronization.
- Event-flag delivery or observation after the SPU finishes a descriptor.
- Another RPCS3 emulation detail specific to the embedded `edgezlib_inflate_ta` task.

A proper RPCS3 core fix would require tracing the submitted descriptor, SPU completion write, event flag, and PPU wait on an unpatched run. The game patch is intentionally a compatibility workaround: it avoids the suspect asynchronous path without claiming to repair RPCS3's SPURS/EdgeZlib implementation.

## Safety and limitations

- Apply only to PPU hash `PPU-ae3f946dfcb103b782f73f1cc5f90587e652f439` and NPUB30643 app version 03.19.
- Do not force the completion flag or skip `CHARACTERICONS_SF.XXX`; either could expose incomplete output to the engine.
- The patch redirects all requests that would normally take this small-buffer EdgeZlib path, not only `CHARACTERICONS_SF.XXX`.
- PPU decompression may use more CPU than the original SPU path, although the verified package completed quickly.
- This patch is intended for RPCS3. Retail PS3 hardware should continue using the original EdgeZlib path.
