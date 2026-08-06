# DUST 514 PS3 EBOOT Ghidra project instructions

## Project objective

Maintain a reproducible pipeline that prepares a fresh PS3 `EBOOT.elf` in Ghidra
and then runs the existing Steps 1-9 function-analysis workflow. The preparation
phase is an intentional mutable GUI prerequisite. The Steps 1-9 pipeline treats
its selected Ghidra source project as read-only.

These instructions apply to the entire repository.

## Canonical entry points

- `inventory/Invoke-Ps3EbootPreparation.ps1` — ordered Ghidra GUI preparation
- `inventory/Invoke-EbootAnalysisWorkflow.ps1` — reproducible Steps 1-9 workflow
- `inventory/README.md` — user-facing workflow documentation
- `inventory/ghidra_scripts` — headless export helpers

Do not merge the GUI prerequisite into `Invoke-EbootAnalysisWorkflow.ps1`. The
separation protects the analysis workflow's read-only/reproducible boundary.

## Specialized subagent documentation

Four reviewed role contracts live under `docs/subagents`. Read the relevant file
before doing work in that specialty:

| Role | Instructions | Use for |
| --- | --- | --- |
| Ghidra GUI research | `docs/subagents/ghidra_gui_research/AGENTS.md` | Source-backed menu, dialog, key-binding, task-window, and log facts |
| PowerShell GUI design | `docs/subagents/powershell_gui_design/AGENTS.md` | State-machine architecture, input safety, completion gates, and evidence capture |
| Workflow inspection | `docs/subagents/workflow_inspect/AGENTS.md` | Steps 1-9 boundaries, parameter flow, nested paths, and headless handoff |
| Script review | `docs/subagents/script_review/AGENTS.md` | PowerShell 5.1, persistence, project identity, regression, and documentation review |

For a cross-cutting change, use them in this order:

1. Establish Ghidra behavior with `ghidra_gui_research` guidance.
2. Apply the safety/state-machine rules from `powershell_gui_design`.
3. Check the Step 1 handoff with `workflow_inspect`.
4. Run the `script_review` regression checklist.

The subagent documents preserve reviewed findings; they do not override these
root project constraints or user instructions.

## Required end-to-end lifecycle

### Phase A: fresh GUI preparation

Run `inventory/Invoke-Ps3EbootPreparation.ps1` against an empty destination. The
required order is immutable:

1. Open or reuse the exact requested Ghidra project and one CodeBrowser.
2. Invoke the GUI **File -> Import File** action for the fresh ELF.
3. Select `PowerISA-Altivec-64-32addr`, Big Endian, default compiler. The saved
   pair must be `PowerPC:BE:64:A2ALT-32addr:default`.
4. Select the destination `/{TitleID}/{var1-or-var2}/{version}` folder, creating
   missing folders but preserving unrelated folders such as an errant `NewFolder`.
5. In `Analyze?`, select the middle `No`, never `No (Don't ask again)`.
6. Close `Import Results Summary` with OK.
7. Run `Scripts -> AnalyzePs3Binary`.
8. Wait until `AnalyzePs3Binary.java` has disappeared, its new
   `Toc / R2 set to 0x...` marker exists, and background analysis is stably idle.
9. Run `Analysis -> Auto Analyze 'EBOOT.elf'...`, retain default options, and
   wait for ordered task start/completion plus stable background idle.
10. Run `Scripts -> Analysis -> DefinePS3Syscalls` and wait for its task window,
    `Found <positive N> syscalls callers`, and stable background idle.
11. Save, wait until program storage and presave files are stable, and verify the
    saved language and syscall markers.

Never reorder, overlap, or automatically retry these GUI actions. Polling and
focus may be retried; clicks, menu actions, imports, and script invocations may not.

### Phase B: project-lock handoff

After successful preparation, save and close Ghidra. Confirm the project lock is
released before starting headless analysis. Do not break or delete a lock.

The program name supplied to the analysis workflow must be the full nested Ghidra
path, for example:

`/NPUB30643/var1/0319/EBOOT.elf`

Leaf-only `EBOOT.elf` is not an acceptable substitute.

### Phase C: Steps 1-9

Invoke:

```powershell
& .\inventory\Invoke-EbootAnalysisWorkflow.ps1 `
    -Mode RebuildWithGhidra `
    -FromStage 1 `
    -GhidraProjectDirectory .\ghidra_output `
    -GhidraProjectName dust `
    -GhidraProgramName /NPUB30643/var1/0319/EBOOT.elf `
    -ElfPath .\EBOOT.elf
```

Preserve the workflow's checkpoint, resume, output-isolation, `-readOnly`, and
`-noanalysis` semantics unless the user explicitly requests a pipeline change.

## Environment anchors

- Expected Ghidra release: `12.1.2 PUBLIC`
- Installed Ghidra root:
  `G:/ghidra_12.1.2_PUBLIC_20260605-root/ghidra_12.1.2_PUBLIC`
- Installed PS3 extension:
  `C:/Users/sebor/AppData/Roaming/ghidra/ghidra_12.1.2_PUBLIC/Extensions/Ps3GhidraScripts`
- Application log:
  `C:/Users/sebor/AppData/Roaming/ghidra/ghidra_12.1.2_PUBLIC/application.log`
- Required processor-spec change:
  `Ghidra/Processors/PowerPC/data/languages/ppc_64_32.cspec` must contain the
  `r2` register entry.

The GUI adapter is version-locked. Do not silently reuse its coordinates with a
different Ghidra version, theme, localization, or unverified layout.

## Global safety rules

- Use Windows PowerShell 5.1-compatible syntax.
- Preserve strict mode, terminating errors, dry-run support, and bounded timeouts.
- Treat all existing and unrelated workspace changes as user-owned.
- Refuse to overwrite an existing Ghidra destination item.
- Do not delete a prepared item merely to make a test pass.
- Do not delete, rename, or force-unlock a Ghidra project without explicit user
  authorization for that exact target.
- Prove the exact on-disk project through the `DefaultProject` log path and live
  `.lock`/`.lock~` state before GUI input.
- Require one visible Ghidra JVM and one matching dialog/window per action.
- Keep the interactive desktop unlocked and untouched during live GUI automation.
- Capture failure evidence rather than guessing or repeating an ambiguous action.
- Treat `Couldnt find mapping for syscall_988` as an expected warning.

## Current fixture state

The current project index contains the prepared item:

`/NPUB30643/var1/0319/EBOOT.elf`

Its known ELF SHA-256 is:

`156558691375E7C3034DF98D7BB9B6DDE3EB2A55F023F68519549C027ED6C17A`

Use that item only for read-only fixture checks and `-DryRun`. A live fresh-import
test requires an explicitly empty destination or explicit user authorization to
remove the exact item. Preserve it by default.

## Required validation for preparation-script changes

At minimum:

1. Parse `Invoke-Ps3EbootPreparation.ps1` with the Windows PowerShell 5.1 parser.
2. Run its documented `-DryRun` and verify no project mutation.
3. Dot-source in dry-run mode and compile the embedded native adapter.
4. Validate installed PS3 scripts, Ghidra version, ELF header/hash, and the r2 entry.
5. Replay or inspect new-stage log markers without accepting stale records.
6. Verify saved fixture markers for language and syscalls read-only.
7. Confirm storage files are refreshed after a stable save.
8. Confirm README examples and the printed Step 1 command use the full nested path.

Report live-GUI validation separately. Static checks and historical fixtures do not
prove normalized Swing coordinates on a new import.

## Documentation standard

Lead with observable outcomes. Distinguish verified facts, source-backed behavior,
inferences, and residual live-GUI risk. Reference exact local files, classes, dialog
titles, log markers, and commands so another agent can reproduce the conclusion.
