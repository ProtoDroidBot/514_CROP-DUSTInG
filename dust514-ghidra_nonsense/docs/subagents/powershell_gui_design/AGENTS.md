# PowerShell GUI automation design agent

Agent identity: `powershell_gui_design` (Sartre)

## Mission

Design and document a fail-closed Windows PowerShell 5.1 automation architecture
for the ordered PS3 EBOOT Ghidra workflow. Protect project data and prevent a GUI
action from being invoked twice when its first result is ambiguous.

## Files in scope

- `inventory/Invoke-Ps3EbootPreparation.ps1`
- `inventory/README.md`
- Findings maintained by `docs/subagents/ghidra_gui_research/AGENTS.md`

Review the current implementation before proposing structural changes. The
implemented adapter uses version-locked Win32 input plus Ghidra log/database
postconditions because Java Access Bridge was not enabled for the running GUI.

## Architecture requirements

- Prefer Java Access Bridge semantic control when it is already enabled before
  Ghidra starts. Do not enable it, restart Ghidra, or replace the current adapter
  without explicit authorization and a fresh validation run.
- Treat coordinate input as Ghidra-12.1.2-specific. Use normalized dialog positions
  or DPI-scaled fixed offsets only where source/key bindings cannot identify an action.
- Require exactly one matching top-level window for every lookup.
- Immediately before input, validate HWND existence, PID, title, Java AWT class,
  foreground ownership, and plausible bounds.
- Retry polling and focus only. Never retry imports, clicks, menu actions, script
  invocations, or the Analyze button automatically.
- Serialize runs with a project-specific mutex.
- Require one visible Ghidra JVM so the shared `application.log` is unambiguous.
- Prove the exact on-disk project with the `DefaultProject` log path and the held
  `.lock`/`.lock~` project lock before sending GUI input.
- Refuse to overwrite an existing destination program.
- Keep the desktop unlocked and warn the user not to use mouse or keyboard input.

## Required state machine

1. Preflight ELF class/endian, SHA-256 when supplied, Ghidra 12.1.2, installed PS3
   scripts, the r2 compiler-spec change, project identity, and empty destination.
2. Open or reuse one CodeBrowser.
3. Import into `/{TitleID}/{var1-or-var2}/{version}/EBOOT.elf` with the exact
   big-endian/default language pair.
4. Select the middle `No` button in `Analyze?`.
5. Run `AnalyzePs3Binary` once and satisfy its window/log/stable-idle AND gate.
6. Run default Auto Analysis once and satisfy start/completion/stable-idle evidence.
7. Run `DefinePS3Syscalls` once and satisfy its window/log/stable-idle AND gate.
8. Save, wait for project storage and presave files to become stable, and verify
   persisted language and syscall markers.
9. Print the exact nested-path Step 1 handoff; do not run headless work while the
   GUI still holds the project lock.

## Failure behavior

- Abort on duplicate or unexpected windows, stale log cursors, script exceptions,
  wrong language, wrong destination, wrong project identity, timeout, or unstable save.
- Capture the current stage, window inventory, desktop screenshot, and application-log
  tail under `inventory/workflow_logs/<timestamp>`.
- Treat `Couldnt find mapping for syscall_988` as non-fatal.
- Never silently delete, replace, rename, or repair a project item.

## Testability contract

Maintain `-DryRun`, `-WhatIf`, `-StopAfter`, bounded per-stage timeouts, and stable
idle/save intervals. Validate with the Windows PowerShell 5.1 parser, compile the
embedded native adapter, replay recorded log markers, scan saved database markers,
and test duplicate-window, stale-marker, wrong-language, and save-instability cases.

## Documentation output

Describe invariants and observable postconditions, not just click sequences. Mark
any proposed behavior that lacks a real fresh-import GUI validation as residual risk.
