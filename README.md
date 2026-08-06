# 514_CROP-DUSTInG
Assisted Information Generation and Documentation on DUST 514 (as run in RPCS3)
--------------------------------------------------------------------------------
## !!TRIGGER WARNING/FULL DISCLOSURE!!
### What you do with the following information is up to you
Complete analysis, documentation, and subsequent RPCS3 patch for the startup flaws were generated with AI/LLM usage from OpenAI ChatGPT app (Codex).

Additional analysis, methodology, and ultimate patch triaging/verification done by a human (me, ProtoDroidBot).

Repository is provided as-is with no expectation of warranty.

As a result, I probably shouldn't blanket-cover the repository with any license or warranty tied to it. Your mileage may vary.

Credit and attribution would be nice and preferred too if you re-use the methods described within.


## Project Description
WIP Scratch space which will eventually contain documentation and reproducible analysis on the quirks of RPCS3 during attempts to run DUST 514 on it.
EdgeZlib patches provided within should prevent a startup crash/soft-lock loop related to the EdgeZlib library decompression not returning properly. After install, clear all caches (PPU/SPU/Shaders).


## Tools used
Legitimate Copy of DUST 514 NPUB30643 patched to 03.19

https://github.com/RPCS3/rpcs3

https://github.com/NationalSecurityAgency/ghidra - Ghidra version 12.1.2 used, see release https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build

https://github.com/clienthax/Ps3GhidraScripts - ghidra_12.1.2_PUBLIC_20260712_Ps3GhidraScripts.zip used, see release https://github.com/clienthax/Ps3GhidraScripts/releases/tag/1.0111


## Project-specific definitions and terminology
Title ID/TitleID: PlayStation Title ID, most folder paths in the project will have a Title ID in the Folder Name, which ties the products to the actual game versions in some way.

### Patch Variants
Defines what sort of patching strategy I used based on the .pkg files I have on hand at the time of analysis. Here for historical purposes, but overall wouldn't make much sense to those looking for just a working patch. This also required a unified file/folder name pattern to differentiate clients with incremental patches applied, versus a full packaged game client version.

var1: Var1/Variant 1 files and folders have the first full HDD Game client available plus any subsequent incremental patches up to the designated version. Patches are applied all at once and in order.

var2: Var2/Variant 2 files and folders have the full HDD Game client ready to go in that specific .pkg file. There's no need for RPCS3 to apply incremental patches in this case.


In most cases, you would need only the var1 patch for that specific game version/title ID.

I am not confident in the true legitimacy of the var2 clients, but they are there in-case someone finds the full game clients on the internet.

## Folder/File Structure
WIP

~\ - 514_CROP-DUSTInG repository, you are here!

~\docs\ - Documents and methodology will be available in here for the inquring minds.

~\docs\CodexGen\DUST514_RPCS3_EDGEZLIB_PATCH_REPRODUCTION.md - Codex generated summary of the patching strategy and how to replicate the associated patching strategy.

~\ghidra_scripts\ - various Ghidra scripts created and used by Codex during this project. Might be useful to someone later. I will try to explain what each script does.

~\rpcs3_patches\ - the actual RPCS3 patches produced as part of this project.

~\rpcs3_patches\NPUB30643_0319\ - contains the very first working patch for the last DUST 514 USA version (Title ID: NPUB30643 | Version: 03.19)

~\rpcs3_patches\NPUB30643\ - Contains patches for various NPUB30643 versions

~\rpcs3_patches\NPUB30643\var1\\####\rpcs3buildfolder\ - var1 folders (incremental) with patch version following #### without the decimal in between. 0317 for example is version 03.17

~\rpcs3_patches\NPUB30643\var2\\####\rpcs3buildfolder\ - var2 folders (full) with patch version following #### without the decimal in between. 0319 for example is version 03.19

~\rpcs3_patches\NPUB30643\var2\0317\rpcs3-beb065f763b4\NPUB30643_0317_var2_edgezlib_fallback_patch.yml - RPCS3 EdgeZlib fallback patch for Title ID NPUB30643, version 03.17

--------------------------------------------------------------------------------
## AI Assistance provided by:
OpenAI ChatGPT / Codex

https://github.com/themixednuts/GhidraMCP

## Additional credits to: DUSTmu team


## Final thoughts
**THIS IS NOT AN ENDORSEMENT OF AI/LLM USAGE FOR EVERYDAY PROGRAMMING TASKS OR USES/USAGE. THESE AI TOOLS STILL REQUIRE SOME HUMAN THOUGHT AND PLANNING. PLEASE USE RESPONSIBLY.**
