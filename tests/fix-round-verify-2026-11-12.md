# Fix-Round Live Verification — 2026-11-12 (castelblack, Win2019 17763)

Re-verification after the review fix round
(RedBofAnalizer `f9ca13d..80506a4`, RedLoader `c5b51ef..925e44e`).
Binaries: release mingw builds pushed to `C:\Users\vagrant\rba_fix\`.
RBA built `--no-default-features` for this run: bindgen 0.68 panics on
`_Complex _Float16` with libclang 18 when targeting mingw (host builds
fine; yara coverage unchanged via Linux tests — none of the fixes touch
yara paths).

## Baseline (no regressions)

| Check | Result |
|---|---|
| RBA analyze race.x64.o | 11 sections, `go` entry, signature `zi` |
| RBA execute tpe.x64.o | `dbl(21)=42 trp(14)=42`, SUCCESS, clean sync exit |
| RBA s1 apitest (`--num 21 --small 7 --name anvil --loud`, new trailing args, no `--`) | buffer hex `1500000007000600...616e76696c...01000000`; BOF echoes `int=21 short=7 loud=1 str='anvil'` |
| RBA s1 intune-race `--async --async-timeout 5` (payload embedded) | payload 2850 B, timeout fired at 5.0 s, stop honored, SUCCESS |
| RL execute tpe.x64.o | `dbl(21)=42 trp(14)=42` |
| RL s1 apitest (same args) | `int=21 short=7 loud=1` |
| RL s1 intune-race `--async --async-timeout 5` | full run; monitoring-thread output (`Opened C:\ for monitoring`, `Watching ...`) now visible — global-capture drain (W4) working |

## Hostile inputs (the fix targets — all clean errors, exit 1, no crash)

| Input | RBA | RL |
|---|---|---|
| trunc.pe (88 B, the old panic repro) | `optional header truncated: file ends at 0x58, header starts at 0x58` | same |
| hostile reloc (PageRVA 0x7fff0000) | `reloc block page RVA 0x7fff0000 outside image (SizeOfImage 0xe000)` | same |
| hostile import (ILT 0xF0000000) | `import thunk table RVA outside image` | same |
| hostile export (func RVA 0x7fffffff) | `export 'go' RVA 0x7fffffff outside image (SizeOfImage 0xe000)` | same |

Note: RL's bare-file routing treats non-`.o` extensions as `parse`
(COFF analysis) — hostile files must be named `.x64.o` to reach the PE
execute path. Pre-existing heuristic, not a fix-round regression.

## Verdict

All review findings C1–C4, W1–W7 fixed and live-verified on both tools;
suggestions S1–S6 implemented. Golden buffers byte-identical
(apitest `iszZi`, intune-race `bzi` 2873 B). Fix round CLOSED.
