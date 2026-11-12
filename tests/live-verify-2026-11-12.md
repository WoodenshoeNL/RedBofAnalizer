# Live verification — Windows Server 2019 (castelblack), 2026-11-12

RedBofAnalizer `db6648a`, release build `x86_64-pc-windows-gnu`
(`--no-default-features`, yara omitted). Guest: castelblack (GOAD Light,
17763 AMD64), reached via `ssh -J labhost -i ~/.ssh/redenv_key
vagrant@192.168.56.30`. Fixtures: RedLoader deep-verify BOFs
(apitest/stressasync/tpe) + company-portal-lpe intune-race (MSVC PE).

## Matrix (all PASS)

| # | Test | Result |
|---|------|--------|
| V1 | `analyze race.x64.o` (MSVC PE) | full pipeline: 11 sections, `go` entry, `zi` signature, OPSEC/entropy — PASS |
| V2 | `analyze apitest.x64.o` (COFF) | 26-arg disassembly signature, OpSec 95 — PASS |
| V3 | `s1 apitest.s1.py --list` | spec `iszZi`, 4 options + flag — PASS |
| V4 | `s1 apitest.s1.py -- --num 21 --name anvil --loud` (sync) | SUCCESS; args unpacked exactly (int=21 short=7 loud=1 str='anvil'); stop handle **0x0 (sync ctx)** — PASS |
| V5 | `s1 intune_race_bof.s1.py --file payload_dll=... ` (PE sync) | PE mapped + executed; BOF correctly self-refused (async-only) — PASS |
| V6/A1 | `s1 apitest.s1.py --async` | SUCCESS; live streaming; stop handle **0x27c (async ctx)** — real handle — PASS |
| A2 | `s1 intune_race_bof.s1.py --async` (real async PE BOF) | SUCCESS; full 5 s monitoring loop, payload 2850 B, natural completion — PASS |
| V7 | `execute stressasync.x64.o` (sync) | clean BOF error "no stop event handle (sync context)" — PASS |
| A3 | `execute stressasync.x64.o --async --async-timeout 2` | armed 30 s → stop event signaled at 2.0 s → BOF observed STOP after 4 beats, SUCCESS at 2.00 s — PASS |
| A4 | `execute tpe.x64.o --async` (mingw PE) | SUCCESS; reloc self-check `dbl(21)=42 trp(14)=42` (DIR64 applied correctly), BeaconOutput path, natural finish — PASS |
| V10 | `analyze badcoff/badimp` | parsed with reports, no crashes — PASS |

## Contract values observed

- Stop-event handle: `0x0` sync / non-zero (e.g. `0x27c`) async — matches
  RedLoader's verified contract.
- Stop signaling: `[async] async timeout (2.0s): signaling stop event`,
  cooperative exit, no detach needed in these runs.
- Async output: per-task sink, streamed live (`--- Live Output (async) ---`),
  no cross-task mixing (single-task runs).

## Known cosmetics (inherited from RedLoader's printf engine, unchanged)

- `%p` double prefix (`0x0x…`)
- `%S`/`%ls` wstr rendering quirks in apitest
- Trailing `\0` on BeaconOutput entries

## Fix found during verification

`--async` was exposed as `--is-async` (clap derived the long from the field
name despite `name = "async"`); fixed with `long = "async"` in `db6648a`.
