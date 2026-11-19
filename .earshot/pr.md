Draft: true
Title: QL-803 slice 1: the DNS and SNTP helpers listen where --bind says, and --dns-port

This pull request was written by an AI agent (Claude Code, briefed by Ace for Kyle, QL-803). It
goes to this fork only. Nothing was posted upstream.

## The plan (QL-803: a usable, diagnosable, agent-friendly fork)

One topic per pull request, so that what suits upstream can be offered there later without the
fork-only parts. Each later branch is stacked on the one before it, and the host opens every
pull request against `main`, so a later one also shows the earlier commits until those merge.

| # | Branch | Topic | For upstream? | State |
|---|---|---|---|---|
| 1 | `feat/ql-803/usable-fork-80b208d4` | Helpers honour `--bind`; `--dns-port`; helpers in `/_status` | yes | this pull request |
| 2 | `feat/ql-803/macos-dns-redirect` | macOS: port 53 held by mDNSResponder. The sink moves to 5300 and says so; `stadiacast dns-redirect` shows, loads and removes the pf rule | no (our defaults favour the Mac rig) | built |
| 3 | `feat/ql-803/doctor` | `stadiacast doctor`, plain text and `--json` | perhaps, in parts | built |
| 4 | to come | One line per stage of a controller's connection, the reason when it stalls, and no console line per input report | the quiet flag, yes | not started |
| 5 | to come | `AGENTS.md` / `CLAUDE.md` with the code map and how to test; connection stages in `/_status` and the log for an agent to read | no | not started |

The title keeps its `WIP:` prefix while slices 4 and 5 remain.

## What this slice does

- The DNS sink and the SNTP server are started with `--listen <the address of --bind>`. They
  listened on `0.0.0.0` whatever the receiver was told (`receiver.py`, `_start_dns` and
  `_start_sntp`). The default `--bind 0.0.0.0` behaves as before.
- `--dns-port` (default 53) sets the port of the spawned sink, for a computer whose port 53
  belongs to another program and whose firewall redirects the controller's queries.
- `/_status` gains `helpers`: where each helper listens, its pid, whether it runs, its exit status.
- On macOS, a port below 1024 refused on one address is explained: macOS gives such a port to a
  program that is not root on all addresses only. Checked on this macOS 27.2.1 guest: as a
  normal user `0.0.0.0:53` binds, `127.0.0.1:53` and the Ethernet address are refused with EACCES.

## How it was tested

- `make lint typecheck schemas-check`: green.
- `pytest`: 535 passed of 536 run, 31 skipped. `make check` as a whole is not green on this guest
  (a headless VM whose only sound device is "Apple Virtual Sound Device"), and was not before
  this change: `tests/test_audio.py::test_the_system_source_keeps_real_time` hangs opening that
  device and was deselected, and one to four timing tests in `tests/test_micdevice.py` fail
  from run to run, on the untouched base commit `9605bf4` as well (4 and 3 failures in two
  runs there). Every test this slice adds or touches passes.
- New tests: the arguments the receiver gives both helpers; a real sink spawned by the receiver
  on a loopback port answering a redirected name; the macOS message.
- Not tested: a real controller. Nothing here changes what a controller sees with the default flags.

## Checklist

- CHANGELOG entry under Unreleased: yes.
- The new flag defaults to the old behaviour and leaves `--preset live` unchanged: yes.
- No personal identifiers, captures or certificates in the diff.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_014iKvMAxjjWimWnKnfq4bF9
