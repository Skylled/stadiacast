Draft: true
Title: QL-803 slice 2: macOS port 53 held by mDNSResponder: the sink moves, says so, and dns-redirect sets up pf

This pull request was written by an AI agent (Claude Code, briefed by Ace for Kyle, QL-803). It
goes to this fork only. Nothing was posted upstream.

Slice 2 of the plan in the slice 1 pull request (`feat/ql-803/usable-fork-80b208d4`). It is
stacked on slice 1, so until that merges this one shows its commit too. The topic here is the
last commit. Fork-only: the new default favours the Mac rig. Draft while it has not run on the
Mac it is for.

## The problem

On the Mac mini, mDNSResponder holds `*:53`, with Internet Sharing off too. The DNS sink exited
with "port 53 is taken by another program", the receiver went on without it, and the
controller was answered by macOS with Google's real addresses.

Why it holds the port with Internet Sharing off (verified from this guest, inferred for the
Mac): this guest is a virtual machine on that Mac, its gateway `192.168.64.1` answers DNS, and
that answer comes from macOS's DNS relay for virtual networks. So the port is held for as long
as a virtual machine runs.

Why the hand test with `rdr on bridge100` probably saw nothing (inferred, not verified): a Mac
that already has a bridge for a virtual machine gives the hotspot the next one, `bridge101` or
later. A rule on the wrong bridge loads without complaint and matches nothing. One command on
the Mac settles it: `ifconfig | grep -B6 'inet 192.168.2.1 '`.

## What this slice does

- The receiver tries the sink's port before it starts the sink. `--dns-port` defaults to
  `auto`: 53, or on a Mac whose port 53 a system service holds, 5300. The start then prints
  what holds 53 and the exact command to run, the log gets `dns_sink_moved`, and `/_status`
  has it under `helpers.dns_sink.redirect`.
- Any other taken port (a leftover sink, port 53 asked for by number, Linux) ends the start
  with exit status 2 and the holder's name and pid where `lsof` shows it.
- `stadiacast dns-redirect` prints the pf rule and every command to load, check, keep and
  remove it, and changes nothing. `--apply`, `--status` and `--remove` run `pfctl` through
  `sudo`, each command printed first. `--launchd` prints a launchd job that keeps the rule
  loaded. The receiver itself never asks for root.
- The rule matches by the hotspot's network, not by interface, so the bridge's number does not
  matter: `rdr pass inet proto { udp, tcp } from 192.168.2.0/24 to any port 53 -> 192.168.2.1 port 5300`.
- New module `hostnet.py`: interfaces from `ifconfig` / `ip`, port holders from `lsof`.

## How it was tested

- `make lint typecheck schemas-check`: green. `pytest`: 551 to 554 passed of 555 run, 31 skipped.
  As in slice 1, `make check` as a whole is not green on this guest and was not before:
  `tests/test_audio.py::test_the_system_source_keeps_real_time` hangs on the guest's sound
  device and was deselected, and one to four timing tests in `tests/test_micdevice.py` fail
  from run to run, on the untouched base commit `9605bf4` as well (4 and 3 failures in two
  runs there). Every test this slice adds or touches passes.
- New tests: the parsers against a Mac's `ifconfig` with two bridges and `lsof` output; the
  rule, the printed text, `--apply` / `--status` / `--remove` against a stand-in for sudo, the
  launchd job as a property list; the receiver moving the sink, printing the notice, and
  ending the start for a visible holder, a named port 53, Linux, and a taken 5300.
- On this macOS 27.2.1 guest, by hand: both forms of the rule parse (`pfctl -nvf -`, no root);
  the launchd job passes `plutil -lint`; a real receiver with `--dns-upstream` started its
  sink on 53 and answered `cloudcast-pa.googleapis.com` with its own address; a second
  receiver ended with "held by python3.1 (pid ..., user kyle) on *:53".
- Not tested, and only the Mac can: the fallback itself against mDNSResponder; that pf applies
  the rule to the controller's queries; `--apply` with a real sudo; the launchd job.

## To verify on the Mac

```sh
ifconfig | grep -B6 'inet 192.168.2.1 '          # which bridge the hotspot is (hotspot on)
uv run stadiacast dns-redirect --advertise-ip 192.168.2.1            # read what it would do
uv run stadiacast dns-redirect --apply --advertise-ip 192.168.2.1    # sudo; loads the rule
# start the receiver as before (no --dns-port): it should say the sink moved to 5300
sudo pfctl -a com.apple/250.stadiacast -vs nat   # wake the controller: the counters should grow
tail -f <run directory>/dns.jsonl                # a "query" line per controller query
```

## Checklist

- CHANGELOG entries under Unreleased: yes.
- Behaviour that changes for an upstream user: a DNS port that is taken now ends the start
  where the receiver used to go on without its sink. That is why this slice is fork-only.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_014iKvMAxjjWimWnKnfq4bF9
