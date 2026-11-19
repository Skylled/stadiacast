Title: QL-803 slice 3: stadiacast doctor, in plain language and as JSON

This pull request was written by an AI agent (Claude Code, briefed by Ace for Kyle, QL-803). It
goes to this fork only. Nothing was posted upstream.

Slice 3 of the plan in the slice 1 pull request. It is stacked on slices 1 and 2
(`feat/ql-803/usable-fork-80b208d4`, `feat/ql-803/macos-dns-redirect`), so until those merge
this one shows their commits too. The topic here is the last commit. Draft while it has not
run on the Mac it is for.

## What it does

`stadiacast doctor [--json] <the receiver's own flags>` checks this computer for that receiver,
running or not. It changes nothing and asks for no password.

| check | what it looks at |
|---|---|
| `receiver` | whether a receiver answers `/_status` here |
| `network`, `network.bridge` | this computer on the controller's network: address, interface, bridge members, Internet Sharing on or off, and a note when the hotspot is not `bridge100` |
| `port.<proto>.<n>` | every listener's port: free, the receiver's own, or who else holds it (`lsof`) |
| `devices`, `devices.reach` | macOS: leases on the hotspot (`/var/db/dhcpd_leases`), who answers ARP now, and whether Local Network privacy refuses a send |
| `dns.upstream`, `dns.sink`, `dns.path` | the upstream resolver; the sink's own answer; what port 53 answers, which is what the controller gets; with the sink on 5300, whether queries from the controller's network reached it (its log) and, as root, whether the pf rule is loaded |
| `controller.<label>`, `gamepad.<label>` | a running receiver's controllers and their display link, and a pad that failed |
| `ojd`, `ojd.running` | where OpenJoystickDriver is, its version against 0.6.0-alpha.1, whether the app runs |
| `ffmpeg` | present, with libopus, when the flags need it |
| `firewall` | macOS: on or off |

Text: one line a check, `do:` lines under one that needs them, a count at the end. `--json`:
`{healthy, summary, checks: [{id, status, summary, fix, data}]}`. Exit status 1 when a check failed.

For the evening that led here, with the receiver running, the sink on 5300 and the controller
awake, it would have said (from the test of that case):

```
FAIL  dns.path  port 53 of 192.168.2.1 is not the sink's: asked for cloudcast-pa.googleapis.com it gives
                142.250.72.10, Google's addresses. The controller reaches the sink on port 5300 only through
                the pf redirect. A device is on the network and awake, and none of its queries has reached
                the sink; the rule cannot be seen without root
                do: stadiacast dns-redirect --apply --advertise-ip 192.168.2.1 --dns-port 5300
                do: sudo pfctl -a com.apple/250.stadiacast -vs nat      # loaded? do the counters grow when the controller wakes?
                do: sudo tcpdump -ni bridge101 port 53 or port 5300
```

Also: `/_status` gives the receiver's `pid` (so the doctor can tell the receiver's ports from a
stranger's) and `log_dir` as an absolute path.

## How it was tested

- `make lint typecheck schemas-check`: green. `pytest`: see slice 1 for the two things that
  keep `make check` from green on this guest, before and after (a sound-device test that hangs,
  and timing tests in `tests/test_micdevice.py`). Every test this slice adds or touches passes.
- `tests/test_doctor.py`, 17 tests: every check against a stand-in for the Mac (two bridges,
  mDNSResponder on 53, a lease file, an ARP table), the text and the JSON, the exit status, and
  one test over the wire: a real receiver that a fake controller (`tests/fake_controller.py`)
  has joined, read through `/_status`.
- On this macOS 27.2.1 guest, by hand: the doctor with no receiver (network FAIL, since the
  guest has no hotspot; ports free; ffmpeg with libopus found; firewall off) and with a real
  receiver, its sink and a fake controller running (ports "the receiver has it", `dns.sink` and
  `dns.path` ok, `controller.c0` listed).
- Not tested, and only the Mac can: the lease file and `arp` output of a real Internet Sharing
  hotspot (the formats are from memory of macOS, not from a capture); the Internet Sharing
  plist; the Local Network refusal (inferred from Apple's description of the error);
  `ojd --version` and the app's process name against a real OpenJoystickDriver.

## To verify on the Mac

```sh
uv run stadiacast doctor --preset live --dns-upstream 192.168.86.1 --advertise-ip 192.168.2.1 --gamepad ojd
uv run stadiacast doctor --json --preset live --dns-upstream 192.168.86.1 --advertise-ip 192.168.2.1 --gamepad ojd | jq .summary
cat /var/db/dhcpd_leases; arp -an | grep 192.168.2.     # compare with the 'devices' line
```

## Checklist

- CHANGELOG entry under Unreleased: yes.
- A new command; the receiver's behaviour is unchanged apart from the two `/_status` fields.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_014iKvMAxjjWimWnKnfq4bF9
