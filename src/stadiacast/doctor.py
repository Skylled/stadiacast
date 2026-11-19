"""``stadiacast doctor``: what stands between a controller and this receiver, checked and said.

It takes the receiver's own command line (``stadiacast doctor --preset live --dns-upstream ...``)
and checks that configuration on this computer: the ports and who holds them, the network the
controller joins and who is on it, where its DNS queries end up, the helper programs, and the
receiver itself when one is running. Every check is one plain sentence with what to do about
it, or with ``--json`` one object, for a program or an agent to read.

Nothing here changes the system or asks for root. What only root can see (the rules loaded
into pf, the sockets of other users) is reported as not seen, with the command that shows it;
run as root, the doctor reads it itself.

Each check is a function of the configuration and an :class:`Env`, which is every way the
doctor touches the system. The tests give it a Mac's answers.
"""

from __future__ import annotations

import contextlib
import datetime
import errno
import getpass
import json
import os
import platform
import plistlib
import re
import shutil
import socket
import struct
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from stadiacast import __version__
from stadiacast.config import Config
from stadiacast.dnsredirect import ANCHOR, FALLBACK_DNS_PORT
from stadiacast.errors import SetupError
from stadiacast.helpers import DNS_SINK
from stadiacast.helpers.dnswire import parse_message
from stadiacast.hostnet import (
    Interface,
    PortProbe,
    Runner,
    describe_holders,
    interface_towards,
    interface_with,
    parse_ifconfig,
    parse_ip_addr,
    probe_port,
    run_tool,
)
from stadiacast.ojd_gamepad import RELEASE_URL, find_ojd

OK, WARN, FAIL, INFO, SKIP = "ok", "warn", "fail", "info", "skip"
#: A name the DNS sink answers with the receiver's address, and the controller's first request.
REDIRECTED_NAME = "cloudcast-pa.googleapis.com"
#: The OpenJoystickDriver release the macOS pad was written against.
OJD_TESTED = "0.6.0-alpha.1"
MAC_LEASES = "/var/db/dhcpd_leases"
MAC_SHARING = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
SHARING_PANE = "System Settings > General > Sharing > Internet Sharing"


@dataclass
class Check:
    """One finding: ``status`` is ok, warn, fail, info (a fact, no judgement) or skip (not looked at)."""

    id: str
    status: str
    summary: str
    fix: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


def dns_question(name: str, ident: int = 0x5D0C) -> bytes:
    """A DNS query for the A record of ``name``."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def ask_dns(server: str, port: int, name: str, timeout: float = 2.0) -> list[str] | None:
    """The A records ``server`` gives for ``name``; an empty list for an answer without one, None
    when nothing answered."""
    question = dns_question(name)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(question, (server, port))
            while True:
                data, _ = s.recvfrom(4096)
                if data[:2] == question[:2]:
                    break
        except OSError:
            return None
    try:
        return [str(a["data"]) for a in parse_message(data)["answers"] if a.get("type") == "A"]
    except Exception:  # an answer that is not DNS is no answer
        return None


def send_udp(ip: str) -> OSError | None:
    """Send one empty datagram to the discard port of ``ip``: the error the system refused it with, if any."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.sendto(b"", (ip, 9))
        except OSError as e:
            return e
    return None


def get_json(url: str, timeout: float = 2.0) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            document = json.loads(response.read())
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return document if isinstance(document, dict) else None


def read_file(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


@dataclass
class Env:
    """Every way the doctor touches the system."""

    platform: str = sys.platform
    root: bool = False
    run: Runner = run_tool
    read: Callable[[str], bytes | None] = read_file
    probe: Callable[[str, int, str], PortProbe] = probe_port
    ask_dns: Callable[[str, int, str], list[str] | None] = ask_dns
    send_udp: Callable[[str], OSError | None] = send_udp
    get_json: Callable[[str], dict[str, Any] | None] = get_json
    which: Callable[[str], str | None] = shutil.which
    find_ojd: Callable[[str], str] = find_ojd
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now().astimezone()

    @classmethod
    def real(cls) -> Env:
        geteuid = getattr(os, "geteuid", None)
        return cls(root=bool(geteuid and geteuid() == 0))


@dataclass
class Facts:
    """What the earlier checks found, for the later ones."""

    status: dict[str, Any] | None = None  # the running receiver's /_status
    status_url: str = ""
    own: Interface | None = None  # this computer on the controller's network
    address: str = ""  # its address there
    dns_port: int = 53  # where the sink listens, or would
    leases: list[dict[str, Any]] = field(default_factory=list)  # the devices on the controller's network


# ---- the receiver -----------------------------------------------------------------------


def check_receiver(cfg: Config, env: Env, facts: Facts) -> list[Check]:
    for port in cfg.http_ports:
        url = f"http://127.0.0.1:{port}/_status"
        status = env.get_json(url)
        if status is not None and "controllers" in status:
            facts.status, facts.status_url = status, url
            controllers = status.get("controllers", {})
            return [
                Check(
                    "receiver",
                    OK,
                    f"a receiver is running (version {status.get('version')}, {len(controllers)} controller(s) known); "
                    f"its state is at {url}",
                    data={
                        "running": True,
                        "url": url,
                        "version": status.get("version"),
                        "pid": status.get("pid"),
                        "log_dir": status.get("log_dir"),
                        "controllers": len(controllers),
                    },
                )
            ]
    ports = ", ".join(str(p) for p in cfg.http_ports) or "none"
    return [
        Check(
            "receiver",
            INFO,
            f"no receiver is running here (nothing answered /_status on port {ports}): the checks below say "
            f"whether one could start",
            data={"running": False},
        )
    ]


def _listeners(cfg: Config, facts: Facts) -> list[tuple[str, int, str]]:
    """What the receiver listens on: (what for, port, protocol)."""
    wanted = [("https", cfg.https_port, "tcp")]
    wanted += [("http control", port, "tcp") for port in cfg.http_ports]
    wanted += [("display link", cfg.udp_port, "udp"), ("game session", cfg.game_udp_port, "udp")]
    if cfg.dns_upstream:
        wanted += [("DNS sink", facts.dns_port, "udp"), ("DNS sink", facts.dns_port, "tcp")]
    if cfg.sntp:
        wanted.append(("SNTP server", 123, "udp"))
    return [(what, port, protocol) for what, port, protocol in wanted if port]


def check_ports(cfg: Config, env: Env, facts: Facts) -> list[Check]:
    """Every port the receiver listens on: free for it when it is not running, its own when it is."""
    checks = []
    running = facts.status is not None
    helpers = (facts.status or {}).get("helpers") or {}
    ours = {(facts.status or {}).get("pid")} | {h.get("pid") for h in helpers.values()}
    sink = helpers.get(DNS_SINK) or {}
    if sink.get("listen"):
        facts.dns_port = int(str(sink["listen"]).rpartition(":")[2])
    elif cfg.dns_port:
        facts.dns_port = cfg.dns_port
    for what, port, protocol in _listeners(cfg, facts):
        ident = f"port.{protocol}.{port}"
        probe = env.probe(cfg.bind, port, protocol)
        data: dict[str, Any] = {
            "port": port,
            "protocol": protocol,
            "purpose": what,
            "free": probe.free,
            "holders": [asdict(h) for h in probe.holders],
        }
        name = f"{protocol.upper()} port {port} ({what})"
        if probe.free:
            if running:
                checks.append(
                    Check(
                        ident, FAIL, f"{name} is free although a receiver is running: nothing listens on it", data=data
                    )
                )
            else:
                checks.append(Check(ident, OK, f"{name} is free", data=data))
            continue
        assert probe.error is not None
        data["error"] = str(probe.error)
        if probe.error.errno != errno.EADDRINUSE:
            checks.append(
                Check(
                    ident,
                    FAIL,
                    f"{name} cannot be bound on {cfg.bind}: {probe.error}",
                    fix=["on macOS a port below 1024 is given to a normal user on all addresses only: --bind 0.0.0.0"]
                    if env.platform == "darwin" and isinstance(probe.error, PermissionError)
                    else [],
                    data=data,
                )
            )
            continue
        holders = describe_holders(probe)
        mine = [h for h in probe.holders if h.pid in ours]
        if running and (mine or not probe.holders):
            whose = "the receiver has it" if mine else f"in use, by {holders}"
            checks.append(Check(ident, OK, f"{name}: {whose}", data=data))
        elif what == "DNS sink" and port == 53 and not probe.holders and env.platform == "darwin" and not cfg.dns_port:
            facts.dns_port = FALLBACK_DNS_PORT
            checks.append(
                Check(
                    ident,
                    WARN,
                    f"{name} is held by {holders}. The receiver will put its DNS sink on port {FALLBACK_DNS_PORT} "
                    f"instead, and the controller's queries have to be redirected there (see dns.path)",
                    data=data,
                )
            )
        else:
            checks.append(
                Check(
                    ident,
                    FAIL,
                    f"{name} is taken: held by {holders}",
                    fix=[f"stop that program (kill {probe.holders[0].pid})"] if probe.holders else [],
                    data=data,
                )
            )
    return checks


# ---- the controller's network -----------------------------------------------------------


def _interfaces(env: Env) -> list[Interface]:
    text = env.run(["ifconfig"] if env.platform == "darwin" else ["ifconfig", "-a"])
    if text:
        return parse_ifconfig(text)
    text = env.run(["ip", "-o", "-4", "addr", "show"])
    return parse_ip_addr(text) if text else []


def _sharing_enabled(env: Env) -> bool | None:
    """Whether Internet Sharing is switched on in macOS's settings, or None when that cannot be read."""
    raw = env.read(MAC_SHARING)
    if raw is None:
        return None
    try:
        return bool(plistlib.loads(raw).get("NAT", {}).get("Enabled"))
    except Exception:
        return None


def check_network(cfg: Config, env: Env, facts: Facts) -> list[Check]:
    known = _interfaces(env)
    own = interface_with(cfg.advertise_ip, known) if cfg.advertise_ip else interface_towards(cfg.controller_ip, known)
    sharing = _sharing_enabled(env) if env.platform == "darwin" else None
    data: dict[str, Any] = {
        "controller_ip": cfg.controller_ip,
        "advertise_ip": cfg.advertise_ip,
        "internet_sharing_enabled": sharing,
        "interfaces": [{"name": i.name, "address": i.address, "prefix": i.prefix} for i in known],
    }
    if own is None:
        wanted = cfg.advertise_ip or f"the network of {cfg.controller_ip}"
        fix = []
        if env.platform == "darwin":
            state = {
                True: "it is switched on in the settings",
                False: "it is switched off",
                None: "its state is unknown",
            }
            fix.append(f"turn Internet Sharing on ({SHARING_PANE}); {state[sharing]}")
        fix.append("or, on another network, give the controller's address with --controller-ip")
        return [
            Check(
                "network",
                FAIL,
                f"no interface of this computer has {wanted}: the hotspot the controller joins is not up",
                fix=fix,
                data=data,
            )
        ]
    facts.own, facts.address = own, own.address
    members = f", joining {', '.join(own.members)}" if own.members else ""
    data.update(interface=own.name, address=own.address, network=str(own.network), members=list(own.members))
    checks = [
        Check(
            "network",
            OK if own.active else WARN,
            f"this computer is {own.address} on {own.name} ({own.network}{members})"
            + ("" if own.active else ", and the interface is not active"),
            data=data,
        )
    ]
    if env.platform == "darwin" and own.name.startswith("bridge") and own.name != "bridge100":
        checks.append(
            Check(
                "network.bridge",
                INFO,
                f"the hotspot is {own.name}, not bridge100, which another bridge has (a virtual machine's, usually): "
                f"a pf rule, a capture or IFACE= that names bridge100 looks at the wrong network",
                data={"interface": own.name},
            )
        )
    return checks


_LEASE_FIELD = re.compile(r"^\s*(\w+)=(.*)$")


def parse_mac_leases(text: str) -> list[dict[str, Any]]:
    """The leases in macOS's ``/var/db/dhcpd_leases``: name, ip, mac and the time each ends."""
    leases: list[dict[str, Any]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        if line.strip() == "{":
            current = {}
        elif line.strip() == "}" and current is not None:
            if "ip_address" in current:
                mac = current.get("hw_address", "").partition(",")[2]
                lease: dict[str, Any] = {"name": current.get("name", ""), "ip": current["ip_address"], "mac": mac}
                with contextlib.suppress(ValueError):
                    lease["expires"] = int(current.get("lease", ""), 16)
                leases.append(lease)
            current = None
        elif current is not None:
            m = _LEASE_FIELD.match(line)
            if m:
                current[m.group(1)] = m.group(2).strip()
    return leases


_ARP = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at (\S+)")


def parse_arp(text: str) -> dict[str, str]:
    """ip -> mac for the neighbours ``arp -an`` knows; an address that did not answer is left out."""
    return {m.group(1): m.group(2) for m in _ARP.finditer(text) if ":" in m.group(2)}


def check_devices(cfg: Config, env: Env, facts: Facts) -> list[Check]:
    """Who has joined the controller's network: the leases of macOS's DHCP server, and who answers."""
    if facts.own is None:
        return [Check("devices", SKIP, "not looked at: the controller's network is not up")]
    if env.platform != "darwin":
        return [Check("devices", SKIP, "not looked at: reading the hotspot's leases is known for macOS only")]
    raw = env.read(MAC_LEASES)
    arp = parse_arp(env.run(["arp", "-an"]) or "")
    now = env.now().timestamp()
    devices = []
    for lease in parse_mac_leases(raw.decode("utf-8", "replace")) if raw else []:
        if not facts.own.holds(lease["ip"]) or lease["ip"] == facts.own.address:
            continue
        lease["answers_arp"] = lease["ip"] in arp
        lease["expired"] = "expires" in lease and lease["expires"] < now
        devices.append(lease)
    facts.leases = devices
    data = {"leases_file": MAC_LEASES, "devices": devices}
    provision = "stadiacast-provision provision --ssid <the hotspot's name>   (the controller in setup mode)"
    if not devices:
        return [
            Check(
                "devices",
                WARN,
                f"no device has an address on {facts.own.network}: the controller has not joined the Wi-Fi "
                f"(a provisioning that ends in 'Done' is not proof that it joined)",
                fix=[
                    provision,
                    f"the hotspot must offer WPA2: '{SHARING_PANE} > Wi-Fi Options > Security: WPA2/WPA3 Personal'",
                ],
                data=data,
            )
        ]
    listed = "; ".join(
        f"{d['name'] or 'unnamed'} {d['ip']} ({d['mac']}"
        + (", answering" if d["answers_arp"] else ", silent now")
        + (", lease run out" if d["expired"] else "")
        + ")"
        for d in devices
    )
    live = [d for d in devices if d["answers_arp"]]
    checks = [
        Check(
            "devices",
            OK if live else WARN,
            f"{len(devices)} device(s) joined {facts.own.network}: {listed}"
            + ("" if live else ". None answers now: a controller sleeps until its Stadia button is pressed"),
            data=data,
        )
    ]
    if cfg.controller_ip not in {d["ip"] for d in devices}:
        checks.append(
            Check(
                "devices.controller_ip",
                INFO,
                f"--controller-ip is {cfg.controller_ip} and no device has that address: the helpers' logs mark "
                f"a controller's lines by it (from_controller), so they will not be marked",
                fix=[f"--controller-ip {devices[0]['ip']}"],
                data={"controller_ip": cfg.controller_ip},
            )
        )
    for device in live:
        refused = env.send_udp(device["ip"])
        if refused is not None and refused.errno in (errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
            checks.append(
                Check(
                    "devices.reach",
                    FAIL,
                    f"this program may not send to {device['ip']} ({refused}): macOS's Local Network privacy "
                    f"refuses it, and a receiver started the same way cannot answer the controller either",
                    fix=["System Settings > Privacy & Security > Local Network: allow what starts the receiver"],
                    data={"ip": device["ip"], "error": str(refused)},
                )
            )
            break
    return checks


# ---- DNS --------------------------------------------------------------------------------


def _sink_log(env: Env, facts: Facts) -> dict[str, Any] | None:
    """What the running sink's log says about queries from the controller's network."""
    log_dir = (facts.status or {}).get("log_dir")
    if not log_dir or facts.own is None:
        return None
    raw = env.read(os.path.join(str(log_dir), "dns.jsonl"))
    if raw is None:
        return None
    seen: dict[str, Any] = {"queries": 0, "from_network": 0, "redirected": 0, "last": None, "last_name": None}
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("event") != "query":
            continue
        seen["queries"] += 1
        source = str(record.get("src", "")).rpartition(":")[0]
        if facts.own.holds(source) and source != facts.own.address:
            seen["from_network"] += 1
            seen["redirected"] += record.get("action") == "redirect"
            seen["last"], seen["last_name"] = record.get("ts"), record.get("qname")
    return seen


def _redirect_loaded(env: Env) -> bool | None:
    """Whether a rule is in the pf anchor: only root can read it, so None for anyone else."""
    if not env.root:
        return None
    return any(
        line.strip().startswith("rdr") for line in (env.run(["pfctl", "-a", ANCHOR, "-s", "nat"]) or "").splitlines()
    )


def check_dns(cfg: Config, env: Env, facts: Facts) -> list[Check]:
    if not cfg.dns_upstream:
        return [
            Check(
                "dns",
                INFO,
                "no --dns-upstream: this receiver runs no DNS sink, so something else has to answer the "
                "controller's *.googleapis.com queries with this computer's address",
            )
        ]
    checks = []
    upstream = env.ask_dns(cfg.dns_upstream, 53, "example.com")
    checks.append(
        Check(
            "dns.upstream",
            OK if upstream else FAIL,
            f"the upstream resolver {cfg.dns_upstream} answers"
            if upstream
            else f"the upstream resolver {cfg.dns_upstream} (--dns-upstream) did not answer a query for example.com: "
            f"every name the sink forwards will fail",
            data={"upstream": cfg.dns_upstream, "answers": upstream},
        )
    )
    address = facts.address or cfg.advertise_ip or ""
    port = facts.dns_port
    sink = ((facts.status or {}).get("helpers") or {}).get(DNS_SINK)
    if facts.status is not None:
        if not sink or not sink.get("running"):
            code = sink.get("returncode") if sink else None
            checks.append(
                Check(
                    "dns.sink",
                    FAIL,
                    "the receiver's DNS sink is not running"
                    + (f" (it exited with status {code})" if sink else " (the receiver was started without one)")
                    + ": the controller is not sent to this receiver",
                    fix=["read dns.out in the run directory for what it could not bind, then start the receiver again"],
                    data={"sink": sink},
                )
            )
        else:
            direct = env.ask_dns("127.0.0.1" if cfg.bind in ("", "0.0.0.0") else cfg.bind, port, REDIRECTED_NAME)
            good = bool(direct) and (not address or direct == [address])
            checks.append(
                Check(
                    "dns.sink",
                    OK if good else FAIL,
                    f"the DNS sink on port {port} answers {REDIRECTED_NAME} with {', '.join(direct or [])}"
                    if good
                    else f"the DNS sink on port {port} gave {direct if direct is not None else 'no answer'} for "
                    f"{REDIRECTED_NAME}, and {address or 'this receiver'} was expected",
                    data={"port": port, "answers": direct, "expected": address},
                )
            )
    if facts.own is None or not address:
        checks.append(Check("dns.path", SKIP, "not looked at: the controller's network is not up"))
        return checks
    # What a device on the hotspot gets when it asks this computer, as the controller does.
    at_53 = env.ask_dns(address, 53, REDIRECTED_NAME)
    log = _sink_log(env, facts)
    data = {"asked": f"{address}:53", "name": REDIRECTED_NAME, "answers": at_53, "sink_port": port, "sink_log": log}
    arrived = bool(log and log["from_network"])
    evidence = (
        f"{log['from_network']} of the sink's queries came from the controller's network, the last for "
        f"{log['last_name']} at {log['last']}"
        if log and arrived
        else ""
    )
    if port == 53:
        if at_53 == [address]:
            checks.append(
                Check("dns.path", OK, f"port 53 of {address} answers {REDIRECTED_NAME} with this computer", data=data)
            )
        elif facts.status is not None:
            checks.append(
                Check(
                    "dns.path",
                    FAIL,
                    f"port 53 of {address} answered {at_53 if at_53 is not None else 'nothing'} for {REDIRECTED_NAME}: "
                    f"the controller is not sent to this receiver",
                    data=data,
                )
            )
        else:
            checks.append(
                Check("dns.path", SKIP, "not looked at: no receiver is running, so no sink answers", data=data)
            )
        return checks
    command = f"stadiacast dns-redirect --apply --advertise-ip {address} --dns-port {port}"
    loaded = _redirect_loaded(env)
    data["redirect_loaded"] = loaded
    relay = (
        f"port 53 of {address} is not the sink's: asked for {REDIRECTED_NAME} it "
        + (f"gives {', '.join(at_53)}, Google's addresses" if at_53 else "gives no address")
        + f". The controller reaches the sink on port {port} only through the pf redirect"
    )
    if arrived:
        checks.append(Check("dns.path", OK, f"{relay}, which works: {evidence}", data=data))
    elif loaded is False:
        checks.append(Check("dns.path", FAIL, f"{relay}, and no rule is loaded in {ANCHOR}", fix=[command], data=data))
    elif facts.status is not None and any(d["answers_arp"] for d in facts.leases):
        seen = "is loaded" if loaded else "cannot be seen without root"
        checks.append(
            Check(
                "dns.path",
                FAIL,
                f"{relay}. A device is on the network and awake, and none of its queries has reached the sink; "
                f"the rule {seen}",
                fix=[
                    command,
                    f"sudo pfctl -a {ANCHOR} -vs nat      # loaded? do the counters grow when the controller wakes?",
                    f"sudo tcpdump -ni {facts.own.name if facts.own else '<bridge>'} port 53 or port {port}",
                ],
                data=data,
            )
        )
    else:
        seen = "a rule is loaded" if loaded else "whether the rule is loaded cannot be seen without root"
        checks.append(
            Check(
                "dns.path",
                WARN,
                f"{relay}; {seen}, and no query from the controller's network has reached the sink yet",
                fix=[
                    command,
                    "stadiacast dns-redirect --status     # asks for your password",
                    "then wake the controller and run the doctor again",
                ],
                data=data,
            )
        )
    return checks


# ---- the controllers of a running receiver ----------------------------------------------


def check_controllers(_cfg: Config, _env: Env, facts: Facts) -> list[Check]:
    if facts.status is None:
        return []
    controllers = facts.status.get("controllers") or {}
    if not controllers:
        return [
            Check(
                "controllers",
                INFO,
                "no controller has reached the receiver since it started: with a device on the network, look at "
                "dns.path; a controller that is asleep wakes with a press of about a second on the Stadia button",
                data={"controllers": {}},
            )
        ]
    checks = []
    for label, ctl in controllers.items():
        display = ((ctl.get("session") or {}).get("display") or {}).get("state")
        ready = display in ("ready", "input")  # the last two of controller.DISPLAY_STATES
        checks.append(
            Check(
                f"controller.{label}",
                OK if ready else INFO,
                f"controller {label} at {ctl.get('ip')}: display link at '{display}'"
                + (" (connected)" if ready else " (not connected yet: 'ready' and 'input' are)")
                + ", last heard "
                f"{ctl.get('last_seen_s')} s ago, battery {ctl.get('battery_percent')}",
                data={
                    "label": label,
                    "ip": ctl.get("ip"),
                    "display_state": display,
                    "last_seen_s": ctl.get("last_seen_s"),
                    "serial": ctl.get("serial"),
                },
            )
        )
    for label, pad in (facts.status.get("gamepads") or {}).items():
        if "error" in pad:
            checks.append(
                Check(
                    f"gamepad.{label}",
                    FAIL,
                    f"the virtual pad of {label} failed: {pad['error']} (it is tried again when the controller starts)",
                    data=pad,
                )
            )
    return checks


# ---- programs the receiver uses ---------------------------------------------------------


def check_ojd(cfg: Config, env: Env, _facts: Facts) -> list[Check]:
    if cfg.gamepad != "ojd":
        return []
    try:
        path = env.find_ojd(cfg.ojd_path)
    except SetupError as e:
        return [Check("ojd", FAIL, str(e), fix=[f"install the app from {RELEASE_URL} and open it once"])]
    version = (env.run([path, "--version"]) or "").strip().splitlines()
    said = version[0] if version else ""
    running = [
        line
        for line in (env.run(["pgrep", "-fl", "OpenJoystickDriver"]) or "").splitlines()
        if "pgrep" not in line and " virtual feed" not in line
    ]
    data = {"path": path, "version": said, "running": bool(running), "tested_version": OJD_TESTED}
    checks = []
    if not said:
        checks.append(Check("ojd", WARN, f"OpenJoystickDriver is at {path} and did not say its version", data=data))
    elif OJD_TESTED in said:
        checks.append(
            Check("ojd", OK, f"OpenJoystickDriver {said} at {path}: the release the pad was written for", data=data)
        )
    else:
        checks.append(
            Check(
                "ojd",
                INFO,
                f"OpenJoystickDriver {said} at {path}: the pad was written for {OJD_TESTED}; the feed it uses is the "
                f"same in 0.6.0-alpha.2 by its source, and nothing else was tried",
                data=data,
            )
        )
    if not running:
        checks.append(
            Check(
                "ojd.running",
                WARN,
                "the OpenJoystickDriver app does not seem to be running: a pad needs it open, with Accessibility "
                "and Input Monitoring allowed",
                fix=[
                    "open -a OpenJoystickDriver",
                    "System Settings > Privacy & Security > Accessibility, and Input Monitoring",
                ],
                data=data,
            )
        )
    else:
        checks.append(
            Check(
                "ojd.running",
                OK,
                "the OpenJoystickDriver app is running (whether macOS lets it post input is not something this "
                "check can see: Accessibility and Input Monitoring, under Privacy & Security)",
                data=data,
            )
        )
    return checks


def check_ffmpeg(cfg: Config, env: Env, _facts: Facts) -> list[Check]:
    needed = bool(cfg.audio_source) or cfg.mic_device is not None or cfg.mic_pcm
    path = env.which("ffmpeg")
    if path is None:
        return [
            Check(
                "ffmpeg",
                FAIL if needed else INFO,
                "ffmpeg is not on PATH: "
                + (
                    "this configuration needs it"
                    if needed
                    else "the headset's sound and "
                    "the microphone as a device need it, and this configuration uses neither"
                ),
                fix=["brew install ffmpeg"] if env.platform == "darwin" else [],
                data={"path": None, "needed": needed},
            )
        ]
    encoders = env.run([path, "-hide_banner", "-encoders"]) or ""
    libopus = "libopus" in encoders
    return [
        Check(
            "ffmpeg",
            OK if libopus else (FAIL if needed else WARN),
            f"ffmpeg at {path} "
            + (
                "has libopus"
                if libopus
                else "has no libopus encoder: the headset stream would start again and again without a sound"
            ),
            fix=[] if libopus else ["install an ffmpeg built with libopus (Homebrew's is)"],
            data={"path": path, "libopus": libopus, "needed": needed},
        )
    ]


def check_firewall(_cfg: Config, env: Env, _facts: Facts) -> list[Check]:
    if env.platform != "darwin":
        return []
    said = env.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if said is None:
        return []
    enabled = "enabled" in said.lower()
    return [
        Check(
            "firewall",
            WARN if enabled else OK,
            "the macOS firewall is on: it has to allow incoming connections to the Python that runs the receiver, "
            "or the controller's connections are dropped without a word"
            if enabled
            else "the macOS firewall is off",
            fix=["System Settings > Network > Firewall > Options: allow the receiver's python"] if enabled else [],
            data={"enabled": enabled},
        )
    ]


CHECKS: tuple[Callable[[Config, Env, Facts], list[Check]], ...] = (
    check_receiver,
    check_network,
    check_ports,
    check_devices,
    check_dns,
    check_controllers,
    check_ojd,
    check_ffmpeg,
    check_firewall,
)


def examine(cfg: Config, env: Env | None = None) -> list[Check]:
    """Run every check. One that breaks is reported as a failed check, not as a traceback: the
    doctor is what gets run when things are already wrong."""
    env = env or Env.real()
    facts = Facts()
    found: list[Check] = []
    for check in CHECKS:
        try:
            found.extend(check(cfg, env, facts))
        except Exception as e:
            name = check.__name__.removeprefix("check_")
            found.append(Check(name, FAIL, f"this check broke, which is a bug in the doctor: {e!r}"))
    return found


def report(checks: Sequence[Check], env: Env) -> dict[str, Any]:
    """The ``--json`` document."""
    counts = {status: sum(c.status == status for c in checks) for status in (OK, WARN, FAIL, INFO, SKIP)}
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    return {
        "stadiacast": __version__,
        "platform": env.platform,
        "system": f"{platform.system()} {platform.mac_ver()[0] or platform.release()} ({platform.machine()})",
        "user": user,
        "root": env.root,
        "healthy": counts[FAIL] == 0,
        "summary": counts,
        "checks": [asdict(c) for c in checks],
    }


_MARK = {OK: "ok  ", WARN: "WARN", FAIL: "FAIL", INFO: "note", SKIP: "skip"}


def render(document: dict[str, Any]) -> str:
    """The report for a person: one line a check, what to do under it, and the count at the end."""
    lines = [
        f"stadiacast doctor {document['stadiacast']} on {document['system']}, as {document['user'] or 'a user'}"
        + (" (root)" if document["root"] else ""),
        "",
    ]
    width = max((len(c["id"]) for c in document["checks"]), default=0)
    for check in document["checks"]:
        lines.append(f"{_MARK[check['status']]}  {check['id']:<{width}}  {check['summary']}")
        lines.extend(f"      {'':<{width}}  do: {step}" for step in check["fix"])
    counts = document["summary"]
    lines.append("")
    if counts[FAIL]:
        lines.append(f"{counts[FAIL]} problem(s), {counts[WARN]} warning(s). Start with the first FAIL.")
    elif counts[WARN]:
        lines.append(f"no problem found, {counts[WARN]} warning(s) to read.")
    else:
        lines.append("no problem found.")
    if not document["root"]:
        lines.append("Run as a normal user: other users' sockets and the pf rules were not read.")
    return "\n".join(lines) + "\n"


USAGE = """\
usage: stadiacast doctor [--json] [the receiver's own flags]

Checks this computer for the receiver you would start with those flags, or the one that is
running: ports and who holds them, the network the controller joins and who is on it, where
its DNS queries go, OpenJoystickDriver, ffmpeg. Give it the flags you give the receiver:

    stadiacast doctor --preset live --dns-upstream 192.168.1.1 --gamepad ojd

It changes nothing and asks for no password. Exit status: 0 when no check failed, 1 when one
did, 2 for flags it could not read.

  --json    one JSON object instead of text: {healthy, summary, checks: [{id, status, summary, fix, data}]}
            status is ok, warn, fail, info or skip
"""


def main(argv: Sequence[str] | None = None, env: Env | None = None) -> int:
    from stadiacast.cli import parse_args  # the command line imports this module's command

    args = list(sys.argv[1:] if argv is None else argv)
    if "-h" in args or "--help" in args:
        print(USAGE, end="")
        return 0
    as_json = "--json" in args
    cfg = parse_args([a for a in args if a != "--json"])
    env = env or Env.real()
    document = report(examine(cfg, env), env)
    print(json.dumps(document, indent=1, default=str) if as_json else render(document), end="\n" if as_json else "")
    return 0 if document["healthy"] else 1
