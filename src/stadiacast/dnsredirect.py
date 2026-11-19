"""``stadiacast dns-redirect``: send the controller's DNS queries to a sink that could not have port 53.

On a Mac that shares its connection, or that runs virtual machines, macOS's own DNS relay
(mDNSResponder) holds port 53 on every address, and nothing that is not root can take it from
it or bind it on one address. The DNS sink then listens on another port (5300), and the
packet filter of macOS, pf, rewrites the queries that arrive from the controller's network so
that they reach it: whatever server the controller asked, its own fallback ``8.8.8.8`` included.

Loading a pf rule takes root. This command prints the rule and every command by default, and
runs them through ``sudo`` only with ``--apply`` or ``--remove``, each one shown before it runs.
The receiver itself never asks for root.

The rule names the controller's network, not the interface: the hotspot is ``bridge100`` on a
Mac with nothing else bridged and ``bridge101`` or later on one that runs virtual machines, and
a rule on the wrong bridge matches nothing and says nothing.
"""

from __future__ import annotations

import argparse
import ipaddress
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from stadiacast.config import DEFAULT_CONTROLLER_IP
from stadiacast.errors import SetupError
from stadiacast.hostnet import Interface, Runner, interface_towards, interface_with, interfaces, run_tool
from stadiacast.netutil import local_ip_towards

#: Where the sink listens when port 53 is not to be had.
FALLBACK_DNS_PORT = 5300
#: The pf anchor of the rule. macOS's stock ``/etc/pf.conf`` evaluates ``rdr-anchor "com.apple/*"``,
#: so an anchor under it takes effect without an edit to that file.
ANCHOR = "com.apple/250.stadiacast"
#: The launchd job ``--launchd`` describes, and where its file goes.
LAUNCHD_LABEL = "lol.stadiacast.dns-redirect"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"


@dataclass(frozen=True)
class Redirect:
    """One redirect: the DNS queries from ``network`` go to ``address``:``port``."""

    address: str  # this computer's address on the controller's network
    network: str  # that network, as 192.168.2.0/24
    port: int = FALLBACK_DNS_PORT
    interface: str = ""  # empty: whatever interface the network is on
    interface_seen: str = ""  # the interface that has the address now, for the reader

    @property
    def rule(self) -> str:
        on = f"on {self.interface} " if self.interface else ""
        return (
            f"rdr pass {on}inet proto {{ udp, tcp }} from {self.network} to any port 53 "
            f"-> {self.address} port {self.port}"
        )

    def load_command(self) -> str:
        return f"echo {shlex.quote(self.rule)} | sudo pfctl -a {ANCHOR} -f -"

    def launchd_plist(self) -> str:
        """A launchd job that loads the rule at every start of the Mac and again every five
        minutes, since a change of Internet Sharing may reload pf without it."""
        script = f"echo {shlex.quote(self.rule)} | /sbin/pfctl -a {ANCHOR} -f - ; /sbin/pfctl -e ; true"
        script = script.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n'
            f"  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n"
            "  <key>ProgramArguments</key>\n"
            f"  <array><string>/bin/sh</string><string>-c</string><string>{script}</string></array>\n"
            "  <key>RunAtLoad</key><true/>\n"
            "  <key>StartInterval</key><integer>300</integer>\n"
            "</dict>\n</plist>\n"
        )


def plan(
    advertise_ip: str | None,
    controller_ip: str,
    port: int,
    interface: str = "",
    known: Sequence[Interface] | None = None,
    route: Callable[[str], str | None] = local_ip_towards,
) -> Redirect:
    """The redirect for this computer: its address on the controller's network and that network,
    from the interfaces as they are now. ``advertise_ip`` is taken as given when it is; otherwise
    it is the address of the interface that routes to ``controller_ip``, as the receiver finds it."""
    known = interfaces() if known is None else known
    own = interface_with(advertise_ip, known) if advertise_ip else interface_towards(controller_ip, known)
    # The route is asked only when no tool listed the interfaces: with the hotspot off it leads
    # out through the default route, to an address the controller's network never sees.
    address = advertise_ip or (own.address if own else None) or (None if known else route(controller_ip))
    if not address:
        raise SetupError(
            f"no interface of this computer is on the controller's network ({controller_ip}): start the hotspot "
            f"first, or name this computer's address on it with --advertise-ip"
        )
    own = own or interface_with(address, known)
    # With the hotspot down, or no tool to list the interfaces, the network is the address's /24.
    network = str(own.network if own is not None else ipaddress.ip_network(f"{address}/24", strict=False))
    return Redirect(address, network, port, interface, own.name if own else "")


def describe(redirect: Redirect, command: str = "stadiacast") -> str:
    """Everything a person needs to set the redirect up by hand, check it and take it away."""
    seen = (
        f"on {redirect.interface_seen} now"
        if redirect.interface_seen
        else "on no interface now: the hotspot is off, so the network is a guess from the address"
    )
    return f"""\
The controller asks port 53. The DNS sink of this receiver listens on port {redirect.port}, at
{redirect.address} ({seen}), and this pf rule sends it every DNS query that arrives from
{redirect.network}:

    {redirect.rule}

Set it up (root, until the next restart of the Mac):

    {redirect.load_command()}
    sudo pfctl -s info | grep -q 'Status: Enabled' || sudo pfctl -E

or let this command run the same through sudo, each line shown first:

    {command} dns-redirect --apply --advertise-ip {redirect.address} --dns-port {redirect.port}

Check that it is loaded, and that packets match it once the controller wakes:

    sudo pfctl -a {ANCHOR} -s nat
    sudo pfctl -a {ANCHOR} -vs nat      # the counters: Evaluations and Packets grow with the queries
    sudo tcpdump -ni {redirect.interface_seen or "<the hotspot's bridge>"} port 53 or port {redirect.port}

Keep it across restarts and changes of Internet Sharing, with a launchd job that loads it again:

    {command} dns-redirect --launchd --advertise-ip {redirect.address} --dns-port {redirect.port} \\
        | sudo tee {LAUNCHD_PLIST} >/dev/null
    sudo launchctl bootstrap system {LAUNCHD_PLIST}

Take it away:

    sudo pfctl -a {ANCHOR} -F all
    sudo launchctl bootout system/{LAUNCHD_LABEL}; sudo rm -f {LAUNCHD_PLIST}      # if the job was installed
"""


#: Runs one root step: the command (without ``sudo``), its standard input, and the result.
SudoRunner = Callable[[Sequence[str], str | None], "subprocess.CompletedProcess[str]"]


def run_sudo(command: Sequence[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run ``command`` as root through ``sudo``, which asks for the password on the terminal."""
    return subprocess.run(["sudo", *command], input=stdin, capture_output=True, text=True, check=False)


def _step(sudo: SudoRunner, command: Sequence[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    shown = f"echo {shlex.quote(stdin)} | " if stdin is not None else ""
    print(f"  {shown}sudo {shlex.join(command)}", flush=True)
    return sudo(command, stdin)


def loaded_rules(sudo: SudoRunner) -> list[str]:
    """The redirect rules in the anchor now."""
    shown = _step(sudo, ["pfctl", "-a", ANCHOR, "-s", "nat"])
    return [line.strip() for line in shown.stdout.splitlines() if line.strip().startswith("rdr")]


def apply(redirect: Redirect, sudo: SudoRunner = run_sudo) -> int:
    """Load the rule, switch pf on when it is off, and read the rule back. Exit status."""
    print("loading the redirect, as root:")
    load = _step(sudo, ["pfctl", "-a", ANCHOR, "-f", "-"], redirect.rule + "\n")
    if load.returncode != 0:
        print(f"stadiacast: pf refused the rule: {load.stderr.strip() or load.stdout.strip()}", file=sys.stderr)
        return 1
    info = _step(sudo, ["pfctl", "-s", "info"])
    if "Status: Enabled" not in info.stdout:
        enable = _step(sudo, ["pfctl", "-E"])
        if enable.returncode != 0:
            print(f"stadiacast: pf could not be switched on: {enable.stderr.strip()}", file=sys.stderr)
            return 1
    rules = loaded_rules(sudo)
    if not any(f"port {redirect.port}" in rule for rule in rules):
        found = rules or "nothing"
        print(f"stadiacast: the rule was loaded and is not in {ANCHOR} now (found: {found})", file=sys.stderr)
        return 1
    print(
        f"loaded: DNS queries from {redirect.network} go to {redirect.address} port {redirect.port}, until the Mac "
        f"restarts or pf is reloaded.\nWake the controller: the receiver's dns.jsonl gets a line for each query."
    )
    return 0


def remove(sudo: SudoRunner = run_sudo) -> int:
    print("removing the redirect, as root:")
    flushed = _step(sudo, ["pfctl", "-a", ANCHOR, "-F", "all"])
    if flushed.returncode != 0:
        print(f"stadiacast: {flushed.stderr.strip() or 'pfctl failed'}", file=sys.stderr)
        return 1
    print(f"removed: nothing is in {ANCHOR}. pf itself is left as it was.")
    return 0


def status(redirect: Redirect, sudo: SudoRunner = run_sudo) -> int:
    """Say whether the rule is loaded and pf is on; exit status 0 only when both are."""
    print("reading pf, as root:")
    rules = loaded_rules(sudo)
    enabled = "Status: Enabled" in _step(sudo, ["pfctl", "-s", "info"]).stdout
    wanted = [rule for rule in rules if f"port {redirect.port}" in rule]
    if wanted and enabled:
        print(f"loaded and pf is on: {wanted[0]}")
        return 0
    if wanted:
        print("the rule is loaded, and pf is off, so it does nothing: sudo pfctl -E")
    elif rules:
        print(f"another rule is loaded, not one for port {redirect.port}: {rules[0]}")
    else:
        print(f"no rule is loaded in {ANCHOR}")
    return 1


def main(
    argv: Sequence[str] | None = None,
    *,
    sudo: SudoRunner = run_sudo,
    run: Runner = run_tool,
    platform: str | None = None,
) -> int:
    ap = argparse.ArgumentParser(
        prog="stadiacast dns-redirect",
        description="macOS: show, load or remove the pf rule that sends the controller's DNS queries to a DNS "
        "sink on another port than 53. Without --apply, --remove or --status nothing is changed and no root "
        "is asked for.",
    )
    ap.add_argument(
        "--advertise-ip",
        default=None,
        help="this computer's address on the controller's network (default: the one that routes to --controller-ip)",
    )
    ap.add_argument("--controller-ip", default=DEFAULT_CONTROLLER_IP, help="an address on the controller's network")
    ap.add_argument("--dns-port", type=int, default=FALLBACK_DNS_PORT, help="the port the DNS sink listens on")
    ap.add_argument(
        "--interface",
        default="",
        help="match on this interface only (default: any, by the network's addresses, which holds whatever "
        "number the hotspot's bridge got)",
    )
    action = ap.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true", help="load the rule through sudo, and switch pf on if off")
    action.add_argument("--remove", action="store_true", help="empty the anchor through sudo")
    action.add_argument("--status", action="store_true", help="read the anchor and pf's state through sudo")
    action.add_argument("--launchd", action="store_true", help="print a launchd job that keeps the rule loaded")
    args = ap.parse_args(argv)
    platform = platform or sys.platform
    try:
        redirect = plan(args.advertise_ip, args.controller_ip, args.dns_port, args.interface, interfaces(run))
    except SetupError as e:
        print(f"stadiacast: {e}", file=sys.stderr)
        return 2
    if args.launchd:
        print(redirect.launchd_plist(), end="")
        return 0
    if not (args.apply or args.remove or args.status):
        print(describe(redirect), end="")
        return 0
    if platform != "darwin":
        print("stadiacast: dns-redirect changes pf, the packet filter of macOS, and this is not a Mac", file=sys.stderr)
        return 2
    if args.remove:
        return remove(sudo)
    if args.status:
        return status(redirect, sudo)
    return apply(redirect, sudo)
