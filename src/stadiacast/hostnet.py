"""What this computer's network looks like: its interfaces, and who holds a port.

The receiver asks before it starts a helper on a port, and the commands that explain a setup
(``stadiacast dns-redirect``) ask to name the interface and the network of the controller. The
facts come from the system's own tools (``ifconfig``, ``ip``, ``lsof``), run without root, and
the parsers take their output as text so that the tests feed them what a Mac prints.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

#: Runs a command and returns what it printed, or None when it is missing, failed or hung.
Runner = Callable[[Sequence[str]], str | None]


def run_tool(command: Sequence[str], timeout: float = 5.0) -> str | None:
    """Standard output of ``command``, or None: a tool that is absent or fails is a fact too."""
    if shutil.which(command[0]) is None:
        return None
    try:
        done = subprocess.run(
            list(command), capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 or done.stdout else None


@dataclass(frozen=True)
class Interface:
    """One IPv4 address of this computer: the interface that has it and the network it is on."""

    name: str
    address: str
    prefix: int
    members: tuple[str, ...] = ()  # of a bridge: the interfaces it joins (a Mac's hotspot has its Wi-Fi here)
    active: bool = True

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.address}/{self.prefix}", strict=False)  # type: ignore[return-value]

    def holds(self, ip: str) -> bool:
        """True when ``ip`` is an address of this interface's network."""
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False


def _prefix(netmask: str) -> int:
    """The prefix length of a netmask as ``ifconfig`` writes it: ``0xffffff00`` or ``255.255.255.0``."""
    value = int(netmask, 16) if netmask.startswith("0x") else int(ipaddress.IPv4Address(netmask))
    return value.bit_count()


_IFCONFIG_HEAD = re.compile(r"^(\S+?):? ")
_IFCONFIG_INET = re.compile(r"^\s+inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)\s.*?(?:netmask |Mask:)(\S+)")
_IP_ADDR = re.compile(r"^\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)")


def parse_ifconfig(text: str) -> list[Interface]:
    """The IPv4 addresses in the output of ``ifconfig`` (macOS, the BSDs, Linux's net-tools)."""
    found: list[Interface] = []
    name = ""
    addresses: list[tuple[str, int]] = []
    members: list[str] = []
    active = True

    def flush() -> None:
        found.extend(Interface(name, address, prefix, tuple(members), active) for address, prefix in addresses)

    for line in text.splitlines():
        head = _IFCONFIG_HEAD.match(line)
        if head and not line[0].isspace():
            flush()
            name, addresses, members, active = head.group(1), [], [], True
            continue
        inet = _IFCONFIG_INET.match(line)
        if inet:
            try:
                addresses.append((inet.group(1), _prefix(inet.group(2))))
            except ValueError:
                pass
        elif line.strip().startswith("member: "):
            members.append(line.split()[1])
        elif line.strip().startswith("status: "):
            active = line.split()[1] == "active"
    flush()
    return found


def parse_ip_addr(text: str) -> list[Interface]:
    """The IPv4 addresses in the output of ``ip -o -4 addr show`` (Linux without net-tools)."""
    found = []
    for line in text.splitlines():
        m = _IP_ADDR.match(line)
        if m:
            found.append(Interface(m.group(1), m.group(2), int(m.group(3))))
    return found


def interfaces(run: Runner = run_tool) -> list[Interface]:
    """Every IPv4 address of this computer with its interface, or none when no tool says."""
    text = run(["ifconfig", "-a"] if sys.platform != "darwin" else ["ifconfig"])
    if text:
        return parse_ifconfig(text)
    text = run(["ip", "-o", "-4", "addr", "show"])
    return parse_ip_addr(text) if text else []


def interface_with(ip: str, known: Sequence[Interface]) -> Interface | None:
    """The interface that has ``ip`` as its own address."""
    return next((i for i in known if i.address == ip), None)


def interface_towards(ip: str, known: Sequence[Interface]) -> Interface | None:
    """The interface whose network ``ip`` is on, the most specific one first."""
    on = [i for i in known if i.holds(ip)]
    return max(on, key=lambda i: i.prefix) if on else None


@dataclass(frozen=True)
class Holder:
    """A process that has a port open, as ``lsof`` lists it."""

    command: str
    pid: int
    user: str
    address: str  # what it is bound to: ``*:53``, ``192.168.2.1:53``

    def __str__(self) -> str:
        return f"{self.command} (pid {self.pid}, user {self.user}) on {self.address}"


def parse_lsof(text: str) -> list[Holder]:
    """The processes in the output of ``lsof -nP -i``, one for each socket."""
    holders = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9 or not parts[1].isdigit():
            continue
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(LISTEN)]
        holders.append(Holder(parts[0].replace("\\x20", " "), int(parts[1]), parts[2], parts[8]))
    return holders


def port_holders(port: int, protocol: str, run: Runner = run_tool) -> list[Holder]:
    """Who has ``port`` open (``protocol`` is ``udp`` or ``tcp``), as far as this user may see.

    ``lsof`` shows the sockets of the user's own processes and, to root, everyone's: a port that
    is taken with nobody listed here belongs to another user's process, a system service.
    """
    spec = f"-iUDP:{port}" if protocol == "udp" else f"-iTCP:{port}"
    args = ["lsof", "-nP", spec] + (["-sTCP:LISTEN"] if protocol == "tcp" else [])
    text = run(args)
    seen: dict[tuple[int, str], Holder] = {}
    for holder in parse_lsof(text) if text else []:
        seen.setdefault((holder.pid, holder.address), holder)
    return list(seen.values())


@dataclass
class PortProbe:
    """Whether a listener could take a port now, and who has it when it could not."""

    port: int
    protocol: str  # udp | tcp
    address: str
    error: OSError | None = None
    holders: list[Holder] = field(default_factory=list)

    @property
    def free(self) -> bool:
        return self.error is None


def probe_port(address: str, port: int, protocol: str, run: Runner = run_tool) -> PortProbe:
    """Try the bind a helper would make (same options, closed at once), and name the holder when
    it is refused."""
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    probe = PortProbe(port, protocol, address)
    with socket.socket(socket.AF_INET, kind) as s:
        if sys.platform != "win32":  # as socketserver's allow_reuse_address does
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((address, port))
        except OSError as e:
            probe.error = e
    if probe.error is not None:
        probe.holders = port_holders(port, protocol, run)
    return probe


def describe_holders(probe: PortProbe) -> str:
    """Who holds the port of a refused probe, in words: the processes ``lsof`` named, or what a
    port that nobody visible holds means on this system."""
    if probe.holders:
        return ", ".join(str(h) for h in probe.holders)
    if sys.platform == "darwin" and probe.port == 53:
        return (
            "mDNSResponder, most likely: macOS relays DNS itself for Internet Sharing and for virtual machines, "
            f"and a process of another user is listed to root only (sudo lsof -nP -i{probe.protocol.upper()}:53)"
        )
    return "a process of another user, which is listed to root only"
