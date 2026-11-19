"""stadiacast.hostnet: this computer's interfaces and the holders of a port, from what the system's tools print."""

from __future__ import annotations

import errno
import socket
import sys

from stadiacast import hostnet

#: A Mac that shares its Ethernet over Wi-Fi and runs a virtual machine: the machine's bridge
#: came first, so the hotspot is bridge101.
MAC_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:11:22:33:44:55
	inet6 fe80::1%en0 prefixlen 64 secured scopeid 0x5
	inet 192.168.86.20 netmask 0xffffff00 broadcast 192.168.86.255
	status: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:11:22:33:44:66
	status: inactive
bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	options=3<RXCSUM,TXCSUM>
	ether 02:00:00:00:00:64
	inet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
	member: vmenet0 flags=3<LEARNING,DISCOVER>
	status: active
bridge101: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	ether 02:00:00:00:00:65
	inet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255
	member: ap1 flags=3<LEARNING,DISCOVER>
	status: active
"""

LINUX_IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.0.0  broadcast 10.0.255.255
"""

LINUX_IP = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: wlan0    inet 192.168.2.1/24 brd 192.168.2.255 scope global wlan0\\       valid_lft forever preferred_lft forever
"""

LSOF = """\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
mDNSRespo   243 _mdnsresponder    6u  IPv4 0x6be63bf721e245d3      0t0  UDP *:53
mDNSRespo   243 _mdnsresponder    7u  IPv6 0x6be63bf721e245d4      0t0  UDP *:53
python3.1  9001 kyle   12u  IPv4 0x2284489a3bae76fb      0t0  TCP 127.0.0.1:5300 (LISTEN)
"""


def test_a_macs_interfaces_are_read_with_their_networks_and_bridge_members() -> None:
    found = hostnet.parse_ifconfig(MAC_IFCONFIG)
    assert [(i.name, i.address, i.prefix) for i in found] == [
        ("lo0", "127.0.0.1", 8),
        ("en0", "192.168.86.20", 24),
        ("bridge100", "192.168.64.1", 24),
        ("bridge101", "192.168.2.1", 24),
    ]
    hotspot = hostnet.interface_towards("192.168.2.2", found)
    assert hotspot is not None and hotspot.name == "bridge101" and hotspot.members == ("ap1",) and hotspot.active
    assert str(hotspot.network) == "192.168.2.0/24"
    assert hostnet.interface_with("192.168.64.1", found).name == "bridge100"  # type: ignore[union-attr]
    assert hostnet.interface_towards("10.9.9.9", found) is None and hostnet.interface_with("192.168.2.2", found) is None


def test_linux_interfaces_are_read_from_either_tool() -> None:
    assert [(i.name, i.address, i.prefix) for i in hostnet.parse_ifconfig(LINUX_IFCONFIG)] == [("eth0", "10.0.0.5", 16)]
    assert [(i.name, i.address, i.prefix) for i in hostnet.parse_ip_addr(LINUX_IP)] == [
        ("lo", "127.0.0.1", 8),
        ("wlan0", "192.168.2.1", 24),
    ]
    by_tool = {"ifconfig": None, "ip": LINUX_IP}
    assert [i.name for i in hostnet.interfaces(lambda command: by_tool[command[0]])] == ["lo", "wlan0"]
    assert hostnet.interfaces(lambda _command: None) == []


def test_the_holders_of_a_port_are_named_once_each() -> None:
    asked: list[list[str]] = []

    def lsof(command):
        asked.append(list(command))
        return LSOF

    holders = hostnet.port_holders(53, "udp", lsof)
    assert asked == [["lsof", "-nP", "-iUDP:53"]]
    assert [(h.command, h.pid, h.user, h.address) for h in holders] == [
        ("mDNSRespo", 243, "_mdnsresponder", "*:53"),
        ("python3.1", 9001, "kyle", "127.0.0.1:5300"),
    ]
    assert str(holders[0]) == "mDNSRespo (pid 243, user _mdnsresponder) on *:53"
    hostnet.port_holders(53, "tcp", lsof)
    assert asked[-1] == ["lsof", "-nP", "-iTCP:53", "-sTCP:LISTEN"]
    assert hostnet.port_holders(53, "udp", lambda _command: None) == []


def test_a_probe_says_whether_a_port_is_free_and_who_has_it(monkeypatch) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        if sys.platform == "win32":
            holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        taken = hostnet.probe_port("127.0.0.1", port, "tcp", lambda _command: LSOF)
        assert not taken.free and taken.error is not None and len(taken.holders) == 2
        assert "mDNSRespo (pid 243" in hostnet.describe_holders(taken)
    assert hostnet.probe_port("127.0.0.1", port, "tcp").free

    unseen = hostnet.PortProbe(53, "udp", "0.0.0.0", OSError(errno.EADDRINUSE, "in use"))
    monkeypatch.setattr(sys, "platform", "darwin")
    assert "mDNSResponder, most likely" in hostnet.describe_holders(unseen)
    assert "sudo lsof -nP -iUDP:53" in hostnet.describe_holders(unseen)
    monkeypatch.setattr(sys, "platform", "linux")
    assert hostnet.describe_holders(unseen) == "a process of another user, which is listed to root only"
