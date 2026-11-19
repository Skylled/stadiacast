"""stadiacast doctor: each check against what a Mac answers, and the report as text and as JSON.

The Mac here is the one the doctor was written for: Ethernet shared over a Wi-Fi hotspot on
bridge101, a virtual machine on bridge100, and mDNSResponder on port 53.
"""

from __future__ import annotations

import asyncio
import datetime
import errno
import json
import plistlib
from typing import Any

import pytest

from stadiacast import doctor
from stadiacast.cli import main, parse_args
from stadiacast.doctor import FAIL, INFO, OK, SKIP, WARN, Check, Env
from stadiacast.errors import SetupError
from stadiacast.hostnet import Holder, PortProbe
from tests.helpers import connect_firmware_flow, make_receiver, wait_for
from tests.test_hostnet import MAC_IFCONFIG

FLAGS = ["--preset", "live", "--dns-upstream", "192.168.86.1", "--advertise-ip", "192.168.2.1", "--gamepad", "ojd"]
LEASES = """\
{
	name=stadia-1a2b
	ip_address=192.168.2.2
	hw_address=1,a4:77:33:1a:2b:3c
	identifier=1,a4:77:33:1a:2b:3c
	lease=0x7fffffff
}
{
	name=old-phone
	ip_address=192.168.2.9
	hw_address=1,0:11:22:33:44:55
	lease=0x10
}
{
	name=a-virtual-machine
	ip_address=192.168.64.2
	hw_address=1,2:0:0:0:0:0
	lease=0x7fffffff
}
"""
ARP = """\
? (192.168.2.2) at a4:77:33:1a:2b:3c on bridge101 ifscope [bridge]
? (192.168.2.9) at (incomplete) on bridge101 ifscope [bridge]
? (192.168.86.1) at 0:aa:bb:cc:dd:ee on en0 ifscope [ethernet]
"""
GOOGLE = ["142.250.72.10"]
STATUS = {
    "version": "1.3.0",
    "pid": 500,
    "controllers": {},
    "helpers": {"dns_sink": {"listen": "0.0.0.0:5300", "pid": 501, "running": True, "returncode": None}},
    "log_dir": "/runs/now",
}


class Mac:
    """A Mac's answers, as an :class:`Env`. Attributes say what state it is in."""

    def __init__(self, **state: Any) -> None:
        self.ifconfig = MAC_IFCONFIG
        self.status: dict[str, Any] | None = None  # /_status of a running receiver
        self.system_holds_53 = True
        self.held: dict[tuple[int, str], list[Holder]] = {}  # other taken ports
        self.dns_log = ""  # the sink's dns.jsonl
        self.pf_rules: str | None = None  # what pfctl shows root
        self.root = False
        self.files: dict[str, bytes] = {
            doctor.MAC_LEASES: LEASES.encode(),
            doctor.MAC_SHARING: plistlib.dumps({"NAT": {"Enabled": 1}}),
        }
        self.tools: dict[str, str | None] = {
            "arp": ARP,
            "ojd": "0.6.0-alpha.1\n",
            "pgrep": "812 /Applications/OpenJoystickDriver.app/Contents/MacOS/OpenJoystickDriver\n",
            "ffmpeg": " A....D libopus              libopus Opus (codec opus)\n",
            "socketfilterfw": "Firewall is disabled. (State = 0)\n",
        }
        self.unreachable: OSError | None = None
        self.ojd: str | None = "/usr/local/bin/ojd"
        for key, value in state.items():
            setattr(self, key, value)

    def run(self, command):
        tool = command[0].rpartition("/")[2]
        if tool == "ifconfig":
            return self.ifconfig
        if tool == "pfctl":
            return self.pf_rules
        return self.tools.get(tool)

    def read(self, path: str) -> bytes | None:
        if path == "/runs/now/dns.jsonl":
            return self.dns_log.encode()
        return self.files.get(path)

    def probe(self, address: str, port: int, protocol: str) -> PortProbe:
        in_use = OSError(errno.EADDRINUSE, "Address already in use")
        if (port, protocol) in self.held:
            return PortProbe(port, protocol, address, in_use, self.held[(port, protocol)])
        if port == 53 and self.system_holds_53:
            return PortProbe(port, protocol, address, in_use, [])
        if self.status is not None:  # a running receiver has its own ports
            return PortProbe(port, protocol, address, in_use, [Holder("python3.14", 500, "kyle", f"*:{port}")])
        return PortProbe(port, protocol, address)

    def ask_dns(self, _server: str, port: int, name: str) -> list[str] | None:
        if name == "example.com":
            return ["93.184.216.34"]
        if port == 53:  # macOS's relay
            return GOOGLE
        return ["192.168.2.1"] if self.status is not None else None

    def find_ojd(self, _path: str) -> str:
        if self.ojd is None:
            raise SetupError("--gamepad ojd needs OpenJoystickDriver; install its signed app")
        return self.ojd

    def env(self) -> Env:
        return Env(
            platform="darwin",
            root=self.root,
            run=self.run,
            read=self.read,
            probe=self.probe,
            ask_dns=self.ask_dns,
            send_udp=lambda _ip: self.unreachable,
            get_json=lambda _url: self.status,
            which=lambda name: f"/opt/homebrew/bin/{name}" if self.tools.get(name) else None,
            find_ojd=self.find_ojd,
            now=lambda: datetime.datetime(2026, 11, 19, tzinfo=datetime.UTC),
        )


def examine(mac: Mac, flags: list[str] | None = None) -> dict[str, Check]:
    checks = doctor.examine(parse_args(FLAGS if flags is None else flags), mac.env())
    assert len({c.id for c in checks}) == len(checks)  # an id names one check
    return {c.id: c for c in checks}


def query(source: str, name: str = "cloudcast-pa.googleapis.com", action: str = "redirect") -> str:
    record = {"ts": "2026-11-18T21:00:00.000-05:00", "event": "query", "src": f"{source}:40001"}
    return json.dumps({**record, "qname": name, "action": action}) + "\n"


def test_before_the_receiver_starts_it_says_port_53_is_the_systems_and_what_follows() -> None:
    found = examine(Mac())
    assert found["receiver"].status == INFO and found["receiver"].data == {"running": False}
    assert found["network"].status == OK and "192.168.2.1 on bridge101" in found["network"].summary
    assert found["network"].data["internet_sharing_enabled"] is True and found["network"].data["members"] == ["ap1"]
    assert "not bridge100" in found["network.bridge"].summary
    for port in ("port.tcp.443", "port.tcp.80", "port.udp.40000", "port.udp.123"):
        assert found[port].status == OK and found[port].summary.endswith("is free")
    moved = found["port.udp.53"]
    assert moved.status == WARN and "mDNSResponder, most likely" in moved.summary and "port 5300" in moved.summary
    path = found["dns.path"]
    assert path.status == WARN and "gives 142.250.72.10, Google's addresses" in path.summary
    assert path.fix[0] == "stadiacast dns-redirect --apply --advertise-ip 192.168.2.1 --dns-port 5300"
    assert path.data["redirect_loaded"] is None and "cannot be seen without root" in path.summary
    assert found["dns.upstream"].status == OK and "dns.sink" not in found


def test_the_devices_on_the_hotspot_are_listed_with_who_answers() -> None:
    devices = examine(Mac())["devices"]
    assert devices.status == OK
    assert "stadia-1a2b 192.168.2.2 (a4:77:33:1a:2b:3c, answering)" in devices.summary
    assert "old-phone 192.168.2.9 (0:11:22:33:44:55, silent now, lease run out)" in devices.summary
    assert [d["ip"] for d in devices.data["devices"]] == ["192.168.2.2", "192.168.2.9"]  # not the virtual machine's

    asleep = examine(Mac(tools={"arp": ""}))["devices"]
    assert asleep.status == WARN and "None answers now" in asleep.summary

    nobody = examine(Mac(files={}))
    assert nobody["devices"].status == WARN and "has not joined the Wi-Fi" in nobody["devices"].summary
    assert "stadiacast-provision provision" in nobody["devices"].fix[0]
    assert nobody["network"].data["internet_sharing_enabled"] is None

    elsewhere = examine(Mac(), [*FLAGS, "--controller-ip", "192.168.2.7"])["devices.controller_ip"]
    assert elsewhere.status == INFO and elsewhere.fix == ["--controller-ip 192.168.2.2"]


def test_a_device_awake_whose_queries_never_reach_the_moved_sink_is_a_failure_with_what_to_run() -> None:
    found = examine(Mac(status=STATUS))
    assert found["receiver"].status == OK and found["receiver"].data["pid"] == 500
    assert (
        found["port.udp.5300"].summary == "UDP port 5300 (DNS sink): the receiver has it" and "port.udp.53" not in found
    )
    assert found["dns.sink"].status == OK
    path = found["dns.path"]
    assert path.status == FAIL
    assert "A device is on the network and awake, and none of its queries has reached the sink" in path.summary
    assert path.fix == [
        "stadiacast dns-redirect --apply --advertise-ip 192.168.2.1 --dns-port 5300",
        "sudo pfctl -a com.apple/250.stadiacast -vs nat      # loaded? do the counters grow when the controller wakes?",
        "sudo tcpdump -ni bridge101 port 53 or port 5300",
    ]
    assert found["controllers"].status == INFO


def test_queries_from_the_hotspot_in_the_sinks_log_prove_the_redirect() -> None:
    log = query("192.168.125.7", "probe") + query("192.168.2.2", "time.google.com") + query("192.168.2.2")
    path = examine(Mac(status=STATUS, dns_log=log))["dns.path"]
    assert (
        path.status == OK and "which works: 2 of the sink's queries came from the controller's network" in path.summary
    )
    assert path.data["sink_log"] == {
        "queries": 3,
        "from_network": 2,
        "redirected": 2,
        "last": "2026-11-18T21:00:00.000-05:00",
        "last_name": "cloudcast-pa.googleapis.com",
    }


def test_root_reads_the_pf_anchor_itself() -> None:
    empty = examine(Mac(status=STATUS, root=True, pf_rules=""))["dns.path"]
    assert empty.status == FAIL and "no rule is loaded in com.apple/250.stadiacast" in empty.summary
    rule = "rdr pass inet proto udp from 192.168.2.0/24 to any port = 53 -> 192.168.2.1 port 5300\n"
    loaded = examine(Mac(status=STATUS, root=True, pf_rules=rule))["dns.path"]
    assert loaded.status == FAIL and loaded.data["redirect_loaded"] is True and "the rule is loaded" in loaded.summary
    asleep = examine(Mac(status=STATUS, root=True, pf_rules=rule, tools={"arp": ""}))["dns.path"]
    assert asleep.status == WARN and "a rule is loaded" in asleep.summary


def test_a_sink_on_port_53_is_asked_as_the_controller_asks() -> None:
    on_53 = {**STATUS, "helpers": {"dns_sink": {"listen": "0.0.0.0:53", "pid": 501, "running": True}}}
    mac = Mac(status=on_53, system_holds_53=False)
    mac.ask_dns = lambda _server, _port, name: ["192.168.2.1"] if "googleapis" in name else ["1.1.1.1"]  # type: ignore[method-assign]
    found = examine(mac)
    assert found["dns.path"].status == OK and found["port.udp.53"].summary.endswith("the receiver has it")
    mac.ask_dns = lambda _server, _port, _name: GOOGLE  # type: ignore[method-assign]
    assert examine(mac)["dns.path"].status == FAIL and examine(mac)["dns.sink"].status == FAIL


def test_a_sink_that_exited_and_an_upstream_that_is_silent_are_failures() -> None:
    dead = {**STATUS, "helpers": {"dns_sink": {"listen": "0.0.0.0:53", "pid": 501, "running": False, "returncode": 1}}}
    sink = examine(Mac(status=dead))["dns.sink"]
    assert sink.status == FAIL and "it exited with status 1" in sink.summary
    mac = Mac()
    mac.ask_dns = lambda _server, _port, _name: None  # type: ignore[method-assign]
    upstream = examine(mac)["dns.upstream"]
    assert upstream.status == FAIL and "192.168.86.1 (--dns-upstream) did not answer" in upstream.summary
    assert examine(Mac(), ["--advertise-ip", "192.168.2.1"])["dns"].status == INFO  # no sink asked for


def test_a_hotspot_that_is_off_fails_once_and_the_rest_is_skipped() -> None:
    mac = Mac(ifconfig=MAC_IFCONFIG[: MAC_IFCONFIG.index("bridge101:")])
    mac.files[doctor.MAC_SHARING] = plistlib.dumps({"NAT": {"Enabled": 0}})
    found = examine(mac)
    assert (
        found["network"].status == FAIL and "no interface of this computer has 192.168.2.1" in found["network"].summary
    )
    assert "it is switched off" in found["network"].fix[0]
    assert found["devices"].status == SKIP and found["dns.path"].status == SKIP


def test_ports_held_by_other_programs_are_named() -> None:
    leftover = Holder("python3.14", 4242, "kyle", "*:443")
    found = examine(Mac(held={(443, "tcp"): [leftover]}))
    assert (
        found["port.tcp.443"].status == FAIL
        and "held by python3.14 (pid 4242, user kyle)" in found["port.tcp.443"].summary
    )
    assert found["port.tcp.443"].fix == ["stop that program (kill 4242)"]
    # the same holder beside a running receiver is not the receiver
    running = examine(Mac(status=STATUS, held={(443, "tcp"): [leftover]}))
    assert running["port.tcp.443"].status == FAIL and running["port.tcp.80"].status == OK

    mac = Mac()
    mac.probe = lambda address, port, protocol: PortProbe(port, protocol, address, PermissionError(13, "denied"))  # type: ignore[method-assign]
    refused = examine(mac, [*FLAGS, "--bind", "192.168.2.1"])["port.tcp.443"]
    assert refused.status == FAIL and "--bind 0.0.0.0" in refused.fix[0]

    free = Mac(status=STATUS)
    free.probe = lambda address, port, protocol: PortProbe(port, protocol, address)  # type: ignore[method-assign]
    assert "is free although a receiver is running" in examine(free)["port.tcp.443"].summary


def test_local_network_privacy_that_refuses_the_send_is_found() -> None:
    refused = examine(Mac(unreachable=OSError(errno.EHOSTUNREACH, "No route to host")))["devices.reach"]
    assert refused.status == FAIL and "Local Network" in refused.fix[0] and refused.data["ip"] == "192.168.2.2"
    assert "devices.reach" not in examine(Mac())


def test_the_pad_driver_and_ffmpeg() -> None:
    found = examine(Mac())
    assert found["ojd"].status == OK and found["ojd.running"].status == OK and found["ffmpeg"].status == OK
    assert found["firewall"].status == OK

    newer = examine(Mac(tools={"ojd": "0.6.0-alpha.2+build.7\n", "pgrep": ""}))
    assert newer["ojd"].status == INFO and "0.6.0-alpha.2+build.7" in newer["ojd"].summary
    assert newer["ojd.running"].status == WARN and newer["ojd.running"].fix[0] == "open -a OpenJoystickDriver"
    assert newer["ffmpeg"].status == INFO  # no ffmpeg, and nothing asked for needs it

    missing = examine(Mac(ojd=None))
    assert missing["ojd"].status == FAIL and "ojd.running" not in missing
    assert "ojd" not in examine(Mac(), FLAGS[:-2])  # no --gamepad ojd

    plain = Mac(
        tools={"ffmpeg": " A....D opus                 Opus\n", "socketfilterfw": "Firewall is enabled. (State = 1)\n"}
    )
    sound = examine(plain, [*FLAGS, "--audio-source", "tone"])
    assert sound["ffmpeg"].status == FAIL and "has no libopus encoder" in sound["ffmpeg"].summary
    assert sound["firewall"].status == WARN
    assert examine(Mac(tools={}), [*FLAGS, "--audio-source", "tone"])["ffmpeg"].status == FAIL


def test_the_controllers_and_pads_of_a_running_receiver() -> None:
    status = {
        **STATUS,
        "controllers": {
            "c0": {
                "ip": "192.168.2.2",
                "last_seen_s": 0.4,
                "battery_percent": 80,
                "session": {"display": {"state": "input"}},
            },
            "c1": {"ip": "192.168.2.3", "last_seen_s": 9.0, "session": {"display": {"state": "dtls-connected"}}},
        },
        "gamepads": {"c0": {"slot": None, "kind": "ojd"}, "c1": {"error": "OJD input queue is full"}},
    }
    found = examine(Mac(status=status))
    assert found["controller.c0"].status == OK and "(connected)" in found["controller.c0"].summary
    assert found["controller.c1"].status == INFO and "not connected yet" in found["controller.c1"].summary
    assert found["gamepad.c1"].status == FAIL and "OJD input queue is full" in found["gamepad.c1"].summary


def test_the_lease_file_and_the_arp_table_are_read() -> None:
    leases = doctor.parse_mac_leases(LEASES + "{\n\tname=no-address\n}\n")
    assert leases[0] == {"name": "stadia-1a2b", "ip": "192.168.2.2", "mac": "a4:77:33:1a:2b:3c", "expires": 0x7FFFFFFF}
    assert len(leases) == 3
    assert doctor.parse_arp(ARP) == {"192.168.2.2": "a4:77:33:1a:2b:3c", "192.168.86.1": "0:aa:bb:cc:dd:ee"}


def test_a_check_that_breaks_is_reported_and_the_others_run() -> None:
    mac = Mac()
    mac.read = lambda _path: 1 / 0  # type: ignore[method-assign,assignment]
    found = examine(mac)
    assert found["network"].status == FAIL and "a bug in the doctor: ZeroDivisionError" in found["network"].summary
    assert found["ffmpeg"].status == OK


def test_the_report_as_text_and_as_json(capsys) -> None:
    mac = Mac(status=STATUS)
    assert doctor.main(FLAGS, mac.env()) == 1
    said = capsys.readouterr().out
    assert said.startswith("stadiacast doctor ")
    assert "\nok    receiver " in said and "\nFAIL  dns.path " in said
    assert "  do: stadiacast dns-redirect --apply --advertise-ip 192.168.2.1 --dns-port 5300\n" in said
    assert "1 problem(s), 0 warning(s). Start with the first FAIL." in said
    assert "the pf rules were not read" in said

    assert doctor.main(["--json", *FLAGS], mac.env()) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["healthy"] is False and document["summary"]["fail"] == 1 and document["platform"] == "darwin"
    by_id = {c["id"]: c for c in document["checks"]}
    assert set(by_id["dns.path"]) == {"id", "status", "summary", "fix", "data"}
    assert by_id["dns.path"]["status"] == "fail" and by_id["dns.path"]["data"]["sink_port"] == 5300
    assert by_id["devices"]["data"]["devices"][0]["mac"] == "a4:77:33:1a:2b:3c"

    log = query("192.168.2.2")
    assert doctor.main(FLAGS, Mac(status=STATUS, dns_log=log).env()) == 0
    assert "no problem found." in capsys.readouterr().out


def test_the_command_is_reached_through_stadiacast_and_explains_itself(capsys, tmp_path) -> None:
    assert main(["doctor", "--help"]) == 0
    assert "usage: stadiacast doctor [--json]" in capsys.readouterr().out
    with pytest.raises(SystemExit) as refused:
        main(["doctor", "--no-such-flag"])
    assert refused.value.code == 2
    assert main(["doctor", "--rpc-response", f"X={tmp_path / 'missing'}"]) == 2


def test_it_reads_a_real_receiver_and_its_controller(tmp_path) -> None:
    """The one check that goes over the wire here: /_status of a receiver a fake controller has joined."""

    async def run() -> list[Check]:
        rx = make_receiver(tmp_path)
        await rx.start()
        try:
            fc = await connect_firmware_flow(rx)
            await asyncio.wait_for(fc.display_ready.wait(), 5)
            assert (await fc.keepalive())["code"] == 0
            await wait_for(lambda: rx.single().display_state in ("ready", "input"))
            cfg = parse_args(["--http-ports", str(rx.http.http_ports[0]), "--advertise-ip", "127.0.0.1"])
            env = Mac().env()
            env.get_json = doctor.get_json
            facts = doctor.Facts()
            found = await asyncio.to_thread(doctor.check_receiver, cfg, env, facts)
            found += doctor.check_controllers(cfg, env, facts)
            fc.close()
            assert facts.status is not None and facts.status["log_dir"] == str(tmp_path / "logs")
            return found
        finally:
            await rx.stop()

    receiver, controller = asyncio.run(run())
    assert receiver.status == OK and receiver.data["controllers"] == 1 and receiver.data["pid"]
    assert controller.id == "controller.c0" and controller.status == OK and controller.data["ip"] == "127.0.0.1"
