"""stadiacast dns-redirect: the pf rule for a DNS sink that could not have port 53, shown by default
and loaded, read or removed through sudo only when asked. No test here runs sudo or pfctl."""

from __future__ import annotations

import plistlib
import subprocess

import pytest

from stadiacast import dnsredirect
from stadiacast.cli import main
from stadiacast.errors import SetupError
from stadiacast.hostnet import parse_ifconfig
from tests.test_hostnet import MAC_IFCONFIG

KNOWN = parse_ifconfig(MAC_IFCONFIG)
RULE = "rdr pass inet proto { udp, tcp } from 192.168.2.0/24 to any port 53 -> 192.168.2.1 port 5300"


def ifconfig(_command):
    return MAC_IFCONFIG


class Sudo:
    """Stands in for sudo: records each command and answers as pfctl would."""

    def __init__(self, enabled: bool = True, loaded: bool = True, refuse: bool = False) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.enabled, self.loaded, self.refuse = enabled, loaded, refuse

    def __call__(self, command, stdin=None):
        self.calls.append((list(command), stdin))
        out, code = "", 0
        if command[-2:] == ["-f", "-"]:
            code = 1 if self.refuse else 0
        elif command[-2:] == ["-s", "info"]:
            out = f"Status: {'Enabled' if self.enabled else 'Disabled'} for 0 days\n"
        elif command[-2:] == ["-s", "nat"] and self.loaded:
            out = (
                "rdr pass inet proto udp from 192.168.2.0/24 to any port = 53 -> 192.168.2.1 port 5300\n"
                "rdr pass inet proto tcp from 192.168.2.0/24 to any port = 53 -> 192.168.2.1 port 5300\n"
            )
        return subprocess.CompletedProcess(command, code, out, "syntax error" if code else "")


def test_the_rule_names_the_controllers_network_whatever_bridge_it_is_on() -> None:
    redirect = dnsredirect.plan(None, "192.168.2.2", 5300, known=KNOWN)
    assert (redirect.address, redirect.network, redirect.interface_seen) == (
        "192.168.2.1",
        "192.168.2.0/24",
        "bridge101",
    )
    assert redirect.rule == RULE  # no interface in it: the hotspot is bridge101 here, bridge100 elsewhere
    on = dnsredirect.plan("192.168.2.1", "192.168.2.2", 5353, "bridge101", KNOWN)
    assert on.rule == RULE.replace("pass inet", "pass on bridge101 inet").replace("5300", "5353")


def test_a_hotspot_that_is_off_is_said_and_never_taken_for_the_default_route() -> None:
    without = [i for i in KNOWN if i.name != "bridge101"]
    with pytest.raises(SetupError, match="start the hotspot first"):
        dnsredirect.plan(None, "192.168.2.2", 5300, known=without, route=lambda _ip: "192.168.86.20")
    named = dnsredirect.plan("192.168.2.1", "192.168.2.2", 5300, known=without)
    assert (named.network, named.interface_seen) == ("192.168.2.0/24", "")
    assert "the hotspot is off" in dnsredirect.describe(named)
    # no tool listed the interfaces: the route is all there is to go by
    assert (
        dnsredirect.plan(None, "192.168.2.2", 5300, known=[], route=lambda _ip: "192.168.2.1").address == "192.168.2.1"
    )


def test_by_default_it_shows_everything_and_runs_nothing(capsys) -> None:
    sudo = Sudo()
    assert dnsredirect.main([], sudo=sudo, run=ifconfig, platform="darwin") == 0
    said = capsys.readouterr().out
    assert sudo.calls == []
    assert RULE in said and "on bridge101 now" in said
    assert f"echo '{RULE}' | sudo pfctl -a com.apple/250.stadiacast -f -" in said
    assert "stadiacast dns-redirect --apply --advertise-ip 192.168.2.1 --dns-port 5300" in said
    assert "sudo pfctl -a com.apple/250.stadiacast -F all" in said and "tcpdump -ni bridge101" in said


def test_apply_loads_the_rule_through_sudo_and_shows_each_step(capsys) -> None:
    sudo = Sudo(enabled=False)
    assert dnsredirect.main(["--apply"], sudo=sudo, run=ifconfig, platform="darwin") == 0
    assert [call[0] for call in sudo.calls] == [
        ["pfctl", "-a", "com.apple/250.stadiacast", "-f", "-"],
        ["pfctl", "-s", "info"],
        ["pfctl", "-E"],  # pf was off
        ["pfctl", "-a", "com.apple/250.stadiacast", "-s", "nat"],
    ]
    assert sudo.calls[0][1] == RULE + "\n"
    said = capsys.readouterr().out
    assert f"echo '{RULE}\n' | sudo pfctl -a com.apple/250.stadiacast -f -" in said and "sudo pfctl -E" in said
    assert "loaded: DNS queries from 192.168.2.0/24 go to 192.168.2.1 port 5300" in said

    already_on = Sudo()
    assert dnsredirect.main(["--apply"], sudo=already_on, run=ifconfig, platform="darwin") == 0
    assert ["pfctl", "-E"] not in [call[0] for call in already_on.calls]


def test_apply_reports_a_rule_pf_refused_or_did_not_keep(capsys) -> None:
    assert dnsredirect.main(["--apply"], sudo=Sudo(refuse=True), run=ifconfig, platform="darwin") == 1
    assert "pf refused the rule: syntax error" in capsys.readouterr().err
    assert dnsredirect.main(["--apply"], sudo=Sudo(loaded=False), run=ifconfig, platform="darwin") == 1
    assert "is not in com.apple/250.stadiacast now" in capsys.readouterr().err


def test_status_and_remove(capsys) -> None:
    assert dnsredirect.main(["--status"], sudo=Sudo(), run=ifconfig, platform="darwin") == 0
    assert "loaded and pf is on" in capsys.readouterr().out
    assert dnsredirect.main(["--status"], sudo=Sudo(enabled=False), run=ifconfig, platform="darwin") == 1
    assert "pf is off, so it does nothing" in capsys.readouterr().out
    assert dnsredirect.main(["--status"], sudo=Sudo(loaded=False), run=ifconfig, platform="darwin") == 1
    assert "no rule is loaded" in capsys.readouterr().out
    assert dnsredirect.main(["--status", "--dns-port", "5301"], sudo=Sudo(), run=ifconfig, platform="darwin") == 1
    assert "another rule is loaded, not one for port 5301" in capsys.readouterr().out
    sudo = Sudo()
    assert dnsredirect.main(["--remove"], sudo=sudo, run=ifconfig, platform="darwin") == 0
    assert sudo.calls == [(["pfctl", "-a", "com.apple/250.stadiacast", "-F", "all"], None)]


def test_root_steps_are_refused_off_a_mac_and_the_rule_is_still_shown(capsys) -> None:
    sudo = Sudo()
    assert dnsredirect.main(["--apply"], sudo=sudo, run=ifconfig, platform="linux") == 2
    assert sudo.calls == [] and "this is not a Mac" in capsys.readouterr().err
    assert dnsredirect.main([], sudo=sudo, run=ifconfig, platform="linux") == 0
    hotspot_off = MAC_IFCONFIG[: MAC_IFCONFIG.index("bridge101:")]
    assert dnsredirect.main([], sudo=sudo, run=lambda _command: hotspot_off, platform="darwin") == 2
    assert "start the hotspot first" in capsys.readouterr().err


def test_the_launchd_job_is_a_property_list_that_loads_the_rule(capsys) -> None:
    assert dnsredirect.main(["--launchd"], sudo=Sudo(), run=ifconfig, platform="darwin") == 0
    job = plistlib.loads(capsys.readouterr().out.encode())
    assert job["Label"] == "lol.stadiacast.dns-redirect" and job["RunAtLoad"] is True and job["StartInterval"] == 300
    shell, flag, script = job["ProgramArguments"]
    assert (shell, flag) == ("/bin/sh", "-c")
    assert script.startswith(f"echo '{RULE}' | /sbin/pfctl -a com.apple/250.stadiacast -f -")


def test_the_command_is_reached_through_stadiacast(capsys) -> None:
    with pytest.raises(SystemExit) as exit_:
        main(["dns-redirect", "--help"])
    assert exit_.value.code == 0 and "pf rule" in capsys.readouterr().out
