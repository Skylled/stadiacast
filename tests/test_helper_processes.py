"""The helper processes as the receiver runs them: one that exits is reported with what it wrote, one
stopped with the receiver is not, and a helper whose port is taken logs who holds it and exits."""

from __future__ import annotations

import asyncio
import errno
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from stadiacast import hostnet, netutil
from stadiacast import receiver as receiver_module
from stadiacast.helpers import DNS_SINK, SNTP_SERVER, helper_command
from tests.helpers import make_receiver, wait_for

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _python(code: str):
    return lambda _name, _args: [sys.executable, "-c", code]


def test_a_helper_that_exits_is_logged_with_its_last_lines(tmp_path, monkeypatch) -> None:
    exits = _python("import sys; print('UDP port 123 is taken'); sys.exit(3)")
    monkeypatch.setattr(receiver_module, "helper_command", exits)

    async def run() -> None:
        rx = make_receiver(tmp_path, sntp=True)
        await rx.start()
        try:
            await wait_for(lambda: rx.log.counts.get("helper_exited", 0) >= 1, timeout=30)
        finally:
            await rx.stop()
        record = next(r for r in rx.log.records if r["event"] == "helper_exited")
        assert (record["helper"], record["returncode"]) == ("sntp_server", 3)
        assert record["output"] == ["UDP port 123 is taken"]

    asyncio.run(run())


def test_a_helper_stopped_with_the_receiver_is_not_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(receiver_module, "helper_command", _python("import time; time.sleep(60)"))

    async def run() -> None:
        rx = make_receiver(tmp_path, sntp=True)
        await rx.start()
        await asyncio.sleep(0.2)
        await rx.stop()
        assert rx._sntp_proc is not None and rx._sntp_proc.returncode is not None
        assert rx.log.counts.get("helper_exited", 0) == 0

    asyncio.run(run())


def test_the_helpers_listen_where_the_receiver_is_told_to(tmp_path, monkeypatch) -> None:
    """``--bind`` is the helpers' address too, and ``--dns-port`` the sink's port: a receiver kept
    to one address had its helpers on every one."""
    spawned: dict[str, list[str]] = {}

    def record(name: str, args: list[str]) -> list[str]:
        spawned[name] = list(args)
        return [sys.executable, "-c", "import time; time.sleep(60)"]

    monkeypatch.setattr(receiver_module, "helper_command", record)

    async def run() -> None:
        rx = make_receiver(tmp_path, sntp=True, dns_upstream="192.0.2.1", dns_port=5300)
        await rx.start()
        try:
            status = rx.status()["helpers"]
        finally:
            await rx.stop()
        dns, sntp = spawned[DNS_SINK], spawned[SNTP_SERVER]
        assert dns[dns.index("--listen") + 1] == "127.0.0.1" and dns[dns.index("--port") + 1] == "5300"
        assert sntp[sntp.index("--listen") + 1] == "127.0.0.1"
        started = next(r for r in rx.log.records if r["event"] == "dns_sink_started")
        assert started["listen"] == "127.0.0.1:5300"
        assert status[DNS_SINK]["listen"] == "127.0.0.1:5300" and status[DNS_SINK]["running"] is True
        assert status[SNTP_SERVER]["listen"] == "127.0.0.1:123"
        assert rx.status()["helpers"][DNS_SINK]["running"] is False  # stopped with the receiver

    asyncio.run(run())


def test_the_spawned_sink_answers_on_the_address_and_port_it_was_given(tmp_path) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    name = b"\x0ccloudcast-pa\x0agoogleapis\x03com\x00"
    question = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"

    async def run() -> None:
        rx = make_receiver(tmp_path, dns_upstream="192.0.2.1", dns_port=port)
        await rx.start()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(0.2)
        try:
            answer = b""
            for _ in range(150):  # until the helper process is up
                client.sendto(question, ("127.0.0.1", port))
                try:
                    answer, _ = await asyncio.to_thread(client.recvfrom, 512)
                    break
                except (TimeoutError, ConnectionError):
                    await asyncio.sleep(0.05)
        finally:
            client.close()
            await rx.stop()
        assert answer[:2] == b"\x12\x34" and answer.endswith(bytes([127, 0, 0, 1]))  # the receiver's address

    asyncio.run(run())


def _sleeping_helpers(monkeypatch) -> None:
    sleeps = _python("import time; time.sleep(60)")
    monkeypatch.setattr(receiver_module, "helper_command", sleeps)


def _probes(monkeypatch, taken: dict[int, list[hostnet.Holder]]) -> None:
    """Have the receiver find the ports in ``taken`` in use, by the holders given (none: a
    process of another user, which lsof does not show)."""

    def probe(address: str, port: int, protocol: str) -> hostnet.PortProbe:
        if port not in taken:
            return hostnet.PortProbe(port, protocol, address)
        return hostnet.PortProbe(
            port, protocol, address, OSError(errno.EADDRINUSE, "Address already in use"), taken[port]
        )

    monkeypatch.setattr(receiver_module, "probe_port", probe)


def test_on_a_mac_whose_port_53_is_the_systems_the_sink_moves_and_says_what_to_run(tmp_path, monkeypatch) -> None:
    spawned: dict[str, list[str]] = {}

    def record(name: str, args: list[str]) -> list[str]:
        spawned[name] = list(args)
        return [sys.executable, "-c", "import time; time.sleep(60)"]

    monkeypatch.setattr(receiver_module, "helper_command", record)
    monkeypatch.setattr(sys, "platform", "darwin")
    _probes(monkeypatch, {53: []})
    fix = "stadiacast dns-redirect --apply --advertise-ip 127.0.0.1 --dns-port 5300"

    async def run() -> None:
        rx = make_receiver(tmp_path, dns_upstream="192.0.2.1")  # --dns-port auto
        await rx.start()
        try:
            sink = rx.status()["helpers"][DNS_SINK]
        finally:
            await rx.stop()
        dns = spawned[DNS_SINK]
        assert dns[dns.index("--port") + 1] == "5300"
        assert sink["listen"] == "127.0.0.1:5300"
        assert sink["redirect"]["command"] == fix and sink["redirect"]["from_port"] == 53
        moved = next(r for r in rx.log.records if r["event"] == "dns_sink_moved")
        assert moved["to_port"] == 5300 and "mDNSResponder" in moved["holder"]
        assert (
            len(rx.notices) == 1 and fix in rx.notices[0] and "reaches Google and never this receiver" in rx.notices[0]
        )

    asyncio.run(run())


def test_the_start_prints_the_notice_under_the_ready_line(tmp_path, monkeypatch, capsys) -> None:
    from stadiacast import cli
    from tests.test_cli import lab_config

    _sleeping_helpers(monkeypatch)
    monkeypatch.setattr(sys, "platform", "darwin")
    _probes(monkeypatch, {53: []})

    async def run() -> str:
        task = asyncio.get_running_loop().create_task(cli.amain(lab_config(tmp_path, dns_upstream="192.0.2.1")))
        out = ""
        for _ in range(500):
            out += capsys.readouterr().out
            if "wake the controller(s) now" in out:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return out

    said = asyncio.run(run())
    assert "DNS: port 53 of this Mac is held by mDNSResponder, most likely" in said
    assert "stadiacast dns-redirect --apply --advertise-ip 127.0.0.1 --dns-port 5300" in said
    assert said.index("ready:") < said.index("DNS: port 53") < said.index("wake the controller(s) now")


@pytest.mark.parametrize(
    ("platform", "dns_port", "holders", "says"),
    [
        # a holder this user can see is a leftover to stop, on a Mac too: the sink does not move
        ("darwin", 0, [hostnet.Holder("python3.14", 4242, "kyle", "*:53")], "held by python3.14 (pid 4242, user kyle)"),
        ("darwin", 53, [], "held by mDNSResponder, most likely"),  # port 53 was asked for by name
        ("linux", 0, [], "often systemd-resolved or dnsmasq"),
    ],
)
def test_a_dns_port_that_is_taken_ends_the_start_with_its_holder(
    tmp_path, monkeypatch, platform, dns_port, holders, says
) -> None:
    """The sink used to exit beside a receiver that went on, and the controller was sent to Google."""
    _sleeping_helpers(monkeypatch)
    monkeypatch.setattr(sys, "platform", platform)
    _probes(monkeypatch, {53: holders})

    async def run() -> None:
        rx = make_receiver(tmp_path, dns_upstream="192.0.2.1", dns_port=dns_port)
        try:
            with pytest.raises(OSError, match=r"the DNS sink cannot listen on 127\.0\.0\.1:53 \(udp\)") as refused:
                await rx.start()
            assert says in str(refused.value)
            assert rx._dns_proc is None
        finally:
            await rx.stop()

    asyncio.run(run())


def test_a_fallback_port_that_is_taken_too_ends_the_start(tmp_path, monkeypatch) -> None:
    _sleeping_helpers(monkeypatch)
    monkeypatch.setattr(sys, "platform", "darwin")
    _probes(monkeypatch, {53: [], 5300: [hostnet.Holder("python3.14", 7, "kyle", "*:5300")]})

    async def run() -> None:
        rx = make_receiver(tmp_path, dns_upstream="192.0.2.1")
        try:
            with pytest.raises(OSError, match=r"cannot listen on 127\.0\.0\.1:5300 .*held by python3\.14 \(pid 7"):
                await rx.start()
        finally:
            await rx.stop()

    asyncio.run(run())


def test_a_low_port_on_one_address_of_a_mac_says_what_macos_allows(monkeypatch) -> None:
    refused = PermissionError(13, "Permission denied")
    monkeypatch.setattr(sys, "platform", "darwin")
    hint = netutil.bind_hint(53, "DNS", refused, "192.168.2.1")
    assert "on all addresses only" in hint and "--bind 0.0.0.0" in hint
    assert "needs root or CAP_NET_BIND_SERVICE" in netutil.bind_hint(53, "DNS", refused, "0.0.0.0")
    monkeypatch.setattr(sys, "platform", "linux")
    assert "needs root or CAP_NET_BIND_SERVICE" in netutil.bind_hint(53, "DNS", refused, "192.168.2.1")


@pytest.mark.parametrize("name", [SNTP_SERVER, DNS_SINK])
def test_a_helper_whose_port_is_taken_says_so_and_exits(tmp_path, name) -> None:
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if sys.platform == "win32":  # Windows lets a second socket share a port unless the first forbids it
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    log = tmp_path / "helper.jsonl"
    args = ["--listen", "127.0.0.1", "--port", str(port), "--log", str(log)]
    if name == DNS_SINK:
        args += ["--redirect-ip", "127.0.0.1"]
    try:
        run = subprocess.run(
            helper_command(name, args),
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": SRC},
            timeout=60,
            check=False,
        )
    finally:
        holder.close()
    assert run.returncode == 1, run.stdout + run.stderr
    assert f"bind_failed listen=127.0.0.1:{port} error=" in run.stdout and f"port {port} is taken" in run.stdout
    assert '"event": "bind_failed"' in log.read_text()


def test_the_sntp_server_answers_a_client_and_nothing_else(tmp_path) -> None:
    """A packet in server mode is another server's reply: answering it would start an exchange
    between the two that never ends."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    log = tmp_path / "sntp.jsonl"
    args = ["--listen", "127.0.0.1", "--port", str(port), "--log", str(log)]
    server = subprocess.Popen(
        helper_command(SNTP_SERVER, args), stdout=subprocess.DEVNULL, env={**os.environ, "PYTHONPATH": SRC}
    )
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(0.5)
    try:
        for _ in range(100):
            if log.exists() and '"start"' in log.read_text():
                break
            time.sleep(0.05)
        request = bytes([(4 << 3) | 3]) + bytes(47)  # version 4, mode 3: a client
        client.sendto(bytes([(4 << 3) | 4]) + bytes(47), ("127.0.0.1", port))  # mode 4: a server's reply
        with pytest.raises(TimeoutError):
            client.recvfrom(512)
        client.sendto(request, ("127.0.0.1", port))
        reply, _ = client.recvfrom(512)
        assert len(reply) == 48 and reply[0] & 7 == 4
        for _ in range(100):  # the record follows the reply
            if '"request"' in log.read_text():
                break
            time.sleep(0.05)
    finally:
        client.close()
        server.terminate()
        server.wait(10)
    events = [json.loads(line)["event"] for line in log.read_text().splitlines()]
    assert events == ["start", "not_a_request", "request"]
