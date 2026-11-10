#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
End-to-end test of the qmeventd event layer. Test only, not shipped.

Runs the real qmeventd binary in the foreground against
  - a fake QEMU process speaking QMP on the qmeventd socket,
  - a fake guest agent on <rundir>/<vmid>.qga,
  - a stub `qm` that records its arguments,
and checks the events seen by a socket subscriber, the `qm event` dispatch
and the status query.

usage: test-qmeventd-events.py <path-to-qmeventd>
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

QMEVENTD = os.path.abspath(sys.argv[1])
TMP = os.environ.get("QMEV_TEST_TMP") or tempfile.mkdtemp(prefix="qmev-test-")
os.environ["QMEV_TEST_TMP"] = TMP
SOCK = os.path.join(TMP, "qmeventd.sock")
RUNDIR = os.path.join(TMP, "run")
QM_LOG = os.path.join(TMP, "qm.log")
VMID = "100"
os.makedirs(RUNDIR, exist_ok=True)

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("FAIL:", msg)


# --- stub qm ------------------------------------------------------------------
QM = os.path.join(TMP, "qm")
if not os.path.exists(QM):
    with open(QM, "w") as f:
        # event runs take a while, so overlapping runs would interleave
        f.write('#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n'
                '[ "$1" = event ] && sleep 0.3\nexit 0\n' % QM_LOG)
    os.chmod(QM, 0o755)


def qm_calls():
    try:
        with open(QM_LOG) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


# --- fake guest agent -----------------------------------------------------------
class FakeAgent(threading.Thread):
    def __init__(self, path):
        super().__init__(daemon=True)
        self.hang = False
        self.ids = []
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(1)

    def run(self):
        while True:
            conn, _ = self.srv.accept()
            data = b""
            conn.settimeout(5)
            try:
                while data.count(b"\n") < 2:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if self.hang:
                    time.sleep(3)  # longer than the probe timeout
                else:
                    lines = data.decode().splitlines()
                    sync = json.loads(lines[0])
                    # fixed id, see probe_start() in qmeventd.c
                    self.ids.append(sync["arguments"]["id"])
                    conn.sendall(
                        b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode()
                        + b"\n" + b'{"return": {}}\n'
                    )
            except OSError:
                pass
            conn.close()


# --- fake QEMU (re-executed with -pidfile so qmeventd finds the vmid) -----------
def fake_qemu_main():
    io_counter = {"ops": 1000}
    status = {"run": "running"}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(json.dumps({"QMP": {"version": {}, "capabilities": []}}).encode() + b"\n")
    ctl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    ctl_path = os.path.join(TMP, "qemu-ctl")
    ctl.bind(ctl_path)
    ctl.setblocking(False)
    s.setblocking(False)
    buf = b""
    while True:
        # commands from the test: emit events, bump io, quit
        try:
            cmd = json.loads(ctl.recv(4096))
            if cmd.get("event"):
                ev = {"event": cmd["event"], "data": cmd.get("data", {}),
                      "timestamp": {"seconds": int(time.time()), "microseconds": 0}}
                s.sendall(json.dumps(ev).encode() + b"\n")
                if cmd["event"] == "SHUTDOWN":
                    status["run"] = "shutdown"
            if cmd.get("io"):
                io_counter["ops"] += cmd["io"]
            if cmd.get("quit"):
                s.close()
                return
        except BlockingIOError:
            pass
        try:
            chunk = s.recv(65536)
            if not chunk:
                return
            buf += chunk
        except BlockingIOError:
            time.sleep(0.02)
            continue
        dec = json.JSONDecoder()
        text = buf.decode()
        while text.strip():
            text = text.lstrip()
            try:
                req, end = dec.raw_decode(text)
            except ValueError:
                break
            text = text[end:]
            ex = req.get("execute")
            ret = {}
            if ex == "query-status":
                ret = {"status": status["run"], "running": status["run"] == "running"}
            elif ex == "query-chardev":
                ret = [{"label": "qga0", "filename": "disconnected:unix:x,server=on",
                        "frontend-open": True}]
            elif ex == "query-blockstats":
                # many disks with all their stats: well above 4 KiB, like real VMs
                pad = {"stat%d" % i: 0 for i in range(40)}
                ret = [{"device": "drive-scsi%d" % d,
                        "stats": dict(pad, rd_operations=io_counter["ops"] if d == 0 else 0,
                                      wr_operations=0, flush_operations=0),
                        "parent": {"stats": dict(pad)}}
                       for d in range(8)]
            elif ex == "quit":
                s.close()
                return
            reply = {"return": ret}
            if "id" in req:
                reply["id"] = req["id"]
            s.sendall(json.dumps(reply).encode() + b"\n")
        buf = text.encode()


if len(sys.argv) > 2 and sys.argv[2] == "-pidfile":
    fake_qemu_main()
    sys.exit(0)


def qemu_ctl(**kw):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.sendto(json.dumps(kw).encode(), os.path.join(TMP, "qemu-ctl"))
    c.close()


# --- subscriber / control -------------------------------------------------------
class Subscriber(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.events = []
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(SOCK)
        self.s.sendall(b'{"subscribe": {}}\n')

    def run(self):
        buf = b""
        while True:
            chunk = self.s.recv(65536)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                msg = json.loads(line)
                if "event" in msg:
                    self.events.append(msg)

    def names(self):
        return [e["event"] for e in self.events]

    def wait_for(self, name, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            for e in self.events:
                if e["event"] == name:
                    return e
            time.sleep(0.1)
        check(False, "event %s not seen (got %s)" % (name, self.names()))
        return None


def control(req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(json.dumps(req).encode() + b"\n")
    f = s.makefile()
    line = f.readline()
    s.close()
    return json.loads(line)


def main():
    daemon = subprocess.Popen([QMEVENTD, "-f", "-q", QM, "-r", RUNDIR, SOCK],
                              stdout=open(os.path.join(TMP, "qmeventd.out"), "w"),
                              stderr=subprocess.STDOUT)
    for _ in range(50):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)

    agent = FakeAgent(os.path.join(RUNDIR, VMID + ".qga"))
    agent.start()
    sub = Subscriber()
    sub.start()
    time.sleep(0.2)

    qemu = subprocess.Popen([sys.executable, __file__, QMEVENTD, "-pidfile",
                             "/var/run/qemu-server/%s.pid" % VMID])

    started = sub.wait_for("STARTED")
    check(started and started["vmid"] == VMID, "STARTED for vmid 100")
    check(started and started["data"]["reconnect"] is False, "STARTED is no reconnect")
    time.sleep(0.5)
    check("event 100 STARTED" in " ".join(qm_calls()), "STARTED dispatched to qm event")

    # what `qm event STARTED` would do
    r = control({"configure": {"vmid": VMID, "dispatch": True,
                               "heartbeat": {"enabled": 1, "interval": 2, "timeout": 1,
                                             "failures": 2, "boot-timeout": 30,
                                             "hang-timeout": 6}}})
    check(r.get("return") == {}, "configure accepted: %s" % r)
    check(control({"configure": {"vmid": "999"}}).get("error"), "configure unknown VM fails")

    sub.wait_for("AGENT_UP")
    st = control({"query": "status"})
    check(st["vms"][VMID]["heartbeat"] == "ok", "status ok: %s" % st)

    # hang: agent silent and no disk I/O for hang-timeout (big blockstats replies)
    agent.hang = True
    sub.wait_for("AGENT_LOST", timeout=20)
    check("GUEST_HANG" not in sub.names(), "no hang before hang-timeout")
    sub.wait_for("GUEST_HANG", timeout=30)
    check(control({"query": "status"})["vms"][VMID]["heartbeat"] == "hang", "status hang")
    agent.hang = False
    sub.wait_for("AGENT_RECOVERED", timeout=20)
    check(set(agent.ids) == {1}, "probe always uses id 1: %s" % set(agent.ids))

    # injected operation event: broadcast, not dispatched
    r = control({"inject": {"vmid": VMID, "event": "PRE_SNAPSHOT", "data": {"snapname": "s1"}}})
    check(r.get("return") == {}, "inject accepted")
    ev = sub.wait_for("PRE_SNAPSHOT")
    check(ev and ev["source"] == "api" and ev["data"]["snapname"] == "s1", "inject payload")
    check(ev and ev["state"]["operation"] == "SNAPSHOT", "operation window in state")
    check(control({"inject": {"vmid": VMID, "event": "GUEST_PANICKED"}}).get("error"),
          "QMP events cannot be injected")
    check(control({"inject": {"vmid": "../1", "event": "PRE_SNAPSHOT"}}).get("error"),
          "invalid vmid rejected")
    control({"inject": {"vmid": VMID, "event": "POST_SNAPSHOT"}})
    time.sleep(0.5)
    check(not any("SNAPSHOT" in c.split()[2] for c in qm_calls() if c.startswith("event")),
          "injected events are not dispatched")

    # crash
    qemu_ctl(event="GUEST_PANICKED", data={"action": "run", "info": {"type": "hyper-v", "arg1": 30}})
    crash = sub.wait_for("GUEST_CRASH")
    check(crash and crash["source"] == "derived", "GUEST_CRASH is derived")
    check(crash and crash["data"]["qmp"]["info"]["arg1"] == 30, "crash carries bugcheck info")
    check(control({"query": "status"})["vms"][VMID]["heartbeat"] == "crashed", "status crashed")
    time.sleep(0.5)
    calls = " ".join(qm_calls())
    check("event 100 GUEST_PANICKED" in calls and "event 100 GUEST_CRASH" in calls,
          "crash dispatched: %s" % calls)

    # event storm: rate limited, summarized
    for _ in range(300):
        qemu_ctl(event="BLOCK_IO_ERROR", data={"device": "drive-scsi0", "operation": "read",
                                                "action": "report"})
    time.sleep(2)

    # shutdown -> EXITED + qm cleanup
    qemu_ctl(event="SHUTDOWN", data={"guest": True, "reason": "guest-shutdown"})
    sub.wait_for("SHUTDOWN")
    qemu.wait(timeout=10)
    sub.wait_for("EXITED")
    time.sleep(0.5)
    calls = qm_calls()
    check(any(c.startswith("cleanup 100 1 1") for c in calls), "qm cleanup still runs: %s" % calls)
    # queued behind the storm's runs (each stub run takes 0.3s), in order
    end = time.time() + 30
    while time.time() < end and not any(c.startswith("event 100 EXITED") for c in qm_calls()):
        time.sleep(0.2)
    check(any(c.startswith("event 100 EXITED") for c in qm_calls()), "EXITED dispatched")

    seqs = [e["seq"] for e in sub.events]
    check(seqs == sorted(seqs), "event sequence numbers increase")

    # `qm event` runs of one VM happen one at a time, in event order
    time.sleep(1)
    run_seqs = [json.loads(c.split(" ", 3)[3])["seq"] for c in qm_calls() if c.startswith("event")]
    check(run_seqs == sorted(run_seqs), "qm event runs in event order: %s" % run_seqs)

    daemon.terminate()
    daemon.wait()
    with open(os.path.join(TMP, "qmeventd.out")) as f:
        out = f.read()
    check("event=GUEST_CRASH" in out, "journal record for GUEST_CRASH")
    io_errors = out.count("event=BLOCK_IO_ERROR")
    check(50 <= io_errors <= 110, "BLOCK_IO_ERROR storm limited in journal: %d" % io_errors)
    check("event=EVENTS_SUPPRESSED" in out, "storm summary in journal")
    check("EVENTS_SUPPRESSED" in sub.names(), "storm summary for subscribers")

    if failures:
        print("%d failure(s), daemon output:\n%s" % (len(failures), out))
        sys.exit(1)
    print("test-qmeventd-events: all checks passed")


main()
