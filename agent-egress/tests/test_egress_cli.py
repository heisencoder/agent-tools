"""Run agent-egress-proxy as a real process: systemd socket activation
(LISTEN_FDS / LISTEN_PID), --listen, SIGHUP, SIGTERM, and the JSON decision
log on stdout.  Only deny paths are exercised, so no DNS or internet is
needed."""

import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import egress_testlib as lib

ep = lib.load_proxy_module()

# Puts the inherited listening socket on fd 3, sets LISTEN_PID to its own PID
# (which exec keeps), and execs the proxy — what systemd does.
ACTIVATE = """\
import os, sys
fds = [int(x) for x in sys.argv[1].split(",")]
for i, fd in enumerate(fds):
    os.dup2(fd, 3 + i)
os.environ["LISTEN_FDS"] = str(len(fds))
os.environ["LISTEN_PID"] = sys.argv[2] or str(os.getpid())
os.execv(sys.executable, [sys.executable, "-I"] + sys.argv[3:])
"""


class ProxyProcess:
    def __init__(self, args, pass_fds=(), activate=None, listen_pid=""):
        cmd = [sys.executable, "-I", str(lib.PROXY_PATH), *args]
        if activate is not None:
            cmd = [sys.executable, "-c", ACTIVATE, ",".join(map(str, activate)),
                   listen_pid, str(lib.PROXY_PATH), *args]
        self.proc = subprocess.Popen(cmd, pass_fds=pass_fds, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)

    def read_line(self, stream, contains, timeout=10):
        """Read lines from stdout/stderr until one contains `contains`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([stream], [], [], deadline - time.monotonic())
            if not ready:
                break
            line = stream.readline()
            if not line:
                break
            if contains in line:
                return line
        raise AssertionError(f"no line containing {contains!r}")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return self.proc.returncode


def request(port, head, source="127.0.0.1"):
    """Send a request head and return everything the proxy answers."""
    with socket.create_connection(("127.0.0.1", port), timeout=10,
                                  source_address=(source, 0)) as s:
        s.sendall(head)
        chunks = []
        try:
            while chunk := s.recv(65536):
                chunks.append(chunk)
        except ConnectionResetError:
            pass
        return b"".join(chunks)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.allow = tmp / "allowlist.d"
        self.allow.mkdir()
        (self.allow / "a.list").write_text("allowed.test\n")
        self.envs = tmp / "envs.conf"
        self.envs.write_text("vm-one ip=127.0.0.2\n")
        self.args = ["--allowlist-dir", str(self.allow), "--envs-conf", str(self.envs)]

    def tearDown(self):
        self.tmp.cleanup()

    def test_socket_activation(self):
        sock = socket.create_server(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        p = ProxyProcess(self.args, pass_fds=(sock.fileno(),), activate=[sock.fileno()])
        sock.close()        # the proxy holds its own copy
        try:
            p.read_line(p.proc.stderr, "listening on 127.0.0.1")
            response = request(port, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
            rec = json.loads(p.read_line(p.proc.stdout, "{"))
            self.assertEqual((rec["env"], rec["decision"], rec["reason"]),
                             ("host", "deny", "ip-literal"))
        finally:
            self.assertEqual(p.stop(), 0)

    def test_wrong_listen_pid_ignored(self):
        sock = socket.create_server(("127.0.0.1", 0))
        p = ProxyProcess(self.args, pass_fds=(sock.fileno(),), activate=[sock.fileno()],
                         listen_pid="1")
        sock.close()
        self.assertEqual(p.proc.wait(10), 2)
        self.assertIn("no listening sockets", p.proc.stderr.read())
        p.stop()

    def test_listener_kind_from_address(self):
        loop = socket.create_server(("127.0.0.1", 0))
        anyaddr = socket.create_server(("0.0.0.0", 0))
        try:
            self.assertEqual(ep.listener_kind(loop), "host")
            self.assertEqual(ep.listener_kind(anyaddr), "vm")
        finally:
            loop.close()
            anyaddr.close()

    def test_systemd_env_parsing(self):
        env = {"LISTEN_PID": str(os.getpid() + 1), "LISTEN_FDS": "1"}
        self.assertEqual(ep.sockets_from_systemd(env), [])
        self.assertEqual(env, {})       # variables are always consumed
        self.assertEqual(ep.sockets_from_systemd({"LISTEN_PID": "x"}), [])

    def test_listen_flag_and_sighup(self):
        p = ProxyProcess(self.args + ["--listen", "127.0.0.1:0=vm"])
        try:
            line = p.read_line(p.proc.stderr, "listening on")
            port = int(line.split("listening on 127.0.0.1:")[1].split()[0])
            self.assertIn("(vm)", line)
            head = b"CONNECT other.test:443 HTTP/1.1\r\n\r\n"

            # Unknown VM client: closed without a response.
            self.assertEqual(request(port, head, source="127.0.0.3"), b"")
            rec = json.loads(p.read_line(p.proc.stdout, "{"))
            self.assertEqual((rec["client"], rec["reason"]), ("127.0.0.3", "unknown-client"))

            # Register it, reload with SIGHUP: now it gets a policy answer.
            with open(self.envs, "a") as f:
                f.write("vm-two ip=127.0.0.3\n")
            p.proc.send_signal(signal.SIGHUP)
            p.read_line(p.proc.stderr, "reloaded")
            response = request(port, head, source="127.0.0.3")
            self.assertTrue(response.startswith(b"HTTP/1.1 403 "), response)
            rec = json.loads(p.read_line(p.proc.stdout, "{"))
            self.assertEqual((rec["env"], rec["reason"]), ("vm-two", "not-allowlisted"))
        finally:
            self.assertEqual(p.stop(), 0)

    def test_bad_envs_conf_fails_startup(self):
        self.envs.write_text("host ip=127.0.0.2\n")
        p = ProxyProcess(self.args + ["--listen", "127.0.0.1:0"])
        self.assertEqual(p.proc.wait(10), 1)
        self.assertIn("reserved", p.proc.stderr.read())
        p.stop()


if __name__ == "__main__":
    unittest.main()
