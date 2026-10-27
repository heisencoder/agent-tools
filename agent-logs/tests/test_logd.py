"""agent-logd: peer checks, framing and acks, store layout and quotas,
OTLP flattening and HTTP, socket activation, and vsock end to end."""

import http.client
import json
import os
import random
import socket
import stat
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

D = helpers.load("agent-logd")
S = helpers.load("agent-log-shipper")


def today():
    return time.strftime("%Y-%m-%d", time.gmtime())


class PeerCheckTest(unittest.TestCase):
    CIDS = {10: "agent-vm1", 1: "loop-vm"}

    def test_vsock(self):
        check = D.check_vsock_peer
        self.assertEqual(check(10, 700, self.CIDS), ("agent-vm1", None))
        self.assertEqual(check(10, 1023, self.CIDS)[0], "agent-vm1")
        self.assertIsNone(check(10, 1024, self.CIDS)[0])          # unprivileged sender
        self.assertIn("unprivileged", check(10, 40000, self.CIDS)[1])
        self.assertIsNone(check(1, 700, self.CIDS)[0])             # host loopback
        self.assertIsNone(check(2, 700, {2: "x"})[0])               # the host itself
        self.assertIsNone(check(11, 700, self.CIDS)[0])             # unknown CID
        self.assertIn("unknown", check(11, 700, self.CIDS)[1])
        # test-only relaxations
        self.assertEqual(check(1, 700, self.CIDS, allow_loopback=True)[0], "loop-vm")
        self.assertEqual(check(10, 5000, self.CIDS, allow_unprivileged=True)[0], "agent-vm1")
        self.assertIsNone(check(2, 700, {2: "x"}, allow_loopback=True)[0])

    def test_unix(self):
        self.assertEqual(D.check_unix_peer(0), ("host", None))
        self.assertIsNone(D.check_unix_peer(2000)[0])
        self.assertEqual(D.check_unix_peer(2000, allow_any_uid=True)[0], "host")

    def test_registry_reload_and_fail_closed(self):
        d = helpers.tempdir(self)
        path = os.path.join(d, "envs.conf")
        with open(path, "w") as f:
            f.write("agent-vm1 cid=10 ip=192.168.123.10\n")
        reg = D.Registry(path)
        self.assertEqual(reg.cids(), {10: "agent-vm1"})
        self.assertEqual(reg.env_for_ip("192.168.123.10"), "agent-vm1")
        self.assertEqual(reg.env_for_ip("127.0.0.1"), "host")
        self.assertEqual(reg.env_for_ip("::ffff:127.0.0.1"), "host")
        self.assertIsNone(reg.env_for_ip("192.168.123.99"))
        with open(path, "w") as f:
            f.write("BAD! cid=10\n")
        os.utime(path, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
        self.assertEqual(reg.cids(), {})

    def test_listen_fds(self):
        env = {"LISTEN_PID": "42", "LISTEN_FDS": "4", "LISTEN_FDNAMES": "vsock:unix:otlp:otlp"}
        self.assertEqual(D.listen_fds(env, 42), [(3, "vsock"), (4, "unix"), (5, "otlp"), (6, "otlp")])
        self.assertEqual(D.listen_fds(env, 43), [])
        self.assertEqual(D.listen_fds({"LISTEN_PID": "1", "LISTEN_FDS": "1"}, 1), [(3, "unknown")])


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.root = helpers.tempdir(self)

    def rec(self, n, pad=0):
        return D.normalize({"source": "hook", "source_id": f"1:{n}", "event": "Stop",
                            "data": {"pad": "x" * pad}}, "agent-vm1", D.utc_iso(time.time()))

    def test_layout_and_modes(self):
        store = D.Store(self.root)
        self.assertTrue(store.append("agent-vm1", self.rec(1)))
        store.sync()
        d = os.path.join(self.root, "agent-vm1")
        path = os.path.join(d, f"{today()}.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o2750)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        rec = helpers.read_jsonl(path)[0]
        self.assertEqual(list(rec), list(D.ENVELOPE_KEYS))
        with self.assertRaises(ValueError):
            store.append("../evil", self.rec(2))

    def test_quota_single_record_survives_restart(self):
        store = D.Store(self.root, quota=2000)
        results = [store.append("agent-vm1", self.rec(i, pad=200)) for i in range(20)]
        self.assertIn(False, results)
        store.sync()
        path = os.path.join(self.root, "agent-vm1", f"{today()}.jsonl")
        events = [r["event"] for r in helpers.read_jsonl(path)]
        self.assertEqual(events.count("quota-exceeded"), 1)
        self.assertEqual(events[-1], "quota-exceeded")
        store2 = D.Store(self.root, quota=2000)
        store2.append("agent-vm1", self.rec(99, pad=2000))
        store2.sync()
        self.assertEqual([r["event"] for r in helpers.read_jsonl(path)].count("quota-exceeded"), 1)


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.root = helpers.tempdir(self)
        self.store = D.Store(self.root)
        self.client, server = socket.socketpair()
        self.addCleanup(self.client.close)
        self.result = {}
        self.thread = threading.Thread(target=lambda: self.result.update(
            n=D.handle_ingest(server, "agent-vm1", self.store)), daemon=True)
        self.thread.start()
        self.reader = self.client.makefile("rb")

    def send(self, *lines):
        self.client.sendall(b"".join(line + b"\n" for line in lines))

    def stored(self):
        return helpers.read_jsonl(os.path.join(self.root, "agent-vm1", f"{today()}.jsonl"))

    def test_batch_ack_and_env_override(self):
        rec = {"ts": "2026-10-27T18:00:00.000Z", "env": "host", "recv_ts": "forged",
               "source": "hook", "source_id": "1:0", "event": "PreToolUse",
               "data": {"x": 1}, "extra": "dropped"}
        self.send(json.dumps(rec).encode(), b'{"batch": 7}')
        self.assertEqual(json.loads(self.reader.readline()), {"ack": 7})
        got = self.stored()[0]
        self.assertEqual(got["env"], "agent-vm1")              # never the payload's
        self.assertNotEqual(got["recv_ts"], "forged")
        self.assertNotIn("extra", got)
        self.assertEqual(got["data"], {"x": 1})

    def test_oversize_and_invalid(self):
        big = json.dumps({"source": "transcript", "source_id": "/p:1:0",
                          "data": "x" * (D.LINE_MAX + 10)}).encode()
        self.send(big, b"not json", b'{"source": "bogus"}',
                  json.dumps({"source": "meta", "source_id": "m", "event": "e"}).encode(),
                  b'{"batch": 1}')
        self.assertEqual(json.loads(self.reader.readline()), {"ack": 1})
        recs = self.stored()
        self.assertEqual([r["event"] for r in recs],
                         ["oversize", "invalid-record", "invalid-record", "e"])
        over = recs[0]["data"]
        self.assertEqual((over["source"], over["source_id"], over["length"]),
                         ("transcript", "/p:1:0", len(big)))
        import hashlib
        self.assertEqual(over["sha256"], hashlib.sha256(big).hexdigest())

    def test_partial_last_line_is_not_stored(self):
        self.client.sendall(b'{"source": "meta", "source_id": "x"')
        self.client.shutdown(socket.SHUT_WR)
        self.thread.join(5)
        self.assertEqual(self.result["n"], 0)


class DaemonUnixTest(unittest.TestCase):
    def start(self, allow_any_uid):
        root = helpers.tempdir(self)
        path = os.path.join(helpers.sockdir(self), "ingest.sock")
        sock = D.bind_unix(path)
        self.addCleanup(sock.close)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        daemon = D.Daemon(D.Store(root), D.Registry(os.path.join(root, "none")),
                          allow_any_uid=allow_any_uid)
        daemon.serve(sock, "unix")
        return root, path

    def exchange(self, path):
        s = S.connect_unix(path)
        s.settimeout(5)
        try:
            s.sendall(b'{"source":"meta","source_id":"a","event":"x"}\n{"batch":1}\n')
            return s.recv(100)
        except ConnectionResetError:           # closed with unread data: rejected
            return b""
        finally:
            s.close()

    def test_non_root_peer_rejected(self):
        root, path = self.start(allow_any_uid=False)
        if os.getuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(self.exchange(path), b"")
        self.assertFalse(os.path.exists(os.path.join(root, "host")))

    def test_test_mode_accepts(self):
        root, path = self.start(allow_any_uid=True)
        self.assertEqual(self.exchange(path), b'{"ack":1}\n')
        self.assertTrue(os.path.exists(os.path.join(root, "host", f"{today()}.jsonl")))


class OTLPTest(unittest.TestCase):
    def load(self, name):
        with open(os.path.join(helpers.FIXTURES, name)) as f:
            return json.load(f)

    def test_flatten_logs(self):
        recs = D.flatten_logs(self.load("otlp-logs.json"), "agent-vm1", "2026-10-27T00:00:00.000Z")
        self.assertEqual([r["event"] for r in recs], ["api_request", "tool_result"])
        api = recs[0]
        self.assertEqual((api["source"], api["env"], api["client_env"], api["session_id"]),
                         ("otel", "host", "agent-vm1", "sess-1111"))
        self.assertEqual(api["ts"], D.utc_iso(1793136000.123))
        self.assertEqual(api["data"]["attributes"]["input_tokens"], 1200)
        self.assertEqual(api["data"]["attributes"]["cost_usd"], 0.0123)
        self.assertEqual(api["data"]["resource"]["service.name"], "claude-code")
        tool = recs[1]["data"]["attributes"]
        self.assertEqual(tool["tool_parameters"], {"command": "ls"})
        self.assertEqual(tool["tags"], ["a", "b"])
        self.assertIs(tool["success"], True)
        again = D.flatten_logs(self.load("otlp-logs.json"), "agent-vm1", "later")
        self.assertEqual(api["source_id"], again[0]["source_id"])   # stable for dedup

    def test_flatten_metrics(self):
        recs = D.flatten_metrics(self.load("otlp-metrics.json"), "host", "2026-10-27T00:00:00.000Z")
        self.assertEqual([r["event"] for r in recs], ["token.usage", "token.usage", "cost.usage"])
        self.assertEqual([r["data"]["value"] for r in recs], [1200, 340, 0.0123])
        self.assertEqual(recs[0]["data"]["attributes"]["type"], "input")
        self.assertEqual(len({r["source_id"] for r in recs}), 3)

    def test_malformed_input_is_tolerated(self):
        self.assertEqual(D.flatten_logs({"resourceLogs": [1, {"scopeLogs": "x"}]}, "host", "t"), [])
        self.assertEqual(D.flatten_metrics([], "host", "t"), [])

    def test_http_end_to_end(self):
        root = helpers.tempdir(self)
        daemon = D.Daemon(D.Store(root), D.Registry(os.path.join(root, "none")))
        sock = D.bind_tcp("127.0.0.1:0")
        port = sock.getsockname()[1]
        daemon.serve(sock, "otlp")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        body = json.dumps(self.load("otlp-logs.json"))
        conn.request("POST", "/v1/logs", body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        resp.read()
        conn.request("POST", "/v1/traces", "{}", {"Content-Type": "application/json"})
        r2 = conn.getresponse()
        self.assertEqual(r2.status, 404)
        r2.read()
        conn.request("POST", "/v1/metrics", "{bad", {"Content-Type": "application/json"})
        r3 = conn.getresponse()
        self.assertEqual(r3.status, 400)
        conn.close()
        path = os.path.join(root, "host", f"otel-{today()}.jsonl")
        recs = helpers.read_jsonl(path)
        self.assertEqual(len(recs), 2)
        self.assertEqual({r["client_env"] for r in recs}, {"host"})
        self.assertFalse(os.path.exists(os.path.join(root, "host", f"{today()}.jsonl")))


def vsock_available():
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.close()
        return True
    except (AttributeError, OSError):
        return False


@unittest.skipUnless(vsock_available(), "AF_VSOCK not available")
class VsockEndToEndTest(unittest.TestCase):
    """Shipper connect_vsock -> agent-logd over vsock_loopback (CID 1), with
    the test-only relaxations for CID 1 and unprivileged source ports."""

    def start(self, **flags):
        root = helpers.tempdir(self)
        conf = os.path.join(root, "envs.conf")
        with open(conf, "w") as f:
            f.write("loop-vm cid=1 ip=192.168.123.77\n")
        for _ in range(20):
            port = random.randint(20000, 60000)
            try:
                sock = D.bind_vsock(port)
                break
            except OSError as e:
                last = e
        else:
            self.skipTest(f"cannot bind vsock: {last}")
        self.addCleanup(sock.close)
        D.Daemon(D.Store(root), D.Registry(conf), **flags).serve(sock, "vsock")
        return root, port

    def exchange(self, port):
        lo = random.randint(30000, 59000)
        try:
            s = S.connect_vsock(1, port, (lo, lo + 200))
        except OSError as e:
            self.skipTest(f"vsock loopback connect failed: {e}")
        s.settimeout(5)
        try:
            s.sendall(b'{"source":"meta","source_id":"v","event":"x"}\n{"batch":3}\n')
            return s.recv(100)
        except (ConnectionResetError, BrokenPipeError):
            # The daemon may close a rejected peer before we finish sending.
            return b""
        finally:
            s.close()

    def test_accepted_with_test_flags(self):
        root, port = self.start(vsock_allow_loopback=True, vsock_allow_unprivileged=True)
        self.assertEqual(self.exchange(port), b'{"ack":3}\n')
        recs = helpers.read_jsonl(os.path.join(root, "loop-vm", f"{today()}.jsonl"))
        self.assertEqual(recs[0]["env"], "loop-vm")

    def test_cid1_rejected_by_default(self):
        root, port = self.start(vsock_allow_unprivileged=True)
        self.assertEqual(self.exchange(port), b"")

    def test_unprivileged_port_rejected(self):
        root, port = self.start(vsock_allow_loopback=True)
        self.assertEqual(self.exchange(port), b"")
        self.assertFalse(os.path.exists(os.path.join(root, "loop-vm")))


if __name__ == "__main__":
    unittest.main()
