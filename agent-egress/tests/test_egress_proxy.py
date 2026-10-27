"""Unit and in-process end-to-end tests for agent-egress-proxy.

No root and no internet: upstreams are local servers, and names are mapped
to 127.0.0.1 by an injected resolver.  Loopback answers pass the
non-global-address check only where a test passes `address_allowed`
explicitly; the default check is exercised separately.
"""

import asyncio
import contextlib
import io
import json
import os
import signal
import socket
import ssl
import tempfile
import unittest
from pathlib import Path

import egress_testlib as lib

ep = lib.load_proxy_module()


def deny_reason(fn, *args):
    try:
        fn(*args)
    except ep.Deny as d:
        return d.reason
    return None


# -----------------------------------------------------------------
# Pure functions
# -----------------------------------------------------------------
class TestNormalizeHost(unittest.TestCase):
    def test_canonical_forms(self):
        self.assertEqual(ep.normalize_host("Example.COM."), "example.com")
        self.assertEqual(ep.normalize_host("api.github.com"), "api.github.com")
        self.assertEqual(ep.normalize_host("BÜCHER.example"), "xn--bcher-kva.example")
        self.assertEqual(ep.normalize_host("xn--bcher-kva.example"), "xn--bcher-kva.example")
        self.assertEqual(ep.normalize_host("1.2.3.com"), "1.2.3.com")
        self.assertEqual(ep.normalize_host("_dmarc.example.com"), "_dmarc.example.com")

    def test_ip_literals_refused(self):
        for raw in ["1.2.3.4", "127.0.0.1", "127.1", "2130706433", "0x7f000001",
                    "0x7f.0.0.1", "0177.0.0.1", "1.2.3.4.", "[::1]", "::1",
                    "::ffff:127.0.0.1", "[2001:db8::1]"]:
            with self.subTest(raw=raw):
                self.assertEqual(deny_reason(ep.normalize_host, raw), "ip-literal")

    def test_bad_names_refused(self):
        for raw in ["", ".", "a..b", "exa mple.com", "a/b.com", "-a.com", "a-.com",
                    "a" * 64 + ".com", "evil.com%00", "user@host.com", "ex\x00.com",
                    ("a" * 60 + ".") * 5 + "com", "*.example.com"]:
            with self.subTest(raw=raw):
                self.assertEqual(deny_reason(ep.normalize_host, raw), "bad-host")


class TestAddresses(unittest.TestCase):
    def test_global(self):
        for addr in ["8.8.8.8", "140.82.112.3", "2606:4700::1111",
                     "::ffff:8.8.8.8", "64:ff9b::808:808"]:
            with self.subTest(addr=addr):
                self.assertTrue(ep.is_global_address(addr))

    def test_non_global(self):
        for addr in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.123.1",
                     "169.254.169.254", "100.64.0.1", "0.0.0.0", "255.255.255.255",
                     "224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12::1",
                     "2001:db8::1",
                     # IPv4-mapped
                     "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
                     # 6to4 embedding private IPv4
                     "2002:7f00:1::1", "2002:c0a8:7b01::",
                     # NAT64 embedding private IPv4
                     "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:7b01",
                     # deprecated IPv4-compatible
                     "::7f00:1",
                     "not-an-address"]:
            with self.subTest(addr=addr):
                self.assertFalse(ep.is_global_address(addr))


class TestAllowlist(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def load(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            allow = ep.Allowlist.load(self.dir)
        return allow, err.getvalue()

    def test_matching(self):
        (self.dir / "a.list").write_text(
            "# comment\n\nGitHub.com   # trailing comment\n.ubuntu.com\n"
            "bücher.example\n")
        allow, err = self.load()
        self.assertEqual(err, "")
        self.assertTrue(allow.match("github.com"))
        self.assertFalse(allow.match("api.github.com"))     # exact only
        self.assertFalse(allow.match("evilgithub.com"))
        self.assertTrue(allow.match("ubuntu.com"))          # .x matches apex
        self.assertTrue(allow.match("archive.ubuntu.com"))
        self.assertTrue(allow.match("a.b.ubuntu.com"))
        self.assertFalse(allow.match("notubuntu.com"))
        self.assertFalse(allow.match("ubuntu.com.evil.example"))
        self.assertTrue(allow.match("xn--bcher-kva.example"))

    def test_bad_entries_skipped_and_other_files_ignored(self):
        (self.dir / "a.list").write_text("1.2.3.4\n*.example.com\nok.example\n")
        (self.dir / "notes.txt").write_text("other.example\n")
        allow, err = self.load()
        self.assertEqual(allow.exact, {"ok.example"})
        self.assertEqual(allow.suffixes, set())
        self.assertIn("ip-literal", err)
        self.assertIn("bad-host", err)

    def test_symlinked_profiles_followed(self):
        profiles = self.dir / "profiles"
        enabled = self.dir / "allowlist.d"
        profiles.mkdir()
        enabled.mkdir()
        (profiles / "x.list").write_text("x.example\n")
        (enabled / "x.list").symlink_to("../profiles/x.list")
        (enabled / "broken.list").symlink_to("../profiles/missing.list")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            allow = ep.Allowlist.load(enabled)
        self.assertTrue(allow.match("x.example"))
        self.assertIn("broken.list", err.getvalue())

    def test_missing_directory_denies_everything(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            allow = ep.Allowlist.load(self.dir / "nope")
        self.assertEqual(len(allow), 0)
        self.assertIn("missing", err.getvalue())

    def test_shipped_profiles(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            allow = ep.Allowlist.load(lib.EGRESS_DIR / "allowlist.d")
        self.assertEqual(err.getvalue(), "")
        for host in ["api.anthropic.com", "claude.ai", "claude.com", "platform.claude.com",
                     "sso.claude.com", "downloads.claude.ai", "code.claude.com",
                     "github.com", "api.github.com", "codeload.github.com",
                     "objects.githubusercontent.com", "raw.githubusercontent.com",
                     "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
                     "archive.ubuntu.com", "security.ubuntu.com",
                     "us.archive.ubuntu.com"]:
            self.assertTrue(allow.match(host), host)
        self.assertFalse(allow.match("gist.github.com"))
        self.assertFalse(allow.match("statsig.anthropic.com"))


class TestEnvsConf(unittest.TestCase):
    def test_example_file(self):
        text = (lib.REPO_DIR / "envs.conf.example").read_text()
        self.assertEqual(ep.parse_envs_conf(text), {"192.168.123.10": "agent-vm1"})

    def test_format(self):
        text = ("# comment\n\n"
                "vm-a   cid=10 ip=192.168.123.10 mac=52:54:00:a9:00:10  # note\n"
                "vm-b   cid=11\n"                       # no ip: not a proxy client
                "vm-c ip=192.168.123.12\n")
        self.assertEqual(ep.parse_envs_conf(text),
                         {"192.168.123.10": "vm-a", "192.168.123.12": "vm-c"})

    def test_errors(self):
        for text in ["Bad_Name ip=192.168.123.10\n",
                     "host ip=192.168.123.10\n",
                     "a ip=192.168.123.10\na ip=192.168.123.11\n",
                     "a ip=192.168.123.10\nb ip=192.168.123.10\n",
                     "a ip=192.168.123.300\n",
                     "a ip\n",
                     "a ip=1.2.3.4 ip=1.2.3.5\n"]:
            with self.subTest(text=text):
                with self.assertRaises(ep.ConfigError):
                    ep.parse_envs_conf(text)

    def test_missing_file_means_no_vm_clients(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(ep.load_envs_conf("/nonexistent/envs.conf"), {})


class TestClientHelloParsing(unittest.TestCase):
    def body(self, records):
        """Strip record headers and the handshake header."""
        hs = b""
        while records:
            length = int.from_bytes(records[3:5], "big")
            hs += records[5:5 + length]
            records = records[5 + length:]
        return hs[4:4 + int.from_bytes(hs[1:4], "big")]

    def test_genuine_client_hello(self):
        records = lib.genuine_client_hello("allowed.test")
        self.assertEqual(records[0], 0x16)
        self.assertEqual(ep.parse_client_hello(self.body(records)), ("allowed.test", False))

    def test_genuine_client_hello_without_sni(self):
        records = lib.genuine_client_hello(None)
        self.assertEqual(ep.parse_client_hello(self.body(records)), (None, False))

    def test_crafted(self):
        self.assertEqual(ep.parse_client_hello(self.body(lib.crafted_hello("a.test"))),
                         ("a.test", False))
        self.assertEqual(ep.parse_client_hello(self.body(lib.crafted_hello("a.test", ech=True))),
                         ("a.test", True))
        self.assertEqual(ep.parse_client_hello(self.body(lib.crafted_hello(None))),
                         (None, False))
        self.assertEqual(ep.parse_client_hello(lib.client_hello_body(with_extensions=False)),
                         (None, False))

    def test_malformed(self):
        dup = lib.client_hello_body(lib.server_name_ext("a.test") + lib.server_name_ext("b.test"))
        two = lib.client_hello_body(lib.server_name_ext("a.test", "b.test"))
        other_type = lib.client_hello_body(lib.server_name_ext("a.test", name_type=1))
        good = lib.client_hello_body(lib.server_name_ext("a.test"))
        for body in [dup, two, other_type, good[:-3], good + b"\x00", b"", b"\x03\x03"]:
            with self.subTest(body=body[-8:]):
                with self.assertRaises(ValueError):
                    ep.parse_client_hello(body)


class TestReadClientHello(unittest.IsolatedAsyncioTestCase):
    async def read(self, data, eof=True, **kw):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        if eof:
            reader.feed_eof()
        return await ep.read_client_hello(reader, **kw)

    async def reason(self, data, **kw):
        try:
            await self.read(data, **kw)
        except ep.Deny as d:
            return d.reason
        return None

    async def test_single_and_split_records(self):
        whole = lib.crafted_hello("a.test")
        raw, body = await self.read(whole + b"extra")
        self.assertEqual(raw, whole)
        split = lib.crafted_hello("a.test", split_at=10)
        raw, body = await self.read(split)
        self.assertEqual(raw, split)
        self.assertEqual(ep.parse_client_hello(body), ("a.test", False))

    async def test_failures(self):
        self.assertEqual(await self.reason(b"GET / HTTP/1.1\r\n\r\n"), "not-tls")
        self.assertEqual(await self.reason(b"\x17\x03\x03\x00\x05hello"), "not-tls")
        self.assertEqual(await self.reason(b"\x16\x03\x01\x00\x04\x02\x00\x00\x00"), "not-tls")
        self.assertEqual(await self.reason(lib.crafted_hello("a.test")[:20]), "not-tls")
        self.assertEqual(await self.reason(lib.crafted_hello("a.test"), limit=20),
                         "client-hello-too-large")
        self.assertEqual(await self.reason(b"\x16\x03", eof=False, timeout=0.05),
                         "client-hello-timeout")


class TestParseHead(unittest.TestCase):
    def test_ok(self):
        head = b"GET http://a.test/x HTTP/1.1\r\nHost: a.test\r\nX-A:  b \r\n\r\n"
        self.assertEqual(ep.parse_head(head),
                         ("GET", "http://a.test/x", "HTTP/1.1", [("Host", "a.test"), ("X-A", "b")]))

    def test_bad(self):
        for head in [b"GET http://a.test/ HTTP/2\r\n\r\n",
                     b"GET  http://a.test/ HTTP/1.1\r\n\r\n",
                     b"GET http://a.test/\tx HTTP/1.1\r\n\r\n",
                     b"GET http://a.test/ HTTP/1.1\r\nX: a\nY: b\r\n\r\n",
                     b"GET http://a.test/ HTTP/1.1\r\n folded\r\n\r\n",
                     b"GET http://a.test/ HTTP/1.1\r\nBad Name: x\r\n\r\n"]:
            with self.subTest(head=head):
                self.assertEqual(deny_reason(ep.parse_head, head), "bad-request")


# -----------------------------------------------------------------
# End to end, in process
# -----------------------------------------------------------------
class ProxyTestCase(unittest.IsolatedAsyncioTestCase):
    """Starts a proxy with a host listener and a VM listener on loopback, a
    TLS echo upstream, a raw capture upstream, and an HTTP upstream."""

    proxy_kwargs = {}
    allow_loopback = True

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        (tmp / "allowlist.d").mkdir()
        (tmp / "allowlist.d" / "test.list").write_text(
            "allowed.test\n.wild.test\nplain.test\nprivate.test\nmixed.test\n"
            "unresolvable.test\n")
        (tmp / "envs.conf").write_text("vm-one cid=10 ip=127.0.0.2 mac=52:54:00:00:00:02\n")
        self.allowlist_dir, self.envs_conf = tmp / "allowlist.d", tmp / "envs.conf"
        cert, key = lib.write_cert(tmp)
        self.client_ctx = ssl.create_default_context(cafile=cert)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert, key)

        # TLS echo upstream: answers each line with "echo:<line>".
        async def tls_echo(reader, writer):
            with contextlib.suppress(Exception):
                while line := await reader.readline():
                    writer.write(b"echo:" + line)
                    await writer.drain()
            writer.close()
        self.tls_server = await asyncio.start_server(tls_echo, "127.0.0.1", 0, ssl=server_ctx)

        # Raw capture upstream: records what it receives and answers "OK".
        self.captured = []

        async def capture(reader, writer):
            data = await reader.read(65536)
            self.captured.append(data)
            writer.write(b"OK")
            await writer.drain()
            writer.close()
        self.raw_server = await asyncio.start_server(capture, "127.0.0.1", 0)

        # HTTP upstream: records the request head and returns a tiny response.
        self.http_requests = []

        async def http(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            self.http_requests.append(head)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            await writer.drain()
            writer.close()
        self.http_server = await asyncio.start_server(http, "127.0.0.1", 0)

        port = lambda s: s.sockets[0].getsockname()[1]
        self.dns = {
            "allowed.test": [("127.0.0.1", port(self.tls_server))],
            "sub.wild.test": [("127.0.0.1", port(self.raw_server))],
            "plain.test": [("127.0.0.1", port(self.http_server))],
            "private.test": [("10.0.0.1", 443)],
            "mixed.test": [("8.8.8.8", 443), ("192.168.1.1", 443)],
        }

        async def resolver(host, port_):
            if host not in self.dns:
                raise socket.gaierror(socket.EAI_NONAME, "not found")
            return self.dns[host]

        kwargs = dict(resolver=resolver, log_stream=io.StringIO())
        if self.allow_loopback:
            kwargs["address_allowed"] = (
                lambda ip: ip == "127.0.0.1" or ep.is_global_address(ip))
        kwargs.update(self.proxy_kwargs)
        self.log = kwargs["log_stream"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.proxy = ep.Proxy(self.allowlist_dir, self.envs_conf, **kwargs)
        host_sock = socket.create_server(("127.0.0.1", 0))
        vm_sock = socket.create_server(("127.0.0.1", 0))
        self.host_port = host_sock.getsockname()[1]
        self.vm_port = vm_sock.getsockname()[1]
        await self.proxy.start([(host_sock, "host"), (vm_sock, "vm")])

    async def asyncTearDown(self):
        await self.proxy.close()
        for s in (self.tls_server, self.raw_server, self.http_server):
            s.close()
        self.tmp.cleanup()

    # --- helpers ---------------------------------------------------
    async def connect(self, port=None, source="127.0.0.1"):
        return await asyncio.open_connection(
            "127.0.0.1", port or self.host_port, local_addr=(source, 0))

    async def send_head(self, head, **kw):
        reader, writer = await self.connect(**kw)
        writer.write(head)
        await writer.drain()
        return reader, writer

    async def status(self, reader):
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        return int(head.split(b" ")[1])

    async def records(self, n=1):
        """Wait for at least n decision log lines and return them parsed."""
        for _ in range(200):
            lines = self.log.getvalue().splitlines()
            if len(lines) >= n:
                return [json.loads(line) for line in lines]
            await asyncio.sleep(0.01)
        self.fail(f"expected {n} log lines, got {self.log.getvalue()!r}")

    async def deny_test(self, head, status, reason, **kw):
        reader, writer = await self.send_head(head, **kw)
        self.assertEqual(await self.status(reader), status)
        body = await reader.read()
        self.assertIn(reason.encode(), body)
        writer.close()
        rec = (await self.records())[-1]
        self.assertEqual((rec["decision"], rec["reason"]), ("deny", reason))
        return rec

    async def connect_and_hello(self, hello, host="allowed.test"):
        reader, writer = await self.send_head(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
        self.assertEqual(await self.status(reader), 200)
        writer.write(hello)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        return data


class TestConnect(ProxyTestCase):
    async def test_tls_end_to_end(self):
        reader, writer = await self.send_head(
            b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
        self.assertEqual(await self.status(reader), 200)
        await writer.start_tls(self.client_ctx, server_hostname="allowed.test")
        writer.write(b"hello\n")
        self.assertEqual(await asyncio.wait_for(reader.readline(), 5), b"echo:hello\n")
        writer.close()
        rec = (await self.records())[-1]
        self.assertEqual(rec["decision"], "allow")
        self.assertEqual(rec["env"], "host")
        self.assertEqual(rec["client"], "127.0.0.1")
        self.assertEqual(rec["method"], "CONNECT")
        self.assertEqual(rec["host"], "allowed.test")
        self.assertEqual(rec["port"], 443)
        self.assertEqual(rec["sni"], "allowed.test")
        self.assertEqual(rec["addr"], "127.0.0.1")
        self.assertGreater(rec["bytes_up"], 100)
        self.assertGreater(rec["bytes_down"], 100)
        self.assertIsInstance(rec["duration_ms"], int)
        self.assertEqual(set(rec), {"ts", "env", "client", "method", "host", "port", "sni",
                                    "addr", "decision", "reason", "bytes_up", "bytes_down",
                                    "duration_ms"})

    async def test_genuine_hello_forwarded_verbatim_to_wildcard_host(self):
        hello = lib.genuine_client_hello("sub.wild.test")
        self.assertEqual(await self.connect_and_hello(hello, "SUB.Wild.Test."), b"OK")
        self.assertEqual(self.captured, [hello])
        rec = (await self.records())[-1]
        self.assertEqual((rec["decision"], rec["host"]), ("allow", "sub.wild.test"))
        self.assertEqual(rec["bytes_up"], len(hello))
        self.assertEqual(rec["bytes_down"], 2)

    async def test_sni_normalized_before_comparison(self):
        hello = lib.crafted_hello("Sub.Wild.Test.")
        self.assertEqual(await self.connect_and_hello(hello, "sub.wild.test"), b"OK")

    async def sni_deny(self, hello, reason, host="sub.wild.test"):
        self.assertEqual(await self.connect_and_hello(hello, host), b"")
        self.assertEqual(self.captured, [], "upstream must not be contacted")
        rec = (await self.records())[-1]
        self.assertEqual((rec["decision"], rec["reason"]), ("deny", reason))
        return rec

    async def test_sni_mismatch_fronting(self):
        rec = await self.sni_deny(lib.genuine_client_hello("evil.example"), "sni-mismatch")
        self.assertEqual(rec["sni"], "evil.example")

    async def test_sni_mismatch_other_allowed_host(self):
        await self.sni_deny(lib.crafted_hello("allowed.test"), "sni-mismatch")

    async def test_sni_missing(self):
        await self.sni_deny(lib.genuine_client_hello(None), "sni-missing")

    async def test_ech(self):
        await self.sni_deny(lib.crafted_hello("sub.wild.test", ech=True), "ech")

    async def test_not_tls(self):
        await self.sni_deny(b"GET / HTTP/1.1\r\nHost: sub.wild.test\r\n\r\n", "not-tls")

    async def test_duplicate_sni_extension(self):
        body = lib.client_hello_body(lib.server_name_ext("sub.wild.test")
                                     + lib.server_name_ext("evil.example"))
        await self.sni_deny(lib.client_hello_records(body), "not-tls")

    async def test_policy_denials(self):
        await self.deny_test(b"CONNECT other.test:443 HTTP/1.1\r\n\r\n", 403, "not-allowlisted")
        await self.deny_test(b"CONNECT allowed.test:8443 HTTP/1.1\r\n\r\n", 403, "bad-port")
        await self.deny_test(b"CONNECT allowed.test:22 HTTP/1.1\r\n\r\n", 403, "bad-port")
        await self.deny_test(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", 403, "ip-literal")
        await self.deny_test(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n", 403, "ip-literal")
        await self.deny_test(b"CONNECT 2130706433:443 HTTP/1.1\r\n\r\n", 403, "ip-literal")
        await self.deny_test(b"CONNECT allowed.test HTTP/1.1\r\n\r\n", 400, "bad-request")
        await self.deny_test(b"CONNECT unresolvable.test:443 HTTP/1.1\r\n\r\n", 502,
                             "resolve-failed")

    async def test_non_global_address(self):
        rec = await self.deny_test(b"CONNECT private.test:443 HTTP/1.1\r\n\r\n", 403,
                                   "non-global-address")
        self.assertEqual(rec["addr"], "10.0.0.1")
        # One bad answer among good ones is enough to refuse.
        rec = await self.deny_test(b"CONNECT mixed.test:443 HTTP/1.1\r\n\r\n", 403,
                                   "non-global-address")
        self.assertEqual(rec["addr"], "192.168.1.1")

    async def test_methods_and_garbage(self):
        await self.deny_test(b"POST http://plain.test/ HTTP/1.1\r\n\r\n", 405, "bad-method")
        await self.deny_test(b"GET /relative HTTP/1.1\r\nHost: plain.test\r\n\r\n", 400,
                             "bad-request")
        await self.deny_test(b"\x16\x03\x01\x02\x00\r\n\r\n", 400, "bad-request")

    async def test_header_too_large(self):
        head = b"CONNECT allowed.test:443 HTTP/1.1\r\nX: " + b"a" * 70000 + b"\r\n\r\n"
        await self.deny_test(head, 431, "header-too-large")


class TestListeners(ProxyTestCase):
    async def test_vm_listener_known_client(self):
        hello = lib.genuine_client_hello("sub.wild.test")
        reader, writer = await self.send_head(b"CONNECT sub.wild.test:443 HTTP/1.1\r\n\r\n",
                                              port=self.vm_port, source="127.0.0.2")
        self.assertEqual(await self.status(reader), 200)
        writer.write(hello)
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"OK")
        writer.close()
        rec = (await self.records())[-1]
        self.assertEqual((rec["env"], rec["client"], rec["decision"]),
                         ("vm-one", "127.0.0.2", "allow"))

    async def closed_without_response(self, port, source):
        reader, writer = await self.send_head(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n",
                                              port=port, source=source)
        try:        # closing with unread input may surface as a reset
            data = await asyncio.wait_for(reader.read(), 5)
        except ConnectionResetError:
            data = b""
        self.assertEqual(data, b"")
        writer.close()
        rec = (await self.records())[-1]
        self.assertEqual((rec["env"], rec["client"], rec["reason"]),
                         (None, source, "unknown-client"))

    async def test_vm_listener_unknown_client(self):
        await self.closed_without_response(self.vm_port, "127.0.0.3")

    async def test_vm_listener_rejects_host_loopback(self):
        await self.closed_without_response(self.vm_port, "127.0.0.1")

    async def test_host_listener_rejects_other_sources(self):
        await self.closed_without_response(self.host_port, "127.0.0.2")

    async def test_sighup_reloads_allowlist_and_envs(self):
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, self.proxy.reload)
        self.addCleanup(loop.remove_signal_handler, signal.SIGHUP)
        self.assertFalse(self.proxy.allowlist.match("new.test"))
        (self.allowlist_dir / "more.list").write_text("new.test\n")
        with open(self.envs_conf, "a") as f:
            f.write("vm-two ip=127.0.0.3\n")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            os.kill(os.getpid(), signal.SIGHUP)
            for _ in range(100):
                if "reloaded" in err.getvalue():
                    break
                await asyncio.sleep(0.01)
        self.assertTrue(self.proxy.allowlist.match("new.test"))
        reader, writer = await self.send_head(b"CONNECT other.test:443 HTTP/1.1\r\n\r\n",
                                              port=self.vm_port, source="127.0.0.3")
        self.assertEqual(await self.status(reader), 403)
        writer.close()
        self.assertEqual((await self.records())[-1]["env"], "vm-two")

    async def test_reload_keeps_old_config_on_error(self):
        self.envs_conf.write_text("host ip=127.0.0.9\n")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertFalse(self.proxy.reload())
        self.assertIn("keeping previous", err.getvalue())
        self.assertEqual(self.proxy.vm_clients, {"127.0.0.2": "vm-one"})


class TestLimits(ProxyTestCase):
    proxy_kwargs = dict(max_conns_per_client=2, header_timeout=0.3,
                        client_hello_timeout=0.3, idle_timeout=0.3)

    async def test_per_client_connection_limit(self):
        idle = [await self.connect() for _ in range(2)]
        await asyncio.sleep(0.05)
        reader, writer = await self.connect()
        self.assertEqual(await self.status(reader), 429)
        writer.close()
        # A different client is not affected.
        reader2, writer2 = await self.send_head(b"CONNECT other.test:443 HTTP/1.1\r\n\r\n",
                                                port=self.vm_port, source="127.0.0.2")
        self.assertEqual(await self.status(reader2), 403)
        writer2.close()
        for _, w in idle:
            w.close()

    async def test_header_timeout(self):
        reader, writer = await self.send_head(b"CONNECT allowed.test:443 HTTP/1.1\r\n")
        self.assertEqual(await self.status(reader), 408)
        writer.close()

    async def test_client_hello_timeout(self):
        reader, writer = await self.send_head(b"CONNECT sub.wild.test:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(await self.status(reader), 200)
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        writer.close()
        self.assertEqual((await self.records())[-1]["reason"], "client-hello-timeout")

    async def test_idle_tunnel_closed(self):
        reader, writer = await self.send_head(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(await self.status(reader), 200)
        await writer.start_tls(self.client_ctx, server_hostname="allowed.test")
        writer.write(b"x\n")
        self.assertEqual(await reader.readline(), b"echo:x\n")
        # Now stay silent: the proxy closes the tunnel after idle_timeout.
        rec = (await asyncio.wait_for(self.records(), 5))[-1]
        self.assertEqual((rec["decision"], rec["reason"]), ("allow", "idle-timeout"))
        writer.close()


class TestDefaultAddressCheck(ProxyTestCase):
    """Without the test seam, a name resolving to loopback is refused."""
    allow_loopback = False

    async def test_loopback_answer_refused(self):
        rec = await self.deny_test(b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n", 403,
                                   "non-global-address")
        self.assertEqual(rec["addr"], "127.0.0.1")
        await self.deny_test(b"GET http://plain.test/ HTTP/1.1\r\n\r\n", 403,
                             "non-global-address")


class TestPlainHttp(ProxyTestCase):
    async def test_forward_rewrites_request(self):
        head = (b"GET http://Plain.Test/path?q=1#frag HTTP/1.1\r\n"
                b"Host: wrong.example\r\n"
                b"Proxy-Authorization: Basic eDp5\r\n"
                b"Proxy-Connection: keep-alive\r\n"
                b"Connection: keep-alive, X-Hop\r\n"
                b"X-Hop: 1\r\n"
                b"User-Agent: test\r\n\r\n")
        reader, writer = await self.send_head(head)
        response = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        self.assertEqual(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
        self.assertEqual(self.http_requests, [
            b"GET /path?q=1 HTTP/1.1\r\nHost: plain.test\r\nUser-Agent: test\r\n"
            b"Connection: close\r\n\r\n"])
        rec = (await self.records())[-1]
        self.assertEqual((rec["decision"], rec["method"], rec["host"], rec["port"], rec["sni"]),
                         ("allow", "GET", "plain.test", 80, None))
        self.assertEqual(rec["bytes_down"], len(response))

    async def test_head_and_empty_path(self):
        reader, writer = await self.send_head(b"HEAD http://plain.test HTTP/1.0\r\n\r\n")
        await asyncio.wait_for(reader.read(), 5)
        writer.close()
        self.assertEqual(self.http_requests,
                         [b"HEAD / HTTP/1.0\r\nHost: plain.test\r\nConnection: close\r\n\r\n"])

    async def test_denials(self):
        rec = await self.deny_test(b"GET http://user:pw@plain.test/ HTTP/1.1\r\n\r\n", 403,
                                   "userinfo")
        self.assertEqual(rec["host"], "plain.test")
        self.assertNotIn("pw", self.log.getvalue())
        await self.deny_test(b"GET http://plain.test:8080/ HTTP/1.1\r\n\r\n", 403, "bad-port")
        await self.deny_test(b"GET http://other.test/ HTTP/1.1\r\n\r\n", 403, "not-allowlisted")
        await self.deny_test(b"GET http://10.0.0.1/ HTTP/1.1\r\n\r\n", 403, "ip-literal")
        await self.deny_test(b"GET https://plain.test/ HTTP/1.1\r\n\r\n", 400, "bad-request")
        await self.deny_test(b"GET http://plain.test/ HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
                             400, "request-body")
        await self.deny_test(b"GET http://plain.test/ HTTP/1.1\r\nTransfer-Encoding: chunked"
                             b"\r\n\r\n", 400, "request-body")
        self.assertEqual(self.http_requests, [])


if __name__ == "__main__":
    unittest.main()
