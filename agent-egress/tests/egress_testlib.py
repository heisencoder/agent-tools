"""Shared helpers for the agent-egress tests.

Loads agent-egress-proxy (a script without a .py suffix) as a module, builds
TLS ClientHello messages (genuine ones from the ssl module, and hand-crafted
ones for the failure cases), and provides a self-signed certificate for
allowed.test so tests can run a real TLS handshake through the proxy.
"""

import importlib.machinery
import importlib.util
import ssl
import struct
import sys
from pathlib import Path

EGRESS_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = EGRESS_DIR.parent
PROXY_PATH = EGRESS_DIR / "agent-egress-proxy"


def load_proxy_module():
    loader = importlib.machinery.SourceFileLoader("agent_egress_proxy", str(PROXY_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # no __pycache__ beside the script
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = saved
    return module


# Self-signed EC certificate for allowed.test and sub.allowed.test, valid
# until 2126.  Test-only; the key protects nothing.
TEST_CERT = """\
-----BEGIN CERTIFICATE-----
MIIBrzCCAVagAwIBAgIUQ09kYNZneFB8TU1zmCYHeQng6OAwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMYWxsb3dlZC50ZXN0MCAXDTI2MTAyNzIxMTg1M1oYDzIxMjYx
MDAzMjExODUzWjAXMRUwEwYDVQQDDAxhbGxvd2VkLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATfUDBNYJyGCN26Wf2DjoJIohI8qGBejUoRj4LJYxC2BCu0
VtIVHEmrheA6T4K+B+gzx+ks3hprDNEXEKkcYw2ro34wfDAdBgNVHQ4EFgQUvS5E
br9YK+k/p4olsD6I6cGN2P4wHwYDVR0jBBgwFoAUvS5Ebr9YK+k/p4olsD6I6cGN
2P4wDwYDVR0TAQH/BAUwAwEB/zApBgNVHREEIjAgggxhbGxvd2VkLnRlc3SCEHN1
Yi5hbGxvd2VkLnRlc3QwCgYIKoZIzj0EAwIDRwAwRAIgbjswAZYfEv0Jb0ckYhqp
qJpTifZsduVJox0kMbdRSQQCIGabAx9wALSNqNM1O3NNdNgUHmdGigjesM6MkvPT
XMNd
-----END CERTIFICATE-----
"""
TEST_KEY = """\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqaz/xLAW1JzEdVGm
0U5cX2xR/nufiNKcnGs4b9ZObxehRANCAATfUDBNYJyGCN26Wf2DjoJIohI8qGBe
jUoRj4LJYxC2BCu0VtIVHEmrheA6T4K+B+gzx+ks3hprDNEXEKkcYw2r
-----END PRIVATE KEY-----
"""


def write_cert(directory):
    """Write the test cert and key; return (cert_path, key_path)."""
    cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
    cert.write_text(TEST_CERT)
    key.write_text(TEST_KEY)
    return str(cert), str(key)


def genuine_client_hello(server_hostname):
    """The first flight a real TLS client (Python's ssl/OpenSSL) sends."""
    ctx = ssl.create_default_context()
    if server_hostname is None:
        # A ClientHello without SNI; hostname checking needs a name.
        ctx.check_hostname = False
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_hostname)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def _vec(data, n):
    return len(data).to_bytes(n, "big") + data


def server_name_ext(*names, name_type=0):
    entries = b"".join(bytes([name_type]) + _vec(n.encode(), 2) for n in names)
    return struct.pack(">H", 0) + _vec(_vec(entries, 2), 2)


def ext(ext_type, data=b"\x00" * 8):
    return struct.pack(">H", ext_type) + _vec(data, 2)


def client_hello_body(extensions=b"", with_extensions=True):
    body = (b"\x03\x03" + b"\x11" * 32 + _vec(b"", 1)
            + _vec(b"\x13\x01\x13\x02", 2) + _vec(b"\x00", 1))
    if with_extensions:
        body += _vec(extensions, 2)
    return body


def client_hello_records(body, split_at=None):
    """Wrap a ClientHello body in a handshake header and TLS record(s);
    optionally split the handshake message across two records."""
    hs = b"\x01" + _vec(body, 3)
    parts = [hs] if split_at is None else [hs[:split_at], hs[split_at:]]
    return b"".join(b"\x16\x03\x01" + _vec(p, 2) for p in parts)


def crafted_hello(sni=None, ech=False, **kw):
    exts = b""
    if sni is not None:
        exts += server_name_ext(sni)
    if ech:
        exts += ext(0xFE0D)
    exts += ext(0x002B, b"\x02\x03\x04")     # supported_versions: TLS 1.3
    return client_hello_records(client_hello_body(exts), **kw)
