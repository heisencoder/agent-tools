"""Shared helpers for the agent-logs tests (imported by the test_*.py files).

The programs under test are single files without a .py suffix, so they are
loaded with SourceFileLoader.  Temporary files go under $AGENT_LOGS_TEST_TMP
if set (else the system temp dir); Unix sockets always get a short directory
because socket paths are limited to 107 bytes.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
COMPONENT = os.path.dirname(TESTS)
REPO = os.path.dirname(COMPONENT)
FIXTURES = os.path.join(TESTS, "fixtures")
TMP_BASE = os.environ.get("AGENT_LOGS_TEST_TMP") or None
VERBOSE = bool(os.environ.get("AGENT_LOGS_TEST_VERBOSE"))

_modules = {}


def load(name):
    """Import agent-logs/<name> (e.g. "agent-log-shipper") as a module."""
    if name not in _modules:
        modname = name.replace("-", "_")
        loader = importlib.machinery.SourceFileLoader(modname, os.path.join(COMPONENT, name))
        spec = importlib.util.spec_from_loader(modname, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        if not VERBOSE:
            mod.log = lambda *a, **k: None       # keep test output readable
        _modules[name] = mod
    return _modules[name]


def program(name):
    return os.path.join(COMPONENT, name)


def tempdir(tc):
    if TMP_BASE:
        os.makedirs(TMP_BASE, exist_ok=True)
    d = tempfile.mkdtemp(prefix="agent-logs-", dir=TMP_BASE)
    tc.addCleanup(shutil.rmtree, d, True)
    return d


def sockdir(tc):
    base = TMP_BASE if TMP_BASE and len(TMP_BASE) < 60 else None
    d = tempfile.mkdtemp(prefix="al-", dir=base)
    tc.addCleanup(shutil.rmtree, d, True)
    return d


def wait_for(pred, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = pred()
        if value:
            return value
        time.sleep(interval)
    return pred()


def frame(event):
    body = json.dumps(event).encode() if not isinstance(event, bytes) else event
    return struct.pack(">I", len(body)) + body


def send_hook(path, event, timeout=5.0):
    """Act like claude-audit-hook: send one frame, return the reply bytes."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(frame(event))
        reply = b""
        while len(reply) < 2:
            chunk = s.recv(2 - len(reply))
            if not chunk:
                break
            reply += chunk
        return reply
    except socket.timeout:
        return b"<timeout>"
    finally:
        s.close()


def drain(q, n, timeout=10.0):
    """Take n items from a queue.Queue (fewer if it times out)."""
    out = []
    deadline = time.monotonic() + timeout
    while len(out) < n and time.monotonic() < deadline:
        try:
            out.append(q.get(timeout=0.1))
        except Exception:
            pass
    return out


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def python():
    return sys.executable
