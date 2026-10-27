"""Shared helpers for the agent-audit tests (standard library only)."""

import importlib.machinery
import importlib.util
import os
import shutil
import socket
import struct
import tempfile
import threading
from pathlib import Path

AUDIT_DIR = Path(__file__).resolve().parent.parent
HOOK = AUDIT_DIR / "claude-audit-hook"
AGENT_RUN = AUDIT_DIR / "agent-run"
INSTALL = AUDIT_DIR / "install.sh"
INSTALL_CLAUDE = AUDIT_DIR / "install-claude.sh"
REPO = AUDIT_DIR.parent


def load_hook():
    """Import claude-audit-hook (no .py suffix) as a module."""
    loader = importlib.machinery.SourceFileLoader("claude_audit_hook", str(HOOK))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def short_tmpdir(testcase):
    """A temporary directory with a short path.  Unix socket paths are
    limited to 107 bytes, so if $TMPDIR is long fall back to /tmp."""
    base = tempfile.gettempdir()
    if len(base) > 40 and os.access("/tmp", os.W_OK):
        base = "/tmp"
    path = tempfile.mkdtemp(prefix="aa-", dir=base)
    testcase.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path


def bind_socket(path):
    """Create a listening Unix socket at path (for -S checks)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    sock.listen(1)
    return sock


class FakeCollector:
    """Accepts one connection, reads one frame, then replies.

    reply: bytes to send (b"ok" for success), or None to close without
    replying, or "hang" to keep the connection open without replying.
    """

    def __init__(self, path, reply=b"ok"):
        self.path = path
        self.reply = reply
        self.frame = None          # (declared length, body bytes)
        self.sock = bind_socket(path)
        self.sock.settimeout(30)
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _read(self, conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            self.done.set()
            return
        with conn:
            try:
                header = self._read(conn, 4)
                if len(header) == 4:
                    (length,) = struct.unpack(">I", header)
                    self.frame = (length, self._read(conn, length))
                if self.reply == "hang":
                    self.done.wait(30)
                elif self.reply is not None:
                    conn.sendall(self.reply)
            except OSError:
                pass   # client went away (or close() woke us)
        self.done.set()

    def close(self):
        self.done.set()
        if self.thread.is_alive():
            # Wake a pending accept() so the thread can exit.
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(self.path)
            except OSError:
                pass
        self.thread.join(5)
        self.sock.close()
