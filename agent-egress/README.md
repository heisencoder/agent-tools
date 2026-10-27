# agent-egress

Restricted network egress for coding agents (Claude Code with
`--dangerously-skip-permissions`) on the host and in libvirt VMs.

Agents reach the internet **only** through an allowlisting HTTPS proxy on the
host. Host firewall rules drop all other traffic, including DNS, and the
agent cannot change them. Every proxy decision is logged as one JSON line.

Design: [overview](../docs/design/overview.md) (rationale, threat model;
this directory is rollout phase 3) and
[implementation details](../docs/design/implementation.md#egress-proxy)
(proxy algorithm, allowlist, nftables, libvirt). Requires Ubuntu 26.04 or
later (or the Debian equivalent); see
[prerequisites](../docs/design/overview.md#prerequisites).

```
host agent (uid agent) ──► 127.0.0.1:3128 ─┐
                                           ├─► agent-egress-proxy ──► allowlisted hosts :443/:80
VM agent ──► virbr-agent ──► 192.168.123.1:3128 ─┘     (uid agent-egress)
everything else: dropped by nft tables agent_egress / agent_vmnet (logged, rate-limited)
```

## Contents

| File | Installed to | Purpose |
|---|---|---|
| `agent-egress-proxy` | `/usr/local/lib/agent-egress/` | The proxy: single-file Python, standard library only, Python ≥ 3.12 |
| `allowlist.d/*.list` | `/etc/agent-egress/profiles/` | Allowlist profiles; enabled by symlink in `/etc/agent-egress/allowlist.d/` |
| `nftables/agent-host.nft` | `/etc/agent-egress/agent-host.nft` | Restrict host processes of the `agent` UID to the proxy, OTLP port, and dev ports |
| `nftables/agent-vmnet.nft` | `/etc/agent-egress/agent-vmnet.nft` | VMs on `virbr-agent` reach only DHCP and 192.168.123.1:3128/4318; no forwarding |
| `systemd/agent-egress-nft.service` | `/etc/systemd/system/` | Loads both nft tables early in boot |
| `systemd/agent-egress-proxy.socket` | `/etc/systemd/system/` | Holds 127.0.0.1:3128 and 192.168.123.1:3128 (`FreeBind`) from boot |
| `systemd/agent-egress-proxy.service` | `/etc/systemd/system/` | Runs the proxy as `agent-egress`, hardened |
| `sysusers.d/agent-egress.conf` | `/etc/sysusers.d/` | Creates the `agent-egress` system user |
| `libvirt/agent-net.xml` | `/etc/agent-egress/libvirt/` | Isolated network `agent-net` (no forward, no DNS, static leases) |
| `libvirt/vm-interface.xml` | `/etc/agent-egress/libvirt/<vm>-interface.xml` | Per-VM `<interface>` + `<vsock>` snippet for `virsh edit` |
| `managed-settings.d/40-agent-egress.json.in` | `/etc/claude-code/managed-settings.d/40-agent-egress.json` | Proxy env for Claude Code (`@PROXY@` = 127.0.0.1 host, 192.168.123.1 VM) |
| `install-host.sh` | | Host installer |
| `vm/install-vm.sh` | | In-VM installer: `/etc/environment`, apt proxy, `/etc/gitconfig`, managed settings |
| `tests/` | | Unit, integration, installer tests; `check-nft.sh` (needs root) |

`/etc/agent-tools/envs.conf` (from the repo root's `envs.conf.example`) names
each VM environment and its IP, MAC, and vsock CID. The proxy uses it to map a
VM's source IP to its environment name; the installer uses it for DHCP leases.

## Install on the host

Run from the administrator's account (with `sudo`), in a checkout of this repo:

```bash
sudo cp envs.conf.example /etc/agent-tools/envs.conf   # optional: the installer does this if missing
sudoedit /etc/agent-tools/envs.conf                     # one line per agent VM
sudo agent-egress/install-host.sh                       # add --enable npm --enable pypi as needed
```

Options: `--enable PROFILE` (repeatable), `--dev-ports 8000-8999`,
`--mask-snapd` (otherwise asked when run from a terminal), `--no-libvirt`,
`--agent-user NAME` / `--agent-uid N`, `--dry-run`, `--root DIR` (stage into a
directory; skips every `systemctl`/`nft`/`virsh` call). The installer is
idempotent: re-run it after pulling changes or editing `envs.conf`.

What it does: creates the `agent-egress` user; installs the proxy, profiles,
nft files, units, and `40-agent-egress.json`; `nft -c` checks the rules, then
enables `agent-egress-nft.service` and `agent-egress-proxy.socket`; defines,
autostarts, and starts the libvirt network `agent-net`. It reloads the proxy
(SIGHUP) when only configuration changed, and restarts it only when the
proxy code or unit changed.

**Attach each agent VM to `agent-net` only** (with the VM shut down):

```bash
sudo cat /etc/agent-egress/libvirt/agent-vm1-interface.xml
virsh edit agent-vm1     # replace the <interface> on 'default' with the snippet
```

If `envs.conf` changes while `agent-net` is running, the installer prints
how to restart the network (`virsh net-destroy agent-net && virsh net-start
agent-net`, then reboot the VMs).

**If ufw or firewalld is enabled**, its own input rules also apply:
`sudo ufw allow in on virbr-agent to 192.168.123.1 port 3128,4318 proto tcp`.

## Install in each VM

The VM has no route out except the proxy, so copy this directory in from the
host (host → VM SSH works; VM-initiated connections other than the proxy do
not):

```bash
# on the host, from the admin account (ADMIN = the VM's admin account)
scp -r agent-egress ADMIN@192.168.123.10:
# in the VM
sudo ~/agent-egress/vm/install-vm.sh
```

It writes the proxy variables to `/etc/environment` (both cases,
`no_proxy=localhost,127.0.0.1,::1,192.168.123.1`), `/etc/apt/apt.conf.d/90agent-proxy`,
`url.https://github.com/.insteadOf git@github.com:` in `/etc/gitconfig`, and
`40-agent-egress.json` with proxy 192.168.123.1. Log in again for
`/etc/environment` to apply. To use `apt` in the VM, enable `ubuntu` on the
host first (below).

## Managing the allowlist

Patterns, one per line, `#` comments: `example.com` matches exactly;
`.example.com` matches `example.com` and every subdomain. Names are compared
after lowercasing, stripping a trailing dot, and IDNA conversion.

```bash
ls -l /etc/agent-egress/allowlist.d/                   # enabled profiles
sudo ln -s ../profiles/pypi.list /etc/agent-egress/allowlist.d/   # enable
sudo rm /etc/agent-egress/allowlist.d/pypi.list                    # disable
sudoedit /etc/agent-egress/allowlist.d/local.list      # your own additions (not overwritten)
sudo systemctl reload agent-egress-proxy               # apply (SIGHUP); also reloads envs.conf
```

Profiles in `/etc/agent-egress/profiles/` are overwritten by the installer;
put local entries in their own file in `allowlist.d/`. Bad entries (IP
literals, `*.` wildcards) are skipped with a warning in the journal.

To build a list for a new project, run the task and read the denials:

```bash
journalctl -u agent-egress-proxy -o cat --since -1h | grep '^{' | jq -c 'select(.decision=="deny") | [.env,.host,.reason]' | sort | uniq -c
```

Shipped profiles: `anthropic` and `github` (enabled by default), `npm`,
`pypi`, `ubuntu`. `npm` and `pypi` sit on shared CDNs (Cloudflare, Fastly):
the SNI check stops TLS-level fronting, but `Host`-header fronting inside TLS
remains possible. A local mirror (verdaccio, devpi) is the stronger option.

## Verification

```bash
sudo nft list table inet agent_egress        # rules + drop counter for the agent UID
sudo nft list table inet agent_vmnet
systemctl status agent-egress-proxy.socket agent-egress-proxy.service agent-egress-nft.service
virsh net-info agent-net && virsh net-dumpxml agent-net

# as agent on the host (or anywhere in a VM after install-vm.sh)
curl -sS -x http://127.0.0.1:3128 https://api.github.com/zen         # allowed
curl -sS -x http://127.0.0.1:3128 https://example.com/               # 403 not-allowlisted
curl -sS --noproxy '*' --max-time 5 https://example.com/             # fails: DNS and connect dropped by nft
openssl s_client -proxy 127.0.0.1:3128 -connect registry.npmjs.org:443 -servername example.com </dev/null  # sni-mismatch (with npm enabled)

journalctl -u agent-egress-proxy -f -o cat   # decision log (JSON lines) + plain-text startup/reload messages
journalctl -k -g 'agent-(egress|vmnet)'      # kernel drop log
```

## Decision log

One JSON line per client connection on stdout (→ journald, unit
`agent-egress-proxy.service`), written when the connection ends:

```json
{"ts":"2026-10-27T21:30:32.969Z","env":"host","client":"127.0.0.1","method":"CONNECT","host":"api.github.com","port":443,"sni":"api.github.com","addr":"140.82.112.6","decision":"allow","reason":null,"bytes_up":1918,"bytes_down":4358,"duration_ms":301}
```

- `ts` is when the connection was accepted (the journal timestamp is when it
  ended). `env` is the client's environment (`host` or the `envs.conf` name;
  `null` for unknown clients). `addr` is the pinned upstream address, or the
  offending address for `non-global-address`. Client-supplied strings are
  truncated to 256 characters.
- Non-JSON lines (startup, reload, config warnings) go to stderr in the same
  unit; consumers should skip lines that do not start with `{`.

| `reason` | `decision` | Client sees |
|---|---|---|
| `not-allowlisted`, `bad-port`, `ip-literal`, `userinfo`, `non-global-address` | deny | 403 |
| `bad-request`, `bad-host`, `request-body` | deny | 400 |
| `bad-method` | deny | 405 |
| `header-timeout` (30 s) / `header-too-large` (64 KiB) | deny | 408 / 431 |
| `too-many-connections` (64 per client) | deny | 429 |
| `resolve-failed` | deny | 502 |
| `upstream-connect-failed` | deny | 502 (HTTP), close (CONNECT) |
| `unknown-client`, `client-closed` | deny | connection closed |
| `sni-mismatch`, `sni-missing`, `ech`, `not-tls`, `client-hello-timeout` (5 s), `client-hello-too-large` (16 KiB) | deny | closed after `200` |
| `null`, `idle-timeout` (10 min), `io-error: …` | allow | tunnel/response; reason says how it ended |

## Implementation notes

The proxy's request algorithm, deny reasons, limits, and every behavior not
obvious from the overview (listener kinds, IDNA, numeric host names, plain
HTTP handling, config errors, profile layout, unit hardening) are specified
in [implementation.md](../docs/design/implementation.md#egress-proxy).

## Known gaps (from the manual checks)

Manual check on the host (2026-10-27): the proxy on an unprivileged port with
`anthropic`, `github`, `npm`, `pypi` enabled, real DNS, and the real
non-global-address check:

| Client | TLS stack | Result |
|---|---|---|
| `curl` 8.x | OpenSSL 3.5 | pass (SNI sent, no ECH) |
| `git ls-remote https://github.com/...` | libcurl | pass |
| `npm view left-pad version` (Node 24) | OpenSSL | pass |
| `pip download six` (in a venv) | OpenSSL | pass (pypi.org + files.pythonhosted.org) |
| `uv venv --seed` | rustls | pass |
| `gh api /zen` | Go crypto/tls | pass |
| `claude -p ... --model haiku` (2.1.312) | Bun/BoringSSL | pass (api.anthropic.com) |
| `openssl s_client -proxy … -connect registry.npmjs.org:443 -servername example.com` | | denied `sni-mismatch` (fronting attempt) |
| `openssl s_client … -noservername` | | denied `sni-missing` |
| allowlisted `localtest.me` (resolves to loopback) | | denied `non-global-address` |

Gaps and observations:

- **Claude Code tries `mcp-proxy.anthropic.com`** (claude.ai MCP connectors)
  even with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`: about 16 denied
  `CONNECT`s per session start, after which the session works normally. It is
  deliberately not in `anthropic.list`, since connectors (Gmail, Drive, …)
  would be a further exfiltration path.
- **Clients that send GREASE (decoy) ECH are denied `ech`.** None of the CLI
  clients above do. Browsers are expected to (Chromium-based ones, e.g. under
  Playwright or Puppeteer, send GREASE ECH by default); not tested here.
- **Plain SSH remotes** (`git@github.com:`) are rewritten to HTTPS only for
  Claude Code sessions (managed `GIT_CONFIG_*`) on the host and system-wide
  in VMs; other SSH use fails.
- **Header-based fronting** through allowlisted CDN names is not blocked
  ([overview: non-goals](../docs/design/overview.md#non-goals-and-accepted-residual-risks)).
- **Not tested here** (needs root): loading the nft rules
  (`tests/check-nft.sh` runs in CI), the systemd units, and libvirt.

## Tests

From the repository root; no root and no internet needed:

```bash
python3 -m unittest discover -s agent-egress/tests      # 68 tests
agent-egress/tests/run-all.sh       # the above + shellcheck (if installed) + nft -c (if root/sudo)
sudo agent-egress/tests/check-nft.sh   # nft -c -f on the rules exactly as install-host.sh renders them
```

(`-t .` cannot be used with `discover` here: `agent-egress` is not a valid
Python package name.)

- `test_egress_proxy.py`: normalization, IP-literal refusal, non-global
  addresses (incl. IPv4-mapped, 6to4, NAT64), allowlist matching,
  `envs.conf` parsing, ClientHello parsing (genuine ClientHellos from Python's
  `ssl`, hand-crafted mismatch/missing/ECH/duplicate/split cases), and
  in-process end-to-end CONNECT (a real TLS handshake through the proxy) and
  plain HTTP against local upstreams, per-listener client checks, limits and
  timeouts, deny logging, SIGHUP reload. Tests map names to 127.0.0.1 with an
  injected resolver and must pass `address_allowed` explicitly to permit
  loopback; the default check is tested to refuse it.
- `test_egress_cli.py`: the proxy as a real process: socket activation
  (`LISTEN_FDS`/`LISTEN_PID`), `--listen`, SIGHUP, SIGTERM, startup errors.
- `test_egress_install.py`: both installers into a `--root` staging
  directory: layout, substituted templates, JSON (`python3 -m json.tool`) and
  XML validity, idempotency, dry run, input validation; unit-file properties.

## Uninstall

```bash
sudo systemctl disable --now agent-egress-proxy.socket agent-egress-proxy.service agent-egress-nft.service
sudo nft delete table inet agent_egress; sudo nft delete table inet agent_vmnet
sudo virsh net-destroy agent-net; sudo virsh net-undefine agent-net
sudo rm -r /etc/agent-egress /usr/local/lib/agent-egress /etc/claude-code/managed-settings.d/40-agent-egress.json \
  /etc/systemd/system/agent-egress-* /etc/sysusers.d/agent-egress.conf
sudo systemctl daemon-reload
```
