# Self-audit capture suite

Cross-platform secret-store reader for auditing **your own machine**: it tells you
what a plain unprivileged process can actually read out of your browser profiles,
and packages the result so you can inspect it. One codebase runs on Windows,
Linux and macOS.

This is a defensive/self-check tool. It ships no implant, no persistence, no
remote control, and nothing that builds one. The panel runs locally and sends
nothing anywhere unless you explicitly use `--send` against a Telegram chat you
own.

## Run it

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python jwg.py --probe        # what is reachable here, nothing captured
.venv/bin/python jwg.py --dry-run      # capture + archive locally, sends nothing
```

Dry-run leaves an archive in your temp dir; `--keep-archive PATH` copies it
somewhere stable. The zip contains `report.md`, `probe.json`, staged extension
LevelDB files, and `items/*.json` with every decrypted record.

## Audit panel (browser UI)

```bash
.venv/bin/python audit_panel.py        # http://127.0.0.1:8787
```

First sign-in creates the single operator account (username 3-32 chars, password
8+). Pick stores, run captures, browse history, download archives. Binds loopback
by default and refuses a routable bind unless you both set `PANEL_HOST` and pin
`PANEL_SECRET` — don't, this thing reads live browser stores.

## Optional: deliver to yourself

```bash
export JWG_TELEGRAM_TOKEN=<bot token from @BotFather>
export JWG_TELEGRAM_CHAT=<numeric chat/user id you control>
.venv/bin/python jwg.py --send
```

`--send` without those falls back to dry-run rather than dropping the capture.
The destination comes from env only — never a file, never a CLI flag.

## What "no elevation needed" actually means

Measured on this host, unprivileged, uid 1000:

| store | result | why |
|---|---|---|
| Firefox cookies | **704 captured** | `moz_cookies` stores values in plaintext |
| Brave cookies | **0 of 3178** | Chrome/Brave 150+ put the master key in the XDG secret portal (`Local State` has `os_crypt.portal`, no `encrypted_key`) |
| Wallet extensions | **85+ files staged** | LevelDB readable; vault blobs passphrase-wrapped inside |
| System info | complete | own-session reads |

The elevation framing was never the real constraint. Reading your own profile
files needs no privilege because you own them. Decrypting what's inside depends on
a key held by a *separate* service — DPAPI, gnome-keyring, or Firefox's PBE — and
that gate is orthogonal to admin. Root can read every byte of these databases and
still cannot unwrap the keys. So there is nothing to bypass for user-scoped data,
and no amount of privilege helps for portal/app-bound data.

Two things broke grabber-class decryption in current builds, both confirmed here
or in upstream trackers:

- **Linux:** Chrome/Brave 150+ delegate the cookie master key to the desktop secret
  portal instead of writing `encrypted_key`. Not recoverable from files.
- **Windows:** Chrome/Edge 140+ write `v20` app-bound encryption, which only the
  writing browser process can unwrap. DPAPI is not involved.

`--probe` reports which regime a host is in before capture, so an empty result
comes with its cause instead of looking like a bug.

## Verification discipline

Crypto verdicts are self-checking, never heuristic. CBC padding alone is not proof:
against Brave 155 a wrong-but-plausible key produced valid PKCS#7 on **60/60**
records while all of them decoded to high-bit garbage. Padding-pass is therefore
gated behind a printable-content check, and GCM relies on its tag. A false "locked"
is recoverable; a false "decrypted" ships garbage and looks like success.

## Layout

| file | role |
|---|---|
| `jwg.py` | CLI runner: probe -> capture -> archive (+ optional send) |
| `audit_panel.py` | single-operator web console over the same pipeline |
| `capture.py` | verified Chromium/Firefox/extension readers |
| `probe.py` | capability probe: what is reachable, what is gated, and why |
| `report.py` | item persistence, archive builder, report renderer, transport |
| `sysinfo.py` | local system fingerprint |
| `config.py` | env-only destination resolution, fail-closed |
