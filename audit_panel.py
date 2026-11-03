"""Self-audit web panel - run your own capture against your own machine.

Single-user. The operator is the only account; there is no multi-victim builder,
no per-user workspaces, and nothing here produces a remote implant. It exists so
you can:

  1. log in on localhost,
  2. probe what this box can actually read (python jwg.py --probe equivalent),
  3. run the capture against THIS machine,
  4. browse past runs and download their archives to inspect locally.

Why it is built this way (all deliberate):

  * Password hashed with PBKDF2-HMAC-SHA256 + salt, never plaintext. Session
    signing secret is random per start unless you pin PANEL_SECRET, so cookies
    die on restart by default.
  * First login bootstraps the one account from PANEL_USER/PANEL_PASS (or a
    generated password printed at startup). No seeded credentials.
  * Captures run in a background queue (one worker thread), not inside the
    request, because profile reads + archive build take seconds and would hang
    the HTTP connection.
  * Run artifacts live under panel_data/runs/. Downloads check the run id only;
    everything on disk here belongs to this machine's owner.

Bind stays loopback unless you pass an explicit host AND set PANEL_SECRET; a
routable bind without a pinned secret is refused. Don't expose this anyway - it
reads real browser stores on whatever box it runs on.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field, asdict
from functools import wraps

try:
    from flask import (Flask, Response, abort, jsonify, redirect,
                       render_template_string, request, send_file, session, url_for)
except ImportError:
    Flask = None

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "panel_data")
DB_FILE = os.path.join(DATA_DIR, "db.json")
RUNS_DIR = os.path.join(DATA_DIR, "runs")

# Which collectors the audit runs. Keys match the CLI --only toggles exactly, so
# the same selection works whether you click in the panel or script jwg.py.
CAPTURE_OPTIONS = {
    "system_info":   "System Info",
    "cookies":       "Browser Cookies",
    "passwords":     "Saved Passwords",
    "history":       "Browsing History",
    "autofill":      "Autofill / Cards",
    "extensions":    "Extension Stores (raw)",
    "product_keys":  "Product Keys",
    "software_list": "Installed Software",
}

# One-line description per store, shown under each checkbox in the panel.
OPTION_HELP = {
    "system_info":   "Host, user, OS, RAM/GPU/screen, machine id",
    "cookies":       "Chromium + Firefox cookie jars from your profiles",
    "passwords":     "Saved logins (decrypted only if your session key is unlocked)",
    "history":       "Visited URLs from Chromium History / Firefox places",
    "autofill":      "Web Data autofill entries and saved cards",
    "extensions":    "Wallet-extension LevelDB, staged raw (not decrypted)",
    "product_keys":  "Windows user-scoped registration blobs (DPAPI)",
    "software_list": "Installed apps/packages enumerated on this host",
}


# ------------------------------------------------------------------ password hashing
def hash_password(pw: str, salt: bytes | None = None) -> tuple[str, str]:
    """PBKDF2-HMAC-SHA256, 210k iters. Returns (hex_hash, hex_salt)."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 210_000)
    return dk.hex(), salt.hex()


def verify_password(pw: str, stored_hash: str, salt_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 210_000)
    return hmac.compare_digest(dk.hex(), stored_hash)


# ------------------------------------------------------------------ store
@dataclass
class Operator:
    id: str
    username: str
    pw_hash: str
    pw_salt: str
    created: float = field(default_factory=time.time)


@dataclass
class Run:
    id: str
    status: str            # queued | running | done | failed
    created: float
    label: str = ""
    error: str | None = None
    artifact: str | None = None
    counts: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)


class Store:
    """JSON-file store guarded by a process lock. Small scale by design."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self._db: dict = {"operator": None, "runs": {}}
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.path):
            try:
                self._db = json.load(open(self.path, encoding="utf-8"))
            except Exception:
                pass
        self._db.setdefault("operator", None)
        self._db.setdefault("runs", {})

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        json.dump(self._db, open(tmp, "w", encoding="utf-8"), indent=2)
        os.replace(tmp, self.path)

    # ---- operator ----
    def get_operator(self) -> dict | None:
        return self._db.get("operator")

    def set_operator(self, username: str, password: str) -> dict:
        with self.lock:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username.strip()):
                raise ValueError("username: 3-32 chars, letters/digits/._- only")
            if len(password) < 8:
                raise ValueError("password must be >= 8 characters")
            h, s = hash_password(password)
            op = asdict(Operator(id=secrets.token_hex(8), username=username.strip(),
                                 pw_hash=h, pw_salt=s))
            self._db["operator"] = op
            self._save()
            return op

    # ---- runs ----
    def add_run(self, run: dict) -> None:
        with self.lock:
            self._db["runs"][run["id"]] = run
            self._save()

    def update_run(self, rid: str, **kw) -> None:
        with self.lock:
            r = self._db["runs"].get(rid)
            if r:
                r.update(kw)
                self._save()

    def list_runs(self) -> list[dict]:
        return sorted(self._db["runs"].values(), key=lambda r: r.get("created", 0), reverse=True)

    def get_run(self, rid: str) -> dict | None:
        return self._db["runs"].get(rid)


os.makedirs(RUNS_DIR, exist_ok=True)
store = Store(DB_FILE)


# ------------------------------------------------------------------ capture queue
_QUEUE: "list[str]" = []
_QCV = threading.Condition()


def enqueue(run_id: str) -> None:
    with _QCV:
        _QUEUE.append(run_id)
        _QCV.notify()


def _worker() -> None:
    while True:
        with _QCV:
            while not _QUEUE:
                _QCV.wait()
            rid = _QUEUE.pop(0)
        try:
            run_capture(rid)
        except Exception as e:
            store.update_run(rid, status="failed", error=f"{type(e).__name__}: {e}")


def run_capture(rid: str) -> None:
    """Execute one local audit: probe -> capture -> archive into runs/<id>/.

    Reuses the verified readers in capture.py/sysinfo.py/report.py. Nothing is
    sent anywhere; the archive is written for the operator to inspect locally.
    """
    run = store.get_run(rid)
    if not run:
        return
    store.update_run(rid, status="running")

    import capture
    import probe
    import report
    import sysinfo

    stage = tempfile.mkdtemp(prefix="jwg_run_")
    try:
        rows = probe.run_all()
        opts = run.get("options", {})
        # Shared, option-driven collector set (see capture.run_capture). Every
        # toggle in CAPTURE_OPTIONS now maps to a real reader - no dead checkboxes.
        caps = capture.run_capture(stage, {k: bool(opts.get(k)) for k in CAPTURE_OPTIONS})

        system = sysinfo.gather() if opts.get("system_info", True) else {}
        report.write_items(stage, caps)
        text = report.render_report(caps, system, rows)

        out_zip = os.path.join(RUNS_DIR, f"{rid}.zip")
        arch, size, nfiles = report.build_archive(stage, out_zip, caps)
        # keep the human-readable report + probe output inside the archive too
        with zipfile.ZipFile(arch, "a", zipfile.ZIP_DEFLATED) as z:
            z.writestr("report.md", text)
            z.writestr("probe.json", json.dumps(rows, indent=2, default=str))

        counts = {c.kind: c.count for c in caps if c.count}
        store.update_run(rid, status="done", artifact=arch, counts=counts, error=None)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


threading.Thread(target=_worker, daemon=True).start()


# ------------------------------------------------------------------ templates
BASE_CSS = """
:root{--bg:#0a0c0f;--panel:#12151b;--panel2:#0e1116;--line:#232833;--ink:#e8eaed;
 --dim:#8b93a1;--faint:#6b7280;--accent:#f06292;--accent-d:#c2417a;--ok:#3fb950;
 --warn:#e3b341;--bad:#f85149;--radius:14px}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#151a24 0,var(--bg) 60%);
 color:var(--ink);font:14px/1.55 -apple-system,'Segoe UI',Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:960px;margin:0 auto;padding:34px 22px 64px}
.brand{font-weight:800;letter-spacing:.14em;color:var(--accent);font-size:19px;text-transform:uppercase}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);
 border-radius:var(--radius);padding:20px 22px;margin-bottom:18px;box-shadow:0 1px 0 #ffffff08 inset,0 12px 30px -18px #000}
.card h3{margin:0 0 4px;font-size:15px;letter-spacing:.02em}
.card .sub{margin:0 0 16px;color:var(--dim);font-size:12.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.store{display:flex;gap:12px;align-items:flex-start;padding:13px 14px;border:1px solid var(--line);
 border-radius:11px;background:#0d1015;cursor:pointer;transition:border-color .15s,transform .05s}
.store:hover{border-color:#39414f}
.store input{margin-top:3px;width:17px;height:17px;accent-color:var(--accent);flex:0 0 auto;cursor:pointer}
.store .t{font-weight:600;font-size:13.5px;line-height:1.2}
.store .d{color:var(--faint);font-size:11.5px;margin-top:3px}
input[type=text],input[type=password]{width:100%;background:#0d1015;border:1px solid var(--line);
 color:var(--ink);padding:11px 13px;border-radius:9px;font:inherit;outline:none;transition:border-color .15s}
input:focus{border-color:var(--accent)}
label.fld{display:block;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;margin:0 0 6px}
button{background:linear-gradient(180deg,var(--accent),var(--accent-d));color:#160a10;border:0;
 padding:12px 22px;border-radius:10px;font:inherit;font-weight:800;cursor:pointer;letter-spacing:.05em;
 transition:filter .15s}
button:hover{filter:brightness(1.08)}button:active{transform:translateY(1px)}
.btnbig{width:100%;padding:15px;font-size:14.5px;letter-spacing:.12em}
.row{display:flex;gap:12px;align-items:center;justify-content:space-between}
.nav{display:flex;gap:8px;margin:14px 0 24px;border-bottom:1px solid var(--line);padding-bottom:14px}
.nav a{padding:8px 16px;border-radius:9px;background:transparent;border:1px solid transparent;color:var(--dim);
 font-weight:600;font-size:13px}
.nav a:hover{color:var(--ink);text-decoration:none}
.nav a.on{background:var(--accent);color:#160a10;border-color:var(--accent);font-weight:800}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #1a1f27}
tr:last-child td{border-bottom:0}
th{color:var(--dim);font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:.07em}
tbody tr:hover{background:#0f1319}
.pill{padding:3px 11px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.02em;display:inline-block}
.pill.done{background:#0f2a19;color:var(--ok);border:1px solid #14401f}
.pill.running,.pill.queued{background:#2a2410;color:var(--warn);border:1px solid #3d3316}
.pill.failed{background:#2a1113;color:var(--bad);border:1px solid #451a1d}
.muted{color:var(--faint);font-size:12px}.status{font-size:12.5px;color:var(--dim);margin:2px 0 16px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:7px;
 box-shadow:0 0 0 3px #0f2a19}
.err{color:#ffb4ad;background:#201113;border:1px solid #3a1416;padding:12px 14px;border-radius:10px;margin-bottom:16px}
.ok{color:#a6e7b4;background:#0f2016;border:1px solid #12351f;padding:12px 14px;border-radius:10px;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:18px}
.stat{background:#0d1015;border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.stat .k{color:var(--faint);font-size:10.5px;text-transform:uppercase;letter-spacing:.07em}
.stat .v{font-size:22px;font-weight:800;margin-top:4px;letter-spacing:-.01em}
.chip{display:inline-flex;gap:6px;align-items:center;background:#0d1015;border:1px solid var(--line);
 border-radius:20px;padding:4px 11px;font-size:11.5px;color:var(--dim);margin:2px 6px 2px 0}
.chip b{color:var(--ink);font-weight:700}
.dl{padding:5px 12px;border-radius:8px;background:#0d1015;border:1px solid var(--line);color:var(--accent);
 font-size:12px;font-weight:600}
.dl:hover{border-color:var(--accent);text-decoration:none}
.empty{text-align:center;color:var(--faint);padding:34px 0}
.foot{margin-top:26px;text-align:center;color:#4b5260;font-size:11px;letter-spacing:.03em}
.spin{display:inline-block;width:12px;height:12px;border:2px solid #3d3316;border-top-color:var(--warn);
 border-radius:50%;animation:s 0.8s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes s{to{transform:rotate(360deg)}}
"""

LOGIN_TPL = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Self-Audit · sign in</title><style>{{css}}</style>
<div class=wrap style="max-width:430px;padding-top:9vh">
 <div style="text-align:center;margin-bottom:22px">
   <div class=brand style="font-size:22px">Self&#8209;Audit</div>
   <p class=muted style="margin-top:6px">local capture console · this machine only</p>
 </div>
 {%if setup%}<div class=ok>First run &mdash; pick a username and a password (8+ characters).</div>{%endif%}
 {%if err%}<div class=err>{{err}}</div>{%endif%}
 <form method=post>
  <div class=card>
   <label class=fld>Username</label><input name=u type=text autocomplete=username autofocus required>
   <div style="height:14px"></div>
   <label class=fld>Password</label><input name=p type=password autocomplete=current-password required>
  </div>
  <button class=btnbig type=submit>SIGN IN</button>
 </form>
 <div class=foot>runs locally on 127.0.0.1 · no data leaves unless you export it</div>
</div>"""

APP_TPL = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Self-Audit</title><style>{{css}}</style>
<div class=wrap>
 <div class=row style="margin-bottom:4px">
   <div class=brand style="font-size:22px">Self&#8209;Audit</div>
   <div class=muted>{{user.username}} &nbsp;&middot;&nbsp; <a href=/logout>sign out</a></div>
 </div>
 <div class=nav>
   <a class="{{'on' if tab=='capture' else ''}}" href=/>Capture</a>
   <a class="{{'on' if tab=='runs' else ''}}" href=/runs>Runs</a>
 </div>
 {{body|safe}}
 <div class=foot>single-operator console &middot; reads your own machine &middot; nothing is sent anywhere by default</div>
</div>"""

CAPTURE_TPL = """
{%if msg%}<div class=ok>{{msg}}</div>{%endif%}
{%if err%}<div class=err>{{err}}</div>{%endif%}
<div class=status><span class=dot></span>this machine only &mdash; results stay local until you download them</div>
<form method=post action=/capture>
 <div class=card>
   <h3>What to read</h3>
   <p class=sub>Select one or more stores. Each maps to a verified local reader.</p>
   <div class=grid>
     {%for k,label in options.items()%}
       <label class=store>
         <input type=checkbox name="c_{{k}}" {{checks[k]}}>
         <span><span class=t>{{label}}</span><span class=d>{{help[k]}}</span></span>
       </label>
     {%endfor%}
   </div>
 </div>
 <button class=btnbig type=submit>RUN CAPTURE</button>
</form>
"""

RUNS_TPL = """
{%if msg%}<div class=ok>{{msg}}</div>{%endif%}
<div class=stats>
 <div class=stat><div class=k>Total runs</div><div class=v>{{stats.total}}</div></div>
 <div class=stat><div class=k>Completed</div><div class=v>{{stats.done}}</div></div>
 <div class=stat><div class=k>In progress</div><div class=v>{{stats.active}}</div></div>
 <div class=stat><div class=k>Items captured</div><div class=v>{{stats.items}}</div></div>
</div>
<div class=card>
 <h3>History</h3>
 {%if not runs%}<div class=empty>No captures yet. Pick stores on the Capture tab and run one.</div>{%else%}
 <table><thead><tr><th>when</th><th>status</th><th>stores</th><th>items</th><th></th></tr></thead><tbody>
 {%for r in runs%}
 <tr>
   <td class=muted>{{r.when}}</td>
   <td><span class="pill {{r.status}}">{%if r.status in ('running','queued')%}<span class=spin></span>{%endif%}{{r.status}}
       {%if r.status=='failed'%}<div class=muted style="margin-top:4px">{{r.error or ''}}</div>{%endif%}</span></td>
   <td>{%for c in r.chips%}<span class=chip>{{c.k}} <b>{{c.v}}</b></span>{%endfor%}{%if not r.chips%}<span class=muted>&mdash;</span>{%endif%}</td>
   <td class=muted>{{r.summary}}</td>
   <td>{%if r.status=='done' and r.artifact%}<a class=dl href="/download/{{r.id}}">archive &#8595;</a>{%endif%}</td>
 </tr>
 {%endfor%}</tbody></table>
 {%if stats.active%}<p class=muted style="margin-top:12px"><span class=spin></span>capture in progress &mdash; refreshes automatically.</p>{%endif%}
 {%endif%}
</div>
<script>setTimeout(()=>location.reload(),{{ '1500' if stats.active else '8000' }});</script>
"""


# ------------------------------------------------------------------ auth helpers
def current_user() -> dict | None:
    uid = session.get("uid")
    if not uid:
        return None
    op = store.get_operator()
    if op and op["id"] == uid and not op.get("disabled"):
        return op
    return None


def login_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return inner


# ------------------------------------------------------------------ app factory
DEFAULT_CHECKS = {k: k in ("system_info", "cookies", "passwords", "history",
                           "extensions") for k in CAPTURE_OPTIONS}


def _short_kind(kind: str) -> str:
    """Turn a capture kind like 'chromium-cookies:brave/Default' into a compact
    chip label 'cookies · brave'. Splits on ':' then keeps the store + browser."""
    head, _, tail = kind.partition(":")
    # Kinds without a browser/profile suffix (software-list, product-keys) pass through.
    if not tail:
        return {"software-list": "software", "product-keys": "keys"}.get(head, head)
    parts = head.split("-")
    store = parts[-1] if len(parts) > 1 else head
    prof = tail.split("/")[0]
    return f"{store} · {prof}"


def create_app(secret: str | None = None):
    if Flask is None:
        raise RuntimeError("flask not installed: pip install flask")
    app = Flask(__name__)
    app.secret_key = secret or os.environ.get("PANEL_SECRET") or secrets.token_bytes(32)

    def render(body_html: str, tab: str) -> Response:
        u = current_user()
        html = render_template_string(APP_TPL, css=BASE_CSS, body=body_html,
                                      user=u, tab=tab)
        return Response(html, mimetype="text/html")

    # ---- auth ----
    @app.route("/login", methods=["GET", "POST"])
    def login():
        err = ""
        op = store.get_operator()
        first = op is None
        if request.method == "POST":
            uname = request.form.get("u", "")
            pw = request.form.get("p", "")
            if first:
                try:
                    op = store.set_operator(uname, pw)
                except ValueError as e:
                    return Response(render_template_string(
                        LOGIN_TPL, css=BASE_CSS, err=str(e), setup=True),
                        mimetype="text/html")
            if op and op["username"].lower() == uname.strip().lower() \
                    and verify_password(pw, op["pw_hash"], op["pw_salt"]):
                session["uid"] = op["id"]
                return redirect(request.args.get("next") or "/")
            err = err or "bad username or password"
        html = render_template_string(LOGIN_TPL, css=BASE_CSS, err=err, setup=first)
        return Response(html, mimetype="text/html")

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- capture page ----
    @app.get("/")
    @login_required
    def home():
        checks = {k: "checked" if DEFAULT_CHECKS[k] else "" for k in CAPTURE_OPTIONS}
        body = render_template_string(CAPTURE_TPL, options=CAPTURE_OPTIONS, checks=checks,
                                      help=OPTION_HELP,
                                      msg=request.args.get("msg", ""),
                                      err=request.args.get("err", ""))
        return render(body, "capture")

    @app.post("/capture")
    @login_required
    def do_capture():
        opts = {k: bool(request.form.get(f"c_{k}")) for k in CAPTURE_OPTIONS}
        if not any(opts.values()):
            return redirect(url_for("home", err="pick at least one store"))
        run = asdict(Run(id=secrets.token_hex(8), status="queued",
                         created=time.time(), options=opts))
        store.add_run(run)
        enqueue(run["id"])
        return redirect(url_for("runs", msg=f"queued: {run['id']}"))

    # ---- runs ----
    @app.get("/runs")
    @login_required
    def runs():
        all_runs = store.list_runs()
        rows = []
        chips_all = []
        total_items = 0
        n_done = n_active = 0
        for r in all_runs:
            counts = r.get("counts", {}) or {}
            total = sum(counts.values())
            total_items += total
            if r.get("status") == "done":
                n_done += 1
            elif r.get("status") in ("running", "queued"):
                n_active += 1
            # Per-store chips: split "kind:browser/prof" into a short label + count.
            chips = [{"k": _short_kind(k), "v": v} for k, v in
                     sorted(counts.items(), key=lambda x: -x[1])[:6]]
            rows.append({**r,
                         "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created"])),
                         "summary": f"{total:,}" if counts else "-",
                         "chips": chips})
            chips_all.extend(chips)
        stats = {"total": len(all_runs), "done": n_done,
                 "active": n_active, "items": f"{total_items:,}"}
        body = render_template_string(RUNS_TPL, runs=rows, stats=stats,
                                      msg=request.args.get("msg", ""))
        return render(body, "runs")

    @app.get("/download/<rid>")
    @login_required
    def download(rid):
        r = store.get_run(rid)
        if not r or r.get("status") != "done":
            abort(404)
        p = r.get("artifact")
        if not p or not os.path.isfile(p):
            abort(404, description="artifact gone")
        return send_file(p, as_attachment=True, download_name=os.path.basename(p),
                         mimetype="application/zip")

    @app.get("/api/runs")
    @login_required
    def api_runs():
        return jsonify(store.list_runs())

    return app


# ------------------------------------------------------------------ entrypoint
if __name__ == "__main__":
    host = os.environ.get("PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PANEL_PORT", "8787"))
    loopback = host in ("127.0.0.1", "localhost", "::1")
    pinned = os.environ.get("PANEL_SECRET")
    if not loopback and not pinned:
        print("[fatal] refusing routable bind without PANEL_SECRET. "
              "This console reads live browser stores on its own box.", file=sys.stderr)
        raise SystemExit(1)

    app = create_app()
    op = store.get_operator()
    if op is None:
        pw = os.environ.get("PANEL_ADMIN_PASS", "")
        if not pw:
            pw = secrets.token_urlsafe(12)
            print(f"[panel] first run - admin password: {pw}")
        store.set_operator(os.environ.get("PANEL_ADMIN_USER", "admin"), pw)
    print(f"[panel] open http://{host}:{port}  (loopback audit console)")
    app.run(host=host, port=port, threaded=True)
