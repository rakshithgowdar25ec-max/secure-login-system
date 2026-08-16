const path = require("path");
const Database = require("better-sqlite3");

const dbPath = path.join(__dirname, "..", "..", "db", "app.db");
require("fs").mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT UNIQUE NOT NULL,
    email             TEXT UNIQUE NOT NULL,
    password_hash     TEXT NOT NULL,
    twofa_secret      TEXT,
    twofa_enabled     INTEGER NOT NULL DEFAULT 0,
    failed_attempts   INTEGER NOT NULL DEFAULT 0,
    lockout_until     INTEGER,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

module.exports = db;
