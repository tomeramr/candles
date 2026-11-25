-- v2.7: usage, installs, error log and payments ledger (safe to run again)
CREATE TABLE IF NOT EXISTS clients (   -- one row per device/browser that opened the app (random id, no personal data)
  did TEXT PRIMARY KEY, kind TEXT, who TEXT, ver TEXT, dev TEXT, country TEXT,
  first_seen INTEGER, last_seen INTEGER, installed INTEGER DEFAULT 0, installed_at INTEGER, hits INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS clients_seen ON clients(last_seen);
CREATE TABLE IF NOT EXISTS daily (day TEXT, did TEXT, kind TEXT, PRIMARY KEY (day, did));
CREATE TABLE IF NOT EXISTS usage_log (id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER, did TEXT, kind TEXT, ev TEXT);
CREATE INDEX IF NOT EXISTS usage_log_t ON usage_log(t);
CREATE TABLE IF NOT EXISTS errors (
  sig TEXT, day TEXT, first_t INTEGER, last_t INTEGER, n INTEGER, devices INTEGER,
  msg TEXT, src TEXT, line INTEGER, ver TEXT, kind TEXT, page TEXT, dev TEXT, stack TEXT, last_did TEXT,
  PRIMARY KEY (sig, day)
);
CREATE INDEX IF NOT EXISTS errors_t ON errors(last_t);
CREATE TABLE IF NOT EXISTS subs (
  id TEXT PRIMARY KEY, email TEXT, name TEXT, plan TEXT, status TEXT, created INTEGER,
  renews_at INTEGER, ends_at INTEGER, trial_ends_at INTEGER, test INTEGER, order_id TEXT
);
CREATE TABLE IF NOT EXISTS payments (   -- amounts in cents (agorot)
  id TEXT PRIMARY KEY, t INTEGER, sub_id TEXT, order_id TEXT, customer TEXT, email TEXT, plan TEXT, reason TEXT,
  amount INTEGER, refunded_amount INTEGER DEFAULT 0, currency TEXT, status TEXT, test INTEGER, ref TEXT
);
CREATE INDEX IF NOT EXISTS payments_t ON payments(t);
