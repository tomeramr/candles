-- Run once in Cloudflare: D1 → candles-pro → Console
CREATE TABLE IF NOT EXISTS users (
  lic TEXT PRIMARY KEY,      -- SHA-256 of the serial (the serial itself is never stored)
  tail TEXT,                 -- last 4 characters of the serial, to tell serials apart
  email TEXT,
  name TEXT,
  status TEXT,               -- active / inactive / expired / disabled
  first_seen INTEGER,
  last_seen INTEGER,
  last_check INTEGER,
  expires_at TEXT,           -- from Lemon Squeezy (null = until the subscription ends)
  ended_at INTEGER           -- when the serial stopped working (expired / disabled)
);
CREATE TABLE IF NOT EXISTS devices (
  iid TEXT PRIMARY KEY,      -- Lemon Squeezy activation (instance) id
  lic TEXT,
  label TEXT,
  ver TEXT,                  -- app version running on this device
  first_seen INTEGER,
  last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS devices_lic ON devices(lic);
CREATE TABLE IF NOT EXISTS guests (
  h TEXT PRIMARY KEY,        -- SHA-256 of the guest code
  tail TEXT,
  name TEXT,
  created INTEGER,
  expires INTEGER,
  revoked INTEGER,
  last_seen INTEGER,
  expired_logged INTEGER
);
CREATE TABLE IF NOT EXISTS events (  -- the serial log
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  t INTEGER,
  lic TEXT,
  tail TEXT,
  email TEXT,
  ev TEXT,                   -- first_use, device_added, open, expired, disabled, renewed, refused, device_removed, guest_created, guest_revoked
  detail TEXT
);
CREATE INDEX IF NOT EXISTS events_lic ON events(lic, t);
CREATE INDEX IF NOT EXISTS events_t ON events(t);
CREATE TABLE IF NOT EXISTS rl (      -- rate limiting, per IP per minute
  k TEXT PRIMARY KEY,
  n INTEGER,
  t INTEGER
);
