// קורא נרות פרו – שרת רישיונות (Cloudflare Worker)
//
// The paid app is never readable without a valid serial: pro/app.bin on GitHub is encrypted,
// and only this server holds the key. For a valid Lemon Squeezy serial (or a guest code the
// admin created) it decrypts the app, stamps it with the serial, and returns it.
// Every serial has a log (activated, opened, expired, refused, device freed ...), shown in the
// admin dashboard. Requests are rate-limited per IP.
//
// Bindings / secrets (Cloudflare dashboard → Worker → Settings → Variables):
//   DB              D1 database (run schema.sql once)
//   CONTENT_KEY     secret: base64 key of pro/app.enc (tools/build_pro.py --print-key)
//   ADMIN_TOKEN     secret: long random code; typed once in the admin dashboard
//   LS_API_KEY      secret: Lemon Squeezy API key (subscription status for the dashboard)
//   LS_STORE_ID     plain: your Lemon Squeezy store id (required; keys from other stores are refused)
//   LS_PRODUCT_ID   plain, optional: only accept keys of this product
//   ALLOWED_ORIGIN  plain, optional: default https://tomeramr.github.io
//   APP_URL         plain, optional: default https://tomeramr.github.io/candles/pro/app.bin
//   LS_WEBHOOK_SECRET secret: the signing secret of the Lemon Squeezy webhook (payments ledger)

const LS = 'https://api.lemonsqueezy.com';
const REVALIDATE_MS = 60 * 60 * 1000;   // light check (ping): ask Lemon Squeezy at most once an hour
const APP_CHECK_MS = 10 * 60 * 1000;    // opening the app: re-check if the last check is older than 10 min
const ONLINE_MS = 5 * 60 * 1000;
const LIMITS = { unlock: 8, app: 12, ping: 30, release: 10, admin: 90, hit: 20, err: 20, lswebhook: 120 }; // requests per minute per IP
let APP_CACHE = {}; // per language: {at, html}

export default {
  async fetch(req, env, ctx) {
    const origin = env.ALLOWED_ORIGIN || 'https://tomeramr.github.io';
    const cors = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    };
    const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const path = new URL(req.url).pathname.replace(/\/+$/, '');
    try {
      if (path === '' || path === '/health') return json({ ok: true, service: 'candles-pro' });
      // fail closed: without these settings any Lemon Squeezy store's keys would be accepted
      if (!(env.LS_STORE_ID && env.CONTENT_KEY && env.DB)) return json({ ok: false, reason: 'not_ready' }, 503);
      const route = path.startsWith('/admin') ? 'admin' : path.slice(1);
      if (LIMITS[route] && !(await allow(env, req, route))) return json({ ok: false, reason: 'rate' }, 429);
      if (req.method === 'POST' && path === '/unlock') return json(await unlock(env, await body(req)));
      if (req.method === 'POST' && path === '/app') return json(await app(env, await body(req)));
      if (req.method === 'POST' && path === '/ping') return json(await ping(env, await body(req)));
      if (req.method === 'POST' && path === '/release') return json(await release(env, await body(req)));
      if (req.method === 'POST' && path === '/hit') return json(await hit(env, await req.json().catch(() => ({})), req));
      if (req.method === 'POST' && path === '/err') return json(await errLog(env, await req.json().catch(() => ({}))));
      if (req.method === 'POST' && path === '/lswebhook') return json(await lsWebhook(env, req));
      if (path.startsWith('/admin/')) {
        if (!(await isAdmin(req, env))) return json({ ok: false, reason: 'unauthorized' }, 401);
        if (req.method === 'GET' && path === '/admin/stats') return json(await stats(env));
        if (req.method === 'POST' && path === '/admin/guest') return json(await guestCreate(env, await req.json().catch(() => ({}))));
        const q = new URL(req.url).searchParams;
        if (req.method === 'GET' && path === '/admin/overview') return json(await overview(env, q));
        if (req.method === 'GET' && path === '/admin/errors') return json(await errList(env, q));
        if (req.method === 'POST' && path === '/admin/errors/clear') return json(await errClear(env));
        if (req.method === 'GET' && path === '/admin/payments') return json(await payList(env, q, false));
        if (req.method === 'GET' && path === '/admin/payments/all') return json(await payList(env, q, true));
        if (req.method === 'POST' && path === '/admin/sync') return json(await lsSync(env));
        if (req.method === 'POST' && path === '/admin/guest/revoke') return json(await guestRevoke(env, await req.json().catch(() => ({}))));
        if (req.method === 'POST' && path === '/admin/guest/delete') return json(await guestDelete(env, await req.json().catch(() => ({}))));
        if (req.method === 'POST' && path === '/admin/guest/purge') return json(await guestPurge(env));
        if (req.method === 'POST' && path === '/admin/events/clear') return json(await eventsClear(env));
      }
      return json({ ok: false, reason: 'not_found' }, 404);
    } catch (e) {
      return json({ ok: false, reason: e && e.reason ? e.reason : 'server_error' }, e && e.status ? e.status : 500);
    }
  },
};

// ---------- helpers ----------
async function body(req) {
  let b;
  try { b = await req.json(); } catch (e) { throw { reason: 'bad_request', status: 400 }; }
  const key = String((b && b.key) || '').trim();
  if (!/^[A-Za-z0-9-]{8,80}$/.test(key)) throw { reason: 'bad_key', status: 400 };
  return {
    key,
    iid: String((b && b.iid) || '').trim().slice(0, 80),
    dev: String((b && b.dev) || 'מכשיר').replace(/[<>]/g, '').slice(0, 60),
    ver: /^[0-9][0-9.]{0,15}$/.test(String((b && b.ver) || '')) ? String(b.ver) : '',
    lang: b && b.lang === 'en' ? 'en' : 'he',
  };
}
async function sha(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join('');
}
const isGuest = key => /^G-[A-Z2-9]{20}$/.test(key);

async function allow(env, req, route) {
  const ip = req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';
  const minute = Math.floor(Date.now() / 60000);
  const k = `${route}:${ip}:${minute}`;
  const row = await env.DB.prepare('INSERT INTO rl (k, n, t) VALUES (?1, 1, ?2) ON CONFLICT(k) DO UPDATE SET n = n + 1 RETURNING n').bind(k, minute).first();
  if (Math.random() < 0.02) await env.DB.prepare('DELETE FROM rl WHERE t < ?1').bind(minute - 5).run();
  return !row || row.n <= LIMITS[route];
}

async function log(env, lic, tail, email, ev, detail) {
  await env.DB.prepare('INSERT INTO events (t, lic, tail, email, ev, detail) VALUES (?1,?2,?3,?4,?5,?6)')
    .bind(Date.now(), lic, tail || '', email || '', ev, String(detail || '').slice(0, 120)).run();
}

// ---------- Lemon Squeezy ----------
async function lsLicense(endpoint, params) {
  const r = await fetch(`${LS}/v1/licenses/${endpoint}`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  let j = {};
  try { j = await r.json(); } catch (e) {}
  if (r.status >= 500 || r.status === 429) throw { reason: 'ls_unavailable', status: 503 };
  return j;
}
function checkMeta(env, j) {
  const m = (j && j.meta) || {};
  if (!env.LS_STORE_ID || String(m.store_id) !== String(env.LS_STORE_ID)) return 'wrong_product';
  if (env.LS_PRODUCT_ID && String(m.product_id) !== String(env.LS_PRODUCT_ID)) return 'wrong_product';
  return null;
}
function reasonOf(j) {
  const st = j && j.license_key && j.license_key.status;
  if (st === 'expired') return 'expired';
  if (st === 'disabled') return 'disabled';
  const err = String((j && j.error) || '').toLowerCase();
  if (err.includes('activation limit')) return 'device_limit';
  if (err.includes('expired')) return 'expired';
  if (err.includes('disabled')) return 'disabled';
  return 'invalid';
}

async function remember(env, lic, j, iid, dev, ver, now) {
  const m = j.meta || {};
  const tail = (j.license_key && j.license_key.key || '').slice(-4);
  const prev = await env.DB.prepare('SELECT status FROM users WHERE lic=?1').bind(lic).first();
  const status = (j.license_key && j.license_key.status) || 'active';
  await env.DB.prepare(
    `INSERT INTO users (lic, tail, email, name, status, first_seen, last_seen, last_check, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?6,?6,?7)
     ON CONFLICT(lic) DO UPDATE SET email=?3, name=?4, status=?5, last_seen=?6, last_check=?6, expires_at=?7`
  ).bind(lic, tail, m.customer_email || '', m.customer_name || '', status, now, (j.license_key && j.license_key.expires_at) || null).run();
  if (!prev) await log(env, lic, tail, m.customer_email, 'first_use', m.variant_name || '');
  else if (prev.status && prev.status !== status && (prev.status === 'expired' || prev.status === 'disabled')) await log(env, lic, tail, m.customer_email, 'renewed', `${prev.status} → ${status}`);
  if (iid) {
    const d = await env.DB.prepare('SELECT iid FROM devices WHERE iid=?1').bind(iid).first();
    await env.DB.prepare(
      `INSERT INTO devices (iid, lic, label, first_seen, last_seen, ver) VALUES (?1,?2,?3,?4,?4,?5)
       ON CONFLICT(iid) DO UPDATE SET last_seen=?4, ver=CASE WHEN ?5<>'' THEN ?5 ELSE ver END`
    ).bind(iid, lic, dev || 'מכשיר', now, ver || '').run();
    if (!d) await log(env, lic, tail, m.customer_email, 'device_added', dev || '');
  }
  return { tail, email: m.customer_email || '', name: m.customer_name || '', plan: m.variant_name || '' };
}

// a refused serial: log it, and log "expired" once when a working serial stops working
async function refused(env, key, j, reason) {
  const lic = await sha(key);
  const u = await env.DB.prepare('SELECT status, tail, email FROM users WHERE lic=?1').bind(lic).first();
  const tail = (u && u.tail) || key.slice(-4);
  if (u && (reason === 'expired' || reason === 'disabled') && u.status !== reason) {
    await env.DB.prepare('UPDATE users SET status=?2, last_check=?3, ended_at=?3 WHERE lic=?1').bind(lic, reason, Date.now()).run();
    await log(env, lic, tail, u.email, reason === 'expired' ? 'expired' : 'disabled', '');
  } else if (u) {
    await log(env, lic, tail, u.email, 'refused', reason);
  }
  return { ok: false, reason };
}

// ---------- guests (free codes created by the admin) ----------
async function guestCheck(env, key) {
  const g = await env.DB.prepare('SELECT * FROM guests WHERE h=?1').bind(await sha(key)).first();
  if (!g) return { ok: false, reason: 'invalid' };
  if (g.revoked) return { ok: false, reason: 'disabled', g };
  if (Date.now() > g.expires) {
    if (!g.expired_logged) {
      await env.DB.prepare('UPDATE guests SET expired_logged=1 WHERE h=?1').bind(g.h).run();
      await log(env, g.h, g.tail, g.name, 'expired', 'קוד אורח');
    }
    return { ok: false, reason: 'expired', g };
  }
  await env.DB.prepare('UPDATE guests SET last_seen=?2 WHERE h=?1').bind(g.h, Date.now()).run();
  return { ok: true, g };
}
async function guestCreate(env, b) {
  const name = String(b.name || '').replace(/[<>]/g, '').trim().slice(0, 40);
  const days = Math.min(365, Math.max(1, Math.floor(+b.days || 7)));
  if (!name) return { ok: false, reason: 'name_required' };
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const rnd = crypto.getRandomValues(new Uint8Array(20));
  const code = 'G-' + [...rnd].map(x => A[x % 32]).join('');
  const h = await sha(code), now = Date.now();
  await env.DB.prepare('INSERT INTO guests (h, tail, name, created, expires, revoked, last_seen, expired_logged) VALUES (?1,?2,?3,?4,?5,0,NULL,0)')
    .bind(h, code.slice(-4), name, now, now + days * 864e5).run();
  await log(env, h, code.slice(-4), name, 'guest_created', `${days} ימים`);
  return { ok: true, code, name, expires: now + days * 864e5 };
}
async function guestRevoke(env, b) {
  const tail = String(b.tail || '').slice(0, 8), created = +b.created || 0;
  const g = await env.DB.prepare('SELECT * FROM guests WHERE tail=?1 AND created=?2').bind(tail, created).first();
  if (!g) return { ok: false, reason: 'not_found' };
  await env.DB.prepare('UPDATE guests SET revoked=1 WHERE h=?1').bind(g.h).run();
  await log(env, g.h, g.tail, g.name, 'guest_revoked', '');
  return { ok: true };
}

// delete one guest code for good (it stops working at once) and its log lines
async function guestDelete(env, b) {
  const tail = String(b.tail || '').slice(0, 8), created = +b.created || 0;
  const g = await env.DB.prepare('SELECT h FROM guests WHERE tail=?1 AND created=?2').bind(tail, created).first();
  if (!g) return { ok: false, reason: 'not_found' };
  await env.DB.prepare('DELETE FROM guests WHERE h=?1').bind(g.h).run();
  await env.DB.prepare('DELETE FROM events WHERE lic=?1').bind(g.h).run();
  return { ok: true };
}
// delete every guest code that was revoked or has expired, with their log lines
async function guestPurge(env) {
  const now = Date.now();
  const rows = (await env.DB.prepare('SELECT h FROM guests WHERE revoked=1 OR expires < ?1').bind(now).all()).results || [];
  for (const r of rows) await env.DB.prepare('DELETE FROM events WHERE lic=?1').bind(r.h).run();
  await env.DB.prepare('DELETE FROM guests WHERE revoked=1 OR expires < ?1').bind(now).run();
  return { ok: true, deleted: rows.length };
}
// empty the serial log (codes and subscriptions are not touched)
async function eventsClear(env) {
  const r = await env.DB.prepare('DELETE FROM events').run();
  return { ok: true, deleted: (r && r.meta && r.meta.changes) || 0 };
}

// ---------- the app itself ----------
function b64d(s) { const t = atob(s), u = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) u[i] = t.charCodeAt(i); return u; }
async function appHtml(env, lang) {
  const L = lang === 'en' ? 'en' : 'he';
  const c = APP_CACHE[L];
  if (c && Date.now() - c.at < 10 * 60 * 1000) return c.html;
  const base = env.APP_URL || 'https://tomeramr.github.io/candles/pro/app.bin';
  const url = (L === 'en' ? base.replace(/app\.bin$/, 'app_en.bin') : base) + '?t=' + Math.floor(Date.now() / 600000);
  const r = await fetch(url, { cf: { cacheTtl: 300 } });
  if (!r.ok) throw { reason: 'server_error', status: 502 };
  const buf = new Uint8Array(await r.arrayBuffer());
  const key = await crypto.subtle.importKey('raw', b64d(env.CONTENT_KEY), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  const html = await new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  APP_CACHE[L] = { at: Date.now(), html };
  return html;
}
function stamp(html, who) {
  const esc = s => String(s).replace(/[<>&"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
  const tag = `<!-- licensed to ${esc(who.label)} · serial …${esc(who.tail)} · ${new Date().toISOString()} -->\n<script>window.__LIC=${JSON.stringify({ label: who.label, tail: who.tail, guest: !!who.guest, until: who.until || null })};</script>\n`;
  const m = html.match(/<head[^>]*>/i);
  return m ? html.slice(0, m.index + m[0].length) + '\n' + tag + html.slice(m.index + m[0].length) : tag + html;
}

async function validate(env, { key, iid, dev, ver }, maxAge) {
  // returns {ok, who} or {ok:false, reason}
  if (isGuest(key)) {
    const c = await guestCheck(env, key);
    if (!c.ok) {
      if (c.g && c.reason !== 'expired') await log(env, c.g.h, c.g.tail, c.g.name, 'refused', c.reason);
      return { ok: false, reason: c.reason };
    }
    return { ok: true, who: { label: c.g.name + ' (אורח)', tail: c.g.tail, guest: true, until: c.g.expires }, lic: c.g.h };
  }
  const now = Date.now();
  const lic = await sha(key);
  const u = await env.DB.prepare('SELECT last_check, status, tail, email, name FROM users WHERE lic=?1').bind(lic).first();
  if (u && now - (u.last_check || 0) < maxAge && u.status !== 'expired' && u.status !== 'disabled') {
    await env.DB.prepare('UPDATE users SET last_seen=?2 WHERE lic=?1').bind(lic, now).run();
    if (iid) await env.DB.prepare(ver ? 'UPDATE devices SET last_seen=?2, ver=?3 WHERE iid=?1' : 'UPDATE devices SET last_seen=?2 WHERE iid=?1').bind(...(ver ? [iid, now, ver] : [iid, now])).run();
    return { ok: true, who: { label: u.email || u.name || 'מנוי', tail: u.tail }, lic };
  }
  const j = await lsLicense('validate', iid ? { license_key: key, instance_id: iid } : { license_key: key });
  if (!j.valid) return refused(env, key, j, reasonOf(j));
  const bad = checkMeta(env, j);
  if (bad) return { ok: false, reason: bad };
  const w = await remember(env, lic, j, iid, dev, ver, now);
  return { ok: true, who: { label: w.email || w.name || 'מנוי', tail: w.tail }, lic };
}

async function unlock(env, b) {
  let { key, iid, dev, ver } = b;
  if (isGuest(key)) {
    const v = await validate(env, b, 0);
    if (!v.ok) return v;
    await log(env, v.lic, v.who.tail, v.who.label, 'open', dev);
    return { ok: true, iid: '', name: v.who.label, guest: true, until: v.who.until, html: stamp(await appHtml(env, b.lang), v.who) };
  }
  const now = Date.now();
  let j;
  if (iid) {
    j = await lsLicense('validate', { license_key: key, instance_id: iid });
    if (!j.valid && !['expired', 'disabled'].includes(reasonOf(j))) {
      const a = await lsLicense('activate', { license_key: key, instance_name: dev });
      if (a.activated) { j = { ...a, valid: true }; iid = a.instance.id; }
    }
  } else {
    j = await lsLicense('activate', { license_key: key, instance_name: dev });
    if (j.activated) { j.valid = true; iid = j.instance.id; }
  }
  if (!j.valid) return refused(env, key, j, reasonOf(j));
  const bad = checkMeta(env, j);
  if (bad) return { ok: false, reason: bad };
  const lic = await sha(key);
  const w = await remember(env, lic, j, iid, dev, ver, now);
  await log(env, lic, w.tail, w.email, 'open', dev);
  const who = { label: w.email || w.name || 'מנוי', tail: w.tail };
  return { ok: true, iid, name: w.name, email: w.email, plan: w.plan, expires: (j.license_key && j.license_key.expires_at) || null, html: stamp(await appHtml(env, b.lang), who) };
}

async function app(env, b) {
  const v = await validate(env, b, APP_CHECK_MS);
  if (!v.ok) return v;
  // log one "open" per device per hour at most
  const last = await env.DB.prepare("SELECT t FROM events WHERE lic=?1 AND ev='open' ORDER BY t DESC LIMIT 1").bind(v.lic).first();
  if (!last || Date.now() - last.t > 3600e3) await log(env, v.lic, v.who.tail, v.who.label, 'open', b.dev);
  return { ok: true, guest: !!v.who.guest, until: v.who.until || null, html: stamp(await appHtml(env, b.lang), v.who) };
}

async function ping(env, b) {
  const v = await validate(env, b, REVALIDATE_MS);
  return v.ok ? { ok: true } : v;
}

async function release(env, { key, iid }) {
  if (iid && !isGuest(key)) {
    await lsLicense('deactivate', { license_key: key, instance_id: iid });
    const lic = await sha(key);
    const d = await env.DB.prepare('SELECT label FROM devices WHERE iid=?1').bind(iid).first();
    await env.DB.prepare('DELETE FROM devices WHERE iid=?1').bind(iid).run();
    const u = await env.DB.prepare('SELECT tail, email FROM users WHERE lic=?1').bind(lic).first();
    if (u) await log(env, lic, u.tail, u.email, 'device_removed', d ? d.label : '');
  }
  return { ok: true };
}

// ---------- admin ----------
async function isAdmin(req, env) {
  const h = req.headers.get('Authorization') || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!env.ADMIN_TOKEN || t.length < 16) return false;
  const [a, b] = await Promise.all([sha(t), sha(env.ADMIN_TOKEN)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function subscriptions(env) {
  if (!env.LS_API_KEY || !env.LS_STORE_ID) return null;
  const out = [];
  let url = `${LS}/v1/subscriptions?filter[store_id]=${encodeURIComponent(env.LS_STORE_ID)}&page[size]=100`;
  for (let i = 0; i < 20 && url; i++) {
    const r = await fetch(url, { headers: { Accept: 'application/vnd.api+json', Authorization: `Bearer ${env.LS_API_KEY}` } });
    if (!r.ok) return null;
    const j = await r.json();
    for (const s of j.data || []) {
      const a = s.attributes || {};
      if (env.LS_PRODUCT_ID && String(a.product_id) !== String(env.LS_PRODUCT_ID)) continue;
      out.push({ email: a.user_email || '', name: a.user_name || '', status: a.status, trial_ends_at: a.trial_ends_at, renews_at: a.renews_at, ends_at: a.ends_at, created_at: a.created_at });
    }
    url = j.links && j.links.next ? j.links.next : null;
  }
  return out;
}

async function stats(env) {
  const now = Date.now();
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Jerusalem', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(now)).map(x => [x.type, x.value]));
  const todayStart = now - ((+p.hour * 3600 + +p.minute * 60 + +p.second) * 1000 + (now % 1000));
  const users = (await env.DB.prepare('SELECT lic, tail, email, name, status, first_seen, last_seen, expires_at, ended_at FROM users ORDER BY last_seen DESC LIMIT 500').all()).results || [];
  const devs = (await env.DB.prepare('SELECT lic, label, last_seen, ver FROM devices').all()).results || [];
  const evs = (await env.DB.prepare('SELECT t, lic, tail, email, ev, detail FROM events ORDER BY t DESC LIMIT 1500').all()).results || [];
  const guests = (await env.DB.prepare('SELECT h, tail, name, created, expires, revoked, last_seen FROM guests ORDER BY created DESC LIMIT 200').all()).results || [];
  const byLic = {}, evBy = {};
  for (const d of devs) (byLic[d.lic] = byLic[d.lic] || []).push(d);
  for (const e of evs) { const L = (evBy[e.lic] = evBy[e.lic] || []); if (L.length < 30) L.push({ t: e.t, ev: e.ev, detail: e.detail }); }
  const subs = await subscriptions(env);
  const subBy = {};
  if (subs) for (const s of subs) { const k = s.email.toLowerCase(); if (!subBy[k] || s.created_at > subBy[k].created_at) subBy[k] = s; }
  const rows = users.map(u => {
    const ds = byLic[u.lic] || [];
    const last = Math.max(u.last_seen || 0, ...ds.map(d => d.last_seen || 0));
    const s = subBy[(u.email || '').toLowerCase()];
    return {
      email: u.email, name: u.name, tail: u.tail,
      sub: s ? s.status : (u.status === 'expired' || u.status === 'disabled' ? u.status : null),
      valid: !(u.status === 'expired' || u.status === 'disabled'),
      trial_ends_at: s ? s.trial_ends_at : null, renews_at: s ? s.renews_at : null, ends_at: s ? s.ends_at : null,
      ended_at: u.ended_at || null, expires_at: u.expires_at || null,
      versions: [...new Set(ds.map(d => d.ver).filter(Boolean))],
      devices: ds.length, online: now - last < ONLINE_MS, last_seen: last, first_seen: u.first_seen,
      log: evBy[u.lic] || [],
    };
  });
  const g = guests.map(x => ({ tail: x.tail, name: x.name, created: x.created, expires: x.expires, revoked: !!x.revoked, active: !x.revoked && now < x.expires, last_seen: x.last_seen, online: x.last_seen && now - x.last_seen < ONLINE_MS, log: evBy[x.h] || [] }));
  const count = st => subs ? subs.filter(s => st.includes(s.status)).length : null;
  return {
    ok: true, at: now,
    online: rows.filter(r => r.online).length + g.filter(x => x.online).length,
    today: rows.filter(r => r.last_seen >= todayStart).length + g.filter(x => x.last_seen >= todayStart).length,
    known: rows.length,
    trial: count(['on_trial']), paying: count(['active', 'past_due']), cancelled: count(['cancelled', 'expired', 'unpaid', 'paused']),
    subs_available: !!subs,
    users: rows, guests: g,
    recent: evs.slice(0, 60).map(e => ({ t: e.t, tail: e.tail, who: e.email, ev: e.ev, detail: e.detail })),
  };
}

// ---------- usage: who opens the app, who installed it, who is online ----------
const ONLINE_HIT_MS = 150 * 1000;  // the app sends a heartbeat every minute while it is open
const KINDS = ['site', 'share', 'admin', 'pro', 'guest'];
const clean = (v, n) => String(v == null ? '' : v).replace(/[<>\u0000-\u001f]/g, '').slice(0, n);
function ilDay(t) { return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Jerusalem' }).format(new Date(t)); }
function ilOff(t) { const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Jerusalem', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(t)).map(x => [x.type, x.value])); return Date.UTC(+p.year, p.month - 1, +p.day, +p.hour, +p.minute) - Math.floor(t / 60000) * 60000; }
function ilStart(day) { const g = Date.parse(day + 'T00:00:00Z'); return g - ilOff(g); }
async function hit(env, b, req) {
  const did = clean(b.did, 40);
  if (!/^[A-Za-z0-9-]{12,40}$/.test(did)) return { ok: false, reason: 'bad_request' };
  const kind = KINDS.includes(b.kind) ? b.kind : 'site';
  const now = Date.now(), inst = b.installed ? 1 : 0;
  const prev = await env.DB.prepare('SELECT installed FROM clients WHERE did=?1').bind(did).first();
  await env.DB.prepare(
    `INSERT INTO clients (did, kind, who, ver, dev, first_seen, last_seen, installed, installed_at, hits, country) VALUES (?1,?2,?3,?4,?5,?6,?6,?7,CASE WHEN ?7=1 THEN ?6 END,1,?8)
     ON CONFLICT(did) DO UPDATE SET kind=?2, who=CASE WHEN ?3<>'' THEN ?3 ELSE who END, ver=?4, dev=?5, last_seen=?6,
       installed=MAX(installed, ?7), installed_at=COALESCE(installed_at, CASE WHEN ?7=1 THEN ?6 END), hits=hits+1, country=?8`
  ).bind(did, kind, clean(b.who, 60), clean(b.ver, 16), clean(b.dev, 40), now, inst, clean(req.headers.get('CF-IPCountry'), 4)).run();
  await env.DB.prepare('INSERT OR IGNORE INTO daily (day, did, kind) VALUES (?1,?2,?3)').bind(ilDay(now), did, kind).run();
  if (inst && !(prev && prev.installed)) await env.DB.prepare('INSERT INTO usage_log (t, did, kind, ev) VALUES (?1,?2,?3,?4)').bind(now, did, kind, 'installed').run();
  if (!prev) await env.DB.prepare('INSERT INTO usage_log (t, did, kind, ev) VALUES (?1,?2,?3,?4)').bind(now, did, kind, 'first_open').run();
  return { ok: true };
}

// ---------- error log: every JavaScript error in the app, grouped by message ----------
async function errLog(env, b) {
  const did = clean(b.did, 40), msg = clean(b.msg, 300);
  if (!msg || !/^[A-Za-z0-9-]{12,40}$/.test(did)) return { ok: false, reason: 'bad_request' };
  const now = Date.now(), day = ilDay(now);
  const src = clean(b.src, 160), line = Math.max(0, Math.floor(+b.line || 0));
  const sig = (await sha(msg + '|' + src.replace(/\?.*$/, '') + '|' + line + '|' + clean(b.ver, 16))).slice(0, 24);
  const mine = await env.DB.prepare('SELECT COUNT(*) AS n FROM errors WHERE day=?1 AND last_did=?2').bind(day, did).first();
  if (mine && mine.n > 40) return { ok: true, capped: true };
  await env.DB.prepare(
    `INSERT INTO errors (sig, day, first_t, last_t, n, devices, msg, src, line, ver, kind, page, dev, stack, last_did) VALUES (?1,?2,?3,?3,1,1,?4,?5,?6,?7,?8,?9,?10,?11,?12)
     ON CONFLICT(sig, day) DO UPDATE SET last_t=?3, n=n+1, devices=devices+CASE WHEN last_did<>?12 THEN 1 ELSE 0 END, page=?9, dev=?10, last_did=?12`
  ).bind(sig, day, now, msg, src, line, clean(b.ver, 16), KINDS.includes(b.kind) ? b.kind : 'site', clean(b.page, 40), clean(b.dev, 40), clean(b.stack, 600), did).run();
  if (Math.random() < 0.01) await env.DB.prepare('DELETE FROM errors WHERE last_t < ?1').bind(now - 60 * 864e5).run();
  return { ok: true };
}
async function errList(env, q) {
  const days = Math.min(60, Math.max(1, +q.get('days') || 7));
  const rows = (await env.DB.prepare('SELECT sig, day, first_t, last_t, n, devices, msg, src, line, ver, kind, page, dev, stack FROM errors WHERE last_t >= ?1 ORDER BY last_t DESC LIMIT 300')
    .bind(Date.now() - days * 864e5).all()).results || [];
  return { ok: true, days, rows };
}
async function errClear(env) { await env.DB.prepare('DELETE FROM errors').run(); return { ok: true }; }

// ---------- payments (Lemon Squeezy webhook + one-time sync) ----------
function hex(buf) { return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function lsWebhook(env, req) {
  if (!env.LS_WEBHOOK_SECRET) return { ok: false, reason: 'not_configured' };
  const raw = await req.text();
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.LS_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const want = hex(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(raw)));
  const got = String(req.headers.get('X-Signature') || '').toLowerCase();
  let diff = want.length ^ got.length;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ (got.charCodeAt(i) || 0);
  if (diff) throw { reason: 'bad_signature', status: 401 };
  let j; try { j = JSON.parse(raw); } catch (e) { throw { reason: 'bad_request', status: 400 }; }
  const ev = j.meta && j.meta.event_name, d = j.data || {};
  if (d.type === 'subscriptions') await saveSub(env, d);
  else if (d.type === 'subscription-invoices') await saveInvoice(env, d);
  else if (d.type === 'orders' && /refund/.test(ev || '')) await env.DB.prepare("UPDATE payments SET status='refunded' WHERE order_id=?1").bind(String(d.id)).run();
  await env.DB.prepare('INSERT INTO usage_log (t, did, kind, ev) VALUES (?1,?2,?3,?4)').bind(Date.now(), String(d.id || ''), 'ls', clean(ev, 40)).run();
  return { ok: true };
}
const ts = v => (v ? Date.parse(v) || null : null);
async function saveSub(env, d) {
  const a = d.attributes || {};
  if (env.LS_STORE_ID && String(a.store_id) !== String(env.LS_STORE_ID)) return;
  if (env.LS_PRODUCT_ID && String(a.product_id) !== String(env.LS_PRODUCT_ID)) return;
  await env.DB.prepare(
    `INSERT INTO subs (id, email, name, plan, status, created, renews_at, ends_at, trial_ends_at, test, order_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
     ON CONFLICT(id) DO UPDATE SET email=?2, name=?3, plan=?4, status=?5, renews_at=?7, ends_at=?8, trial_ends_at=?9, test=?10`
  ).bind(String(d.id), clean(a.user_email, 120), clean(a.user_name, 120), clean(a.variant_name || a.product_name, 80), clean(a.status, 20),
    ts(a.created_at) || Date.now(), ts(a.renews_at), ts(a.ends_at), ts(a.trial_ends_at), a.test_mode ? 1 : 0, String(a.order_id || '')).run();
}
async function saveInvoice(env, d) {
  const a = d.attributes || {};
  if (env.LS_STORE_ID && String(a.store_id) !== String(env.LS_STORE_ID)) return;
  const sub = await env.DB.prepare('SELECT plan, order_id FROM subs WHERE id=?1').bind(String(a.subscription_id || '')).first();
  const st = a.refunded ? 'refunded' : clean(a.status, 20);
  await env.DB.prepare(
    `INSERT INTO payments (id, t, sub_id, order_id, customer, email, plan, reason, amount, refunded_amount, currency, status, test, ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
     ON CONFLICT(id) DO UPDATE SET status=?12, refunded_amount=?10, customer=?5, email=?6, plan=CASE WHEN ?7<>'' THEN ?7 ELSE plan END`
  ).bind('inv_' + d.id, ts(a.created_at) || Date.now(), String(a.subscription_id || ''), sub ? sub.order_id : '',
    clean(a.user_name, 120), clean(a.user_email, 120), sub ? sub.plan : '', clean(a.billing_reason, 20),
    Math.round(+a.total || 0), Math.round(+a.refunded_amount || 0), clean(a.currency || 'ILS', 3).toUpperCase(), st, a.test_mode ? 1 : 0,
    clean((a.urls && a.urls.invoice_url) ? ('#' + d.id) : d.id, 40)).run();
}
async function lsGetAll(env, path) {
  const out = [];
  let url = `${LS}/v1/${path}?filter[store_id]=${encodeURIComponent(env.LS_STORE_ID)}&page[size]=100`;
  for (let i = 0; i < 50 && url; i++) {
    const r = await fetch(url, { headers: { Accept: 'application/vnd.api+json', Authorization: `Bearer ${env.LS_API_KEY}` } });
    if (!r.ok) throw { reason: 'ls_unavailable', status: 503 };
    const j = await r.json();
    out.push(...(j.data || []));
    url = j.links && j.links.next ? j.links.next : null;
  }
  return out;
}
async function lsSync(env) {
  if (!env.LS_API_KEY || !env.LS_STORE_ID) return { ok: false, reason: 'no_api_key' };
  const subs = await lsGetAll(env, 'subscriptions');
  for (const d of subs) await saveSub(env, d);
  const inv = await lsGetAll(env, 'subscription-invoices');
  for (const d of inv) await saveInvoice(env, d);
  return { ok: true, subs: subs.length, invoices: inv.length };
}
function payWhere(q) {
  const w = [], v = [];
  const test = q.get('test') || 'live';
  if (test === 'live') w.push('test=0'); else if (test === 'test') w.push('test=1');
  const st = q.get('status') || '';
  if (st === 'paid') w.push("status='paid'"); else if (st === 'refunded') w.push("status IN ('refunded','partial_refund')"); else if (st === 'other') w.push("status NOT IN ('paid','refunded','partial_refund')");
  const m = /^\d{4}-\d{2}$/.test(q.get('month') || '') ? q.get('month') : '';
  if (m) { const [y, mo] = m.split('-').map(Number); v.push(ilStart(m + '-01'), ilStart(new Date(Date.UTC(y, mo, 1)).toISOString().slice(0, 10))); w.push(`t >= ?${v.length - 1} AND t < ?${v.length}`); }
  const s = String(q.get('q') || '').trim().slice(0, 60);
  if (s) { v.push('%' + s.replace(/[%_]/g, '') + '%'); w.push(`(customer LIKE ?${v.length} OR email LIKE ?${v.length} OR plan LIKE ?${v.length} OR ref LIKE ?${v.length})`); }
  return { sql: w.length ? ' WHERE ' + w.join(' AND ') : '', v };
}
const SORTS = { t_desc: 't DESC', t_asc: 't ASC', amount_desc: 'amount DESC', amount_asc: 'amount ASC', name: 'customer COLLATE NOCASE ASC' };
async function payList(env, q, all) {
  const { sql, v } = payWhere(q);
  const order = SORTS[q.get('sort')] || 't DESC';
  const size = all ? 5000 : Math.min(200, Math.max(10, +q.get('size') || 50));
  const page = all ? 1 : Math.max(1, Math.floor(+q.get('page') || 1));
  const cols = 'id, t, customer, email, plan, reason, amount, refunded_amount, currency, status, test, ref';
  const rows = (await env.DB.prepare(`SELECT ${cols} FROM payments${sql} ORDER BY ${order} LIMIT ${size} OFFSET ${(page - 1) * size}`).bind(...v).all()).results || [];
  const tot = (await env.DB.prepare(`SELECT currency, COUNT(*) AS n, SUM(CASE WHEN status IN ('paid','partial_refund') THEN amount - refunded_amount ELSE 0 END) AS net, SUM(refunded_amount) AS refunded, COUNT(DISTINCT LOWER(email)) AS customers FROM payments${sql} GROUP BY currency`).bind(...v).all()).results || [];
  const count = tot.reduce((s, x) => s + x.n, 0);
  return { ok: true, page, size, count, pages: Math.max(1, Math.ceil(count / size)), totals: tot, rows };
}

// ---------- overview: the numbers at the top of the admin dashboard ----------
async function overview(env, q) {
  const now = Date.now(), days = Math.min(90, Math.max(7, +q.get('days') || 30)), T = q.get('test') === '1' ? 1 : 0;
  const today = ilDay(now), from = ilDay(now - (days - 1) * 864e5);
  const one = async (sql, ...v) => ((await env.DB.prepare(sql).bind(...v).first()) || {});
  const on = (await env.DB.prepare('SELECT kind, COUNT(*) AS n FROM clients WHERE last_seen >= ?1 GROUP BY kind').bind(now - ONLINE_HIT_MS).all()).results || [];
  const onlineList = (await env.DB.prepare('SELECT kind, who, dev, ver, installed, last_seen, country FROM clients WHERE last_seen >= ?1 ORDER BY last_seen DESC LIMIT 100').bind(now - ONLINE_HIT_MS).all()).results || [];
  const all = await one('SELECT COUNT(*) AS users, SUM(installed) AS installs FROM clients');
  const todayN = await one('SELECT COUNT(*) AS n FROM daily WHERE day=?1', today);
  const week = await one('SELECT COUNT(DISTINCT did) AS n FROM daily WHERE day >= ?1', ilDay(now - 6 * 864e5));
  const newToday = await one('SELECT COUNT(*) AS n FROM clients WHERE first_seen >= ?1', ilStart(today));
  const byKind = (await env.DB.prepare('SELECT kind, COUNT(*) AS n, SUM(installed) AS inst FROM clients GROUP BY kind').all()).results || [];
  const chartA = (await env.DB.prepare('SELECT day, COUNT(*) AS n FROM daily WHERE day >= ?1 GROUP BY day').bind(from).all()).results || [];
  const chartN = (await env.DB.prepare('SELECT first_seen, installed_at FROM clients WHERE first_seen >= ?1 OR installed_at >= ?1').bind(now - days * 864e5).all()).results || [];
  const chartP = (await env.DB.prepare("SELECT t, amount - refunded_amount AS net FROM payments WHERE test=?2 AND status IN ('paid','partial_refund') AND t >= ?1").bind(now - days * 864e5, T).all()).results || [];
  const series = {};
  for (let i = days - 1; i >= 0; i--) series[ilDay(now - i * 864e5)] = { active: 0, new: 0, installs: 0, revenue: 0 };
  for (const r of chartA) if (series[r.day]) series[r.day].active = r.n;
  for (const r of chartN) { const a = series[ilDay(r.first_seen)]; if (a && r.first_seen >= now - days * 864e5) a.new++; if (r.installed_at) { const b = series[ilDay(r.installed_at)]; if (b) b.installs++; } }
  for (const r of chartP) { const a = series[ilDay(r.t)]; if (a) a.revenue += r.net || 0; }
  const subs = (await env.DB.prepare('SELECT status, plan, test FROM subs').all()).results || [];
  const live = subs.filter(s => (s.test ? 1 : 0) === T), test = subs.filter(s => s.test);
  const cnt = (L, st) => L.filter(s => st.includes(s.status)).length;
  const monthStart = ilStart(today.slice(0, 8) + '01'), yearStart = ilStart(today.slice(0, 5) + '01-01');
  const rev = async (from, t) => (await env.DB.prepare(`SELECT currency, SUM(amount - refunded_amount) AS net, COUNT(*) AS n FROM payments WHERE test=?2 AND status IN ('paid','partial_refund') AND t >= ?1 GROUP BY currency`).bind(from, t).all()).results || [];
  const errs = await one('SELECT COUNT(*) AS groups, SUM(n) AS n FROM errors WHERE last_t >= ?1', now - 864e5);
  return {
    ok: true, at: now, days,
    online: on.reduce((s, x) => s + x.n, 0), onlineByKind: on, onlineList,
    users: all.users || 0, installs: all.installs || 0, today: todayN.n || 0, week: week.n || 0, newToday: newToday.n || 0, byKind,
    series: Object.entries(series).map(([day, x]) => ({ day, ...x })),
    trial: cnt(live, ['on_trial']), paying: cnt(live, ['active', 'past_due']), cancelled: cnt(live, ['cancelled', 'expired', 'unpaid', 'paused']), signups: live.length,
    testSubs: test.length,
    test: T, revMonth: await rev(monthStart, T), revYear: await rev(yearStart, T), revAll: await rev(0, T), revTest: await rev(0, 1),
    webhook: !!env.LS_WEBHOOK_SECRET, api: !!env.LS_API_KEY,
    errors24: errs.n || 0, errorGroups24: errs.groups || 0,
  };
}
