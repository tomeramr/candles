// קורא נרות פרו – שרת רישיונות (Cloudflare Worker)
//
// The paid app is never readable without a valid serial: pro/app.enc on GitHub is encrypted,
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
//   APP_URL         plain, optional: default https://tomeramr.github.io/candles/pro/app.enc

const LS = 'https://api.lemonsqueezy.com';
const REVALIDATE_MS = 60 * 60 * 1000;   // light check (ping): ask Lemon Squeezy at most once an hour
const APP_CHECK_MS = 10 * 60 * 1000;    // opening the app: re-check if the last check is older than 10 min
const ONLINE_MS = 5 * 60 * 1000;
const LIMITS = { unlock: 8, app: 12, ping: 30, release: 10, admin: 60 }; // requests per minute per IP
let APP_CACHE = null; // {at, html}

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
      if (path.startsWith('/admin/')) {
        if (!(await isAdmin(req, env))) return json({ ok: false, reason: 'unauthorized' }, 401);
        if (req.method === 'GET' && path === '/admin/stats') return json(await stats(env));
        if (req.method === 'POST' && path === '/admin/guest') return json(await guestCreate(env, await req.json().catch(() => ({}))));
        if (req.method === 'POST' && path === '/admin/guest/revoke') return json(await guestRevoke(env, await req.json().catch(() => ({}))));
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

// ---------- the app itself ----------
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function appHtml(env) {
  if (APP_CACHE && Date.now() - APP_CACHE.at < 10 * 60 * 1000) return APP_CACHE.html;
  const url = (env.APP_URL || 'https://tomeramr.github.io/candles/pro/app.enc') + '?t=' + Math.floor(Date.now() / 600000);
  const r = await fetch(url, { cf: { cacheTtl: 300 } });
  if (!r.ok) throw { reason: 'server_error', status: 502 };
  const e = await r.json();
  const key = await crypto.subtle.importKey('raw', b64d(env.CONTENT_KEY), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(e.iv) }, key, b64d(e.ct));
  const html = await new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  APP_CACHE = { at: Date.now(), html };
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
    return { ok: true, iid: '', name: v.who.label, guest: true, until: v.who.until, html: stamp(await appHtml(env), v.who) };
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
  return { ok: true, iid, name: w.name, email: w.email, plan: w.plan, expires: (j.license_key && j.license_key.expires_at) || null, html: stamp(await appHtml(env), who) };
}

async function app(env, b) {
  const v = await validate(env, b, APP_CHECK_MS);
  if (!v.ok) return v;
  // log one "open" per device per hour at most
  const last = await env.DB.prepare("SELECT t FROM events WHERE lic=?1 AND ev='open' ORDER BY t DESC LIMIT 1").bind(v.lic).first();
  if (!last || Date.now() - last.t > 3600e3) await log(env, v.lic, v.who.tail, v.who.label, 'open', b.dev);
  return { ok: true, guest: !!v.who.guest, until: v.who.until || null, html: stamp(await appHtml(env), v.who) };
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
