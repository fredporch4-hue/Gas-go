#!/usr/bin/env node
/* Gas Buddy TEST SERVER: serves the app, the JSON-file API the app expects in shared-database mode, and WebRTC
 * signalling, all on ONE port, so a single HTTPS tunnel link works on every device.
 *   npm install && npm start            ->  http://localhost:3000
 * Data lives in data.json (delete it, or `npm run reset`, to start fresh). Env: PORT, DATA_FILE, APP_FILE.
 * TEST ONLY: wallet balances and app state are held by the client, there is no payment, email or SMS, and nothing
 * here is hardened for the public internet. What it DOES enforce: passwords are scrypt-hashed, every API call needs
 * a session token, users only see their own orders, vendor phones/bank details are private, delivery codes are
 * checked here (never sent to vendors), and calls are only allowed between the two sides of an order. */
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { attach, iceServers } = require('./signal-server');

const PORT = +process.env.PORT || 3000;
/* The app page: APP_FILE, else Gas_Buddy5.html next to this file, else any .html file in this folder (index.html first),
 * so a renamed upload such as "Gas_Buddy5 (1).html" still works. */
function appFile() {
  if (process.env.APP_FILE) return process.env.APP_FILE;
  const want = path.join(__dirname, 'Gas_Buddy5.html');
  if (fs.existsSync(want)) return want;
  try {
    const f = fs.readdirSync(__dirname).filter(n => /\.html?$/i.test(n)).sort((a, b) => (b === 'index.html') - (a === 'index.html'))[0];
    if (f) return path.join(__dirname, f);
  } catch {}
  return want;
}
const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
let db = { users: [], vendors: [], jobs: [], states: {}, hw: {}, sessions: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch {}
let wt = null;
const save = () => { clearTimeout(wt); wt = setTimeout(() => fs.writeFile(FILE + '.tmp', JSON.stringify(db), e => { if (!e) fs.rename(FILE + '.tmp', FILE, () => {}); }), 150); };

const digits = p => String(p || '').replace(/\D/g, '');
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
const txt = (s, n) => String(s == null ? '' : s).trim().slice(0, n);
const safe = (s, n) => txt(s, n).replace(/['"`\\<>&]/g, '').trim();   // names end up inside inline handlers: keep them inert
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const pid = u => u.role === 'vendor' ? 'V-' + u.vid : u.id;
const pick = (o, ks) => { const r = {}; ks.forEach(k => { if (k in o) r[k] = o[k]; }); return r; };
const PUBLIC = ['id', 'real', 'n', 'd', 'r', 'rn', 'pk', 't', 'e', 'c', 'a', 'h', 'since', 'o', 'own', 'b', 'rv', 'closed'];
const STATUS = new Set(['new', 'accepted', 'out', 'delivered', 'declined', 'cancelled']);
const userByToken = t => { const id = db.sessions[t]; return id && db.users.find(u => u.id === id); };

function session(u, token) {
  if (!token) { token = crypto.randomBytes(24).toString('hex'); db.sessions[token] = u.id; save(); }
  return { token, user: { id: u.id, role: u.role, name: u.name, phone: u.phone }, state: db.states[u.id] || {}, vendor: u.vid ? db.vendors.find(v => v.id === u.vid) : undefined };
}

function signup(b) {
  const role = b.role, name = safe(b.name, 60), pd = digits(b.phone), pw = String(b.password || '');
  if (!['customer', 'vendor'].includes(role) || !name || pd.length < 7 || pd.length > 15) return [400, { error: 'Enter a valid name and phone number' }];
  if (pw.length < 6 || pw.length > 200) return [400, { error: 'Choose a password of at least 6 characters' }];
  if (db.users.some(u => u.pd === pd)) return [409, { error: 'That phone number is already registered. Please log in.' }];
  const salt = crypto.randomBytes(16).toString('hex');
  const u = { role, name, phone: txt(b.phone, 30), pd, salt, h: hash(pw, salt), joined: Date.now() };
  if (role === 'customer') { do { u.id = 'GB-' + rnd(10000, 99999); } while (db.users.some(x => x.id === u.id)); }
  else {
    const s = b.shop || {}, pk = Math.round(+s.pk), n = safe(s.n, 40), a = txt(s.a, 200);
    if (!n || !a || !(pk >= 100 && pk <= 100000)) return [400, { error: 'Fill in every shop field. Price must be at least ₦100' }];
    let id; do { id = rnd(1000, 999999); } while (db.vendors.some(v => v.id === id));
    db.vendors.push({ id, real: true, n, d: Math.round((0.5 + Math.random() * 2.5) * 10) / 10, r: 4.5, rn: 0, pk, t: ['20 min', '30 min', '45 min'][rnd(0, 2)],
      e: ['🏪', '🛢️', '🔥', '🏠'][id % 4], c: ['#e8590c', '#1c7ed6', '#c92a2a', '#2f9e44', '#7048e8', '#0c8599'][id % 6], a,
      h: txt(s.h, 30) || '7am to 9pm', ph: u.phone, since: new Date().getFullYear(), o: 0, own: name, b: 'New vendor on Gas Buddy.', rv: [], closed: false });
    u.id = 'U' + crypto.randomBytes(5).toString('hex'); u.vid = id;
  }
  db.users.push(u); save();
  return [200, session(u)];
}

const tries = new Map();
function login(b) {
  const pd = digits(b.phone), t = tries.get(pd) || { n: 0, until: 0 };
  if (t.until > Date.now()) return [429, { error: 'Too many wrong attempts. Try again in ' + Math.ceil((t.until - Date.now()) / 60000) + ' minute(s).' }];
  const u = db.users.find(x => x.pd === pd);
  if (!u || !same(hash(String(b.password || ''), u.salt), u.h)) {
    if (++t.n >= 5) { t.until = Date.now() + 300000; t.n = 0; } tries.set(pd, t);
    return [401, { error: 'Wrong phone number or password.' }];
  }
  tries.delete(pd);
  return [200, session(u)];
}

function market(u) {
  const mine = u.role === 'vendor' ? u.vid : null;
  const vendors = db.vendors.map(v => v.id === mine ? v : pick(v, PUBLIC));   // others never see phone, banks or earnings
  const jobs = u.role === 'vendor'
    ? db.jobs.filter(j => j.vid === u.vid).map(j => { const { code, ...r } = j; return r; })   // the delivery code never reaches the vendor
    : db.jobs.filter(j => j.cid === u.id);
  return { vendors, jobs };
}

function mergeChat(old, next, f) {
  const out = Array.isArray(old) ? old.slice() : [];
  if (Array.isArray(next)) next.slice(out.length, out.length + 20).forEach(m => {
    if (m && m.f === f && out.length < 300) out.push({ f, x: txt(m.x, 500), t: +m.t || Date.now() });   // append-only, and you can only speak as yourself
  });
  return out;
}

function ops(u, list) {
  if (!Array.isArray(list) || list.length > 50) return [400, { error: 'Bad request' }];
  for (const op of list) {
    const rec = op && op.rec;
    if (!rec || typeof rec !== 'object') return [400, { error: 'Bad request' }];
    if (op.k === 'vendor') {
      const v = u.role === 'vendor' && rec.id === u.vid && db.vendors.find(x => x.id === u.vid);
      if (!v) return [403, { error: 'Not allowed' }];
      const e = pick(rec, ['pk', 'ph', 'a', 'b', 'h', 'closed', 'auto', 'paid', 'banks']);
      if ('pk' in e) { e.pk = Math.round(+e.pk); if (!(e.pk >= 100 && e.pk <= 100000)) return [400, { error: 'Price must be at least ₦100' }]; }
      ['a', 'h', 'ph'].forEach(k => { if (k in e) e[k] = txt(e[k], 200); }); if ('b' in e) e.b = txt(e.b, 300);
      ['closed', 'auto'].forEach(k => { if (k in e) e[k] = !!e[k]; }); if ('paid' in e) e.paid = Math.max(0, +e.paid || 0);
      if ('banks' in e && JSON.stringify(e.banks).length > 2000) delete e.banks;
      Object.assign(v, e);
    } else if (op.k === 'job') {
      const old = db.jobs.find(j => String(j.jid) === String(rec.jid));
      if (old) {
        if (!(u.role === 'vendor' ? old.vid === u.vid : old.cid === u.id)) return [403, { error: 'Not allowed' }];
        const p = pick(rec, u.role === 'vendor' ? ['st', 'step', 'at'] : ['st', 'step', 'dt']);
        if ('st' in p && (!STATUS.has(p.st) || old.st === 'delivered' || (p.st === 'delivered' && !(old.type === 'valve' && u.role === 'customer')))) delete p.st;   // gas is only confirmed via the code
        if ('step' in p) p.step = Math.min(4, Math.max(0, Math.round(+p.step) || 0));
        if ('at' in p || 'dt' in p) { p.at = +p.at || undefined; p.dt = +p.dt || undefined; }
        old.chat = mergeChat(old.chat, rec.chat, u.role === 'vendor' ? 'v' : 'c');
        Object.assign(old, JSON.parse(JSON.stringify(p)));
      } else {
        const v = db.vendors.find(x => x.id === rec.vid), price = +rec.price;
        if (u.role !== 'customer' || !v || !['gas', 'valve'].includes(rec.type) || !isFinite(price) || price < 0 || !(typeof rec.jid === 'number' || /^\w{1,40}$/.test(rec.jid))) return [400, { error: 'Bad order' }];
        const j = { jid: rec.jid, type: rec.type, cid: u.id, cname: u.name, caddr: txt(rec.caddr, 200), vid: v.id, v: v.n, price, st: 'new', t: +rec.t || Date.now(), att: 0, chat: [] };
        if (rec.type === 'gas') {
          if (!/^\d{4,8}$/.test(String(rec.code))) return [400, { error: 'Bad order' }];
          Object.assign(j, { kg: Math.min(100, Math.max(0.5, +rec.kg || 0)), fee: Math.max(0, +rec.fee || 0), code: String(rec.code) });
        } else Object.assign(j, { feat: Math.max(0, +rec.feat || 0), step: 0 });
        db.jobs.unshift(j);
      }
    } else return [400, { error: 'Bad request' }];
  }
  save();
  return [200, { ok: true }];
}

function checkCode(u, id, code) {
  const j = db.jobs.find(x => String(x.jid) === String(id));
  if (u.role !== 'vendor' || !j || j.vid !== u.vid || j.type !== 'gas' || !['accepted', 'out'].includes(j.st)) return [403, { error: 'Not allowed' }];
  if (j.att >= 3) return [429, { error: 'Too many wrong codes. This order is locked.' }];
  if (same(String(code || ''), j.code)) { j.st = 'delivered'; j.dt = Date.now(); save(); return [200, { ok: true }]; }
  j.att++; save();
  return [200, { ok: false, att: j.att }];
}

function hw(u, kind, id) {
  id = txt(id, 40).toUpperCase();
  if (!id) return [400, { error: 'Invalid hardware ID' }];
  if (kind === 'register') { if (db.hw[id] && db.hw[id] !== u.id) return [409, { error: 'This ID belongs to another profile.' }]; db.hw[id] = u.id; save(); return [200, { ok: true }]; }
  if (!(id in db.hw)) return [404, { error: 'Unknown hardware ID' }];
  if (db.hw[id] !== u.id) return [403, { error: 'This ID belongs to another profile. It cannot be used here.' }];
  return [200, { ok: true }];
}

function body(req) {
  return new Promise((ok, no) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > 300000) { no(new Error('big')); req.destroy(); } else c.push(d); });
    req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c)) : {}); } catch (e) { no(e); } });
  });
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const out = (code, o) => { if (res.headersSent) return res.end(); res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(o)); };
  try {
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      let html;
      try { html = fs.readFileSync(appFile()); }
      catch {
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
        return res.end('The Gas Buddy app file was not found.\nUpload Gas_Buddy5.html into the same folder as test-server.js (looked in: ' + __dirname + ').');
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      return res.end(html);
    }
    if (url === '/health') return out(200, { ok: true, signalling: true });
    if (url === '/ice') return out(200, { iceServers: iceServers() });
    if (!url.startsWith('/api/')) { res.writeHead(404); return res.end(); }
    const b = ['POST', 'PUT'].includes(req.method) ? await body(req) : {};
    if (req.method === 'POST' && url === '/api/auth/signup') return out(...signup(b));
    if (req.method === 'POST' && url === '/api/auth/login') return out(...login(b));
    const tok = (/^Bearer (.+)$/.exec(req.headers.authorization || '') || [])[1], u = userByToken(tok);
    if (!u) return out(401, { error: 'Please log in again' });
    if (req.method === 'GET' && url === '/api/me') return out(200, session(u, tok));
    if (req.method === 'GET' && url === '/api/market') return out(200, market(u));
    if (req.method === 'PUT' && url === '/api/state') {
      if (!b.state || typeof b.state !== 'object') return out(400, { error: 'Bad request' });
      db.states[u.id] = b.state; save(); return out(200, { ok: true });
    }
    if (req.method === 'POST' && url === '/api/market/ops') return out(...ops(u, b.ops));
    let m;
    if (req.method === 'POST' && (m = /^\/api\/jobs\/([^/]+)\/code$/.exec(url))) return out(...checkCode(u, decodeURIComponent(m[1]), b.code));
    if (req.method === 'POST' && (m = /^\/api\/hw\/(register|activate)$/.exec(url))) return out(...hw(u, m[1], b.hw));
    return out(404, { error: 'Not found' });
  } catch (e) { if (res.headersSent) return res.end(); return out(e && e.message === 'big' ? 413 : 400, { error: 'Bad request' }); }
});

attach(server, {
  authenticate: (id, token) => { const u = userByToken(token); return !!u && pid(u) === id; },
  canCall: (from, to, orderId) => db.jobs.some(j => String(j.jid) === String(orderId) &&
    ((from === j.cid && to === 'V-' + j.vid) || (from === 'V-' + j.vid && to === j.cid))),
});
process.on('unhandledRejection', e => console.error('Unhandled:', e));   // never let one bad request take the server down
server.listen(PORT, () => {
  console.log(`Gas Buddy test server: http://localhost:${PORT}   (data: ${FILE})`);
  console.log(fs.existsSync(appFile()) ? `Serving app: ${appFile()}` : `WARNING: app file not found. Upload Gas_Buddy5.html next to test-server.js (folder: ${__dirname})`);
});
