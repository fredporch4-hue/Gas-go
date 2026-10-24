#!/usr/bin/env node
/* Gas Buddy signalling (WebRTC) - used by test-server.js, or run standalone.
 * Routes signalling between PROFILE ids (customer "GB-12345", vendor "V-1234"). Phone numbers and audio never reach it:
 * media flows peer-to-peer (or via your TURN relay).
 * Standalone: npm install && node signal-server.js   (PORT=8787; the demo hooks below trust any claimed id)
 * Env: PORT, ALLOWED_ORIGINS (comma list; empty = any), TURN_URL, TURN_USER, TURN_PASS */
const http = require('http');
const { WebSocketServer } = require('ws');

const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const ID_RE = /^[A-Za-z0-9_-]{1,40}$/;
const TYPES = new Set(['invite', 'accept', 'decline', 'offer', 'answer', 'ice', 'hangup']);

function iceServers() {
  const s = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URL) s.push({ urls: process.env.TURN_URL, username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  return s;   // production: issue short-lived TURN credentials per user instead of a static pair
}

/* hooks.authenticate(id, token) -> bool : does this token belong to profile `id`?
 * hooks.canCall(from, to, orderId) -> bool : do both profiles share an active order? */
function attach(server, hooks = {}) {
  const authenticate = hooks.authenticate || (() => true);
  const canCall = hooks.canCall || (() => true);
  const peers = new Map();   // profile id -> socket
  const calls = new Map();   // callId -> { a: caller id, b: callee id }
  const clean = d => ({ name: String((d && d.name) || '').slice(0, 60), reason: String((d && d.reason) || '').slice(0, 60) });
  const send = (ws, o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
  const inCall = id => [...calls.values()].some(c => c.a === id || c.b === id);
  function endCallsOf(id, reason) {
    for (const [cid, c] of calls) if (c.a === id || c.b === id) {
      send(peers.get(c.a === id ? c.b : c.a), { type: 'hangup', callId: cid, reason });
      calls.delete(cid);
    }
  }
  const wss = new WebSocketServer({
    server, maxPayload: 64 * 1024,
    verifyClient: ({ origin }) => !ORIGINS.length || ORIGINS.includes(origin),
  });

  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'http://x'), id = u.searchParams.get('id') || '';
    if (!ID_RE.test(id) || !authenticate(id, u.searchParams.get('token') || '')) return ws.close(4401, 'unauthorized');
    const old = peers.get(id);
    peers.set(id, ws); if (old) old.close(4000, 'replaced');
    ws.isAlive = true; ws.budget = 100;
    send(ws, { type: 'ready', id });
    ws.on('pong', () => { ws.isAlive = true; });
    ws.on('message', raw => {
      if (--ws.budget < 0) return;
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (!m || !TYPES.has(m.type) || typeof m.callId !== 'string' || m.callId.length > 64) return;
      const c = calls.get(m.callId);
      if (m.type === 'invite') {
        const to = String(m.to || '');
        if (!ID_RE.test(to) || to === id || c || !canCall(id, to, m.order)) return send(ws, { type: 'hangup', callId: m.callId, reason: 'not-allowed' });
        if (!peers.has(to)) return send(ws, { type: 'hangup', callId: m.callId, reason: 'unavailable' });
        if (inCall(to) || inCall(id)) return send(ws, { type: 'hangup', callId: m.callId, reason: 'busy' });
        calls.set(m.callId, { a: id, b: to });
        return send(peers.get(to), { type: 'invite', callId: m.callId, from: id, data: clean(m.data) });
      }
      if (!c || (c.a !== id && c.b !== id)) return;                       // only call participants may signal
      if (['accept', 'decline', 'answer'].includes(m.type) && id !== c.b) return;   // callee only
      if (m.type === 'offer' && id !== c.a) return;                       // caller only
      const data = ['offer', 'answer', 'ice'].includes(m.type) ? m.data : clean(m.data);
      send(peers.get(c.a === id ? c.b : c.a), { type: m.type, callId: m.callId, from: id, data });
      if (m.type === 'decline' || m.type === 'hangup') calls.delete(m.callId);
    });
    ws.on('close', () => { if (peers.get(id) === ws) { peers.delete(id); endCallsOf(id, 'disconnected'); } });
  });

  setInterval(() => wss.clients.forEach(w => { w.budget = 100; }), 5000);
  setInterval(() => wss.clients.forEach(w => { if (!w.isAlive) return w.terminate(); w.isAlive = false; w.ping(); }), 25000);
  return wss;
}

module.exports = { attach, iceServers };

if (require.main === module) {
  const PORT = +process.env.PORT || 8787;
  const server = http.createServer((req, res) => {
    const h = { 'content-type': 'application/json', 'access-control-allow-origin': '*' };
    if (req.url === '/health') { res.writeHead(200, h); return res.end('{"ok":true,"signalling":true}'); }
    if (req.url === '/ice') { res.writeHead(200, h); return res.end(JSON.stringify({ iceServers: iceServers() })); }
    res.writeHead(404); res.end();
  });
  attach(server);
  server.listen(PORT, () => console.log(`Gas Buddy signalling on :${PORT}  (ws, /health, /ice)`));
}
