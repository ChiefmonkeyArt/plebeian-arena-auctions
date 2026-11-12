// v0.5.0 checks (no network): remote signers (ADR 0010), the profile reader
// against a stand-in relay, and the parody catalogue against the chain's
// listing rules. Usage: node web/test/login.mjs
import { existsSync } from 'node:fs';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { ArenaClient } from '../src/lib/arena.js';
import { CATALOGUE, PARODY, randomLot } from '../src/lib/catalogue.js';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  PASS', m); } else { fail++; console.log('  FAIL', m); } };

// --- remote signing ---
const sk = generateSecretKey(), pk = getPublicKey(sk);
const api = new ArenaClient('http://x');
const you = { name: 'You', pubkey: pk, walletSk: '11'.repeat(32) };
try { await api.signEvent(you, { kind: 1, created_at: 1, tags: [], content: '' }); ok(false, 'no signer refused'); }
catch (e) { ok(/log in again/.test(e.message), 'a login with no signer is refused'); }
api.signers.set(pk, async (t) => finalizeEvent(t, sk));
const ev = await api.sign(you, 1441, { a: 1 });
ok(ev.pubkey === pk && ev.kind === 1441 && JSON.parse(ev.content).a === 1, 'bids are signed by the remote signer');
api.signers.set(pk, async (t) => finalizeEvent(t, generateSecretKey()));
try { await api.sign(you, 1441, {}); ok(false, 'wrong key refused'); }
catch (e) { ok(/another key/.test(e.message), 'a signer that answers with another key is refused'); }

// --- profile reader, stand-in relay ---
const k10002 = finalizeEvent({ kind: 10002, created_at: 100, tags: [['r', 'wss://write.example'], ['r', 'wss://read.example', 'read']], content: '' }, sk);
const goodK0 = finalizeEvent({ kind: 0, created_at: 200, tags: [], content: JSON.stringify({ name: 'Satoshi\u202e' + 'x'.repeat(60), picture: 'https://img.example/a.png' }) }, sk);
const badK0 = { ...finalizeEvent({ kind: 0, created_at: 300, tags: [], content: JSON.stringify({ name: 'Forged', picture: 'https://evil/x.png' }) }, sk), content: JSON.stringify({ name: 'Tampered' }) };
const jsK0 = finalizeEvent({ kind: 0, created_at: 150, tags: [], content: JSON.stringify({ name: 'Old', picture: 'javascript:alert(1)' }) }, sk);
const opened = [];
globalThis.WebSocket = class {
  constructor(url) { this.url = url; opened.push(url); setTimeout(() => this.onopen?.(), 1); }
  send(m) {
    const [, sub, f] = JSON.parse(m);
    const out = f.kinds[0] === 10002 ? (this.url === 'wss://relay.chiefmonkey.art' ? [k10002] : [])
      : this.url === 'wss://write.example' ? [goodK0, badK0, jsK0] : [jsK0];
    setTimeout(() => { for (const e of out) this.onmessage?.({ data: JSON.stringify(['EVENT', sub, e]) }); this.onmessage?.({ data: JSON.stringify(['EOSE', sub]) }); }, 2);
  }
  close() { this.onclose?.(); }
};
const { fetchProfile } = await import('../src/lib/login.js');
const p = await fetchProfile(pk, ['wss://signer.example', 'http://not-wss.example']);
ok(p && p.name.startsWith('Satoshi') && !p.name.includes('\u202e') && p.name.length <= 40, 'name from the newest verified kind 0, cleaned and capped at 40');
ok(p.picture === 'https://img.example/a.png', 'a tampered newer event is ignored (signature checked)');
ok(opened.includes('wss://write.example') && !opened.includes('wss://read.example'), 'kind 0 is read from the write relays in kind 10002');
ok(!opened.some((u) => u.startsWith('http')), 'only wss relays are opened');
ok(new Set(opened).size <= 12, 'at most 6 relays per round');
globalThis.WebSocket = class { constructor(u) { this.u = u; setTimeout(() => this.onopen?.(), 1); } send(m) { const [, s] = JSON.parse(m); setTimeout(() => { this.onmessage?.({ data: JSON.stringify(['EVENT', s, jsK0]) }); this.onmessage?.({ data: JSON.stringify(['EOSE', s]) }); }, 2); } close() { this.onclose?.(); } };
const q = await fetchProfile(pk, [], ['wss://a.example']);
ok(q && q.picture === '' && q.name === 'Old', 'a non-https picture is dropped');

// --- catalogue vs the chain's listing rules ---
ok(CATALOGUE.length >= 20 && PARODY === 'Parody · fake sats', `${CATALOGUE.length} parody lots, labelled`);
ok(CATALOGUE.every((c) => c.title.length <= 120 && c.name.length <= 40 && c.startPrice > 0 && c.minIncrement > 0), 'titles ≤ 120, names ≤ 40, prices set');
ok(CATALOGUE.every((c) => /^\.\/assets\/merch\/[a-z]+\.webp$/.test(c.image) && existsSync(new URL('../public' + c.image.slice(1), import.meta.url))), 'every image is a bundled same-site WebP');
let good = true;
for (let i = 0; i < 300; i++) {
  const f = randomLot('fixed'), a = randomLot('antisnipe');
  good &&= f.mode === 'fixed' && f.windowSec === undefined && f.durationSec >= 120 && f.durationSec <= 360;
  good &&= a.mode === 'antisnipe' && a.windowSec >= 20 && a.windowSec <= 120 && a.durationSec >= 120 && a.durationSec <= 360;
}
ok(good, 'random lots: fixed 2-6 min without a window; anti-snipe window 20-120 s');

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
