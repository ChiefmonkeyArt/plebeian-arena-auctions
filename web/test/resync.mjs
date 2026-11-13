// v0.5.1: a wallet whose Coco store was lost (counters back at 0, same seed)
// recovers by itself: the mint's "already signed" refusal triggers a NUT-09
// restore, and top-ups, receives and bid locks work again. Needs the local
// stack (./scripts.sh start): node test/resync.mjs [http://127.0.0.1:8080]
import { ArenaClient, newIdentity } from '../src/lib/arena.js';
const base = process.argv[2] || 'http://127.0.0.1:8080';
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('ok  ', m); } else { fail++; console.log('FAIL', m); } };
const id = newIdentity('Resync');
const a = new ArenaClient(base);
ok((await a.faucet(id, 3000)) === 3000, 'first top-up mints 3,000');
await a.close();
// same identity (same seed), empty store: what a browser that lost IndexedDB sees
const b = new ArenaClient(base);
let warned = 0; const w = console.warn; console.warn = (...x) => { if (/restoring/.test(x[0])) warned++; };
const got = await b.faucet(id, 1000).catch((e) => e);
console.warn = w;
ok(typeof got === 'number', `top-up after a lost store works (${got?.message || got})`);
ok(warned === 1, 'the refusal triggered one restore');
ok(got === 4000, 'restore brought back the first 3,000 too: balance 4,000');
await b.close();
// a bid lock and a receive on a store lost again: each restores and goes through
const seller = newIdentity('ResyncSeller');
const cr = await b.createAuction(seller, { title: 'resync test lot', description: '', image: '', category: 'Test', startPrice: 100, minIncrement: 10, durationSec: 30, mode: 'fixed' });
let st, lot;
for (let i = 0; i < 20 && !lot; i++) { await new Promise((r) => setTimeout(r, 250)); st = (await b.view([])).state; lot = st.auctions[cr.id]; }
const c = new ArenaClient(base);
// what the page does on a lost store: the balance reads 0, so it tops up first
ok((await c.balance(id)) === 0, 'a lost store reads 0 sats');
ok((await c.faucet(id, 500)) >= 4500, 'the top-up restores the earlier sats as well');
const { locked } = await c.lockForBid(id, 100, st.params, lot, { force: true, state: st });
ok(locked.length > 0 && locked.reduce((s, p) => s + p.amount, 0) === 100, 'a bid lock works on a lost store');
await c.close();
const other = newIdentity('Other'); const o = new ArenaClient(base);
await o.faucet(other, 200);
const om = await o.coco(other);
const prep = await om.ops.send.prepare({ mintUrl: o.mintUrl, amount: 200 });
const { token } = await om.ops.send.execute(prep);
const d = new ArenaClient(base);
const r = await d.receive(id, token.proofs.map((p) => ({ id: p.id, amount: Number(p.amount), secret: p.secret, C: p.C })));
ok(r === 200, 'receiving ecash works on a lost store');
await o.close(); await d.close();
console.log(`resync: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
