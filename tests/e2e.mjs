// End-to-end acceptance run against the live 4-validator chain and fake-sats mint.
// Usage: node tests/e2e.mjs [http://127.0.0.1:8080]
import { ArenaClient, newIdentity, idPub, totalSats } from '../web/src/lib/arena.js';

const BASE = process.argv[2] || 'http://127.0.0.1:8080';
const c = new ArenaClient(BASE);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; console.log('  PASS', msg); } else { fail++; console.log('  FAIL', msg); } };
const step = (n, t) => console.log(`\n[${n}] ${t}`);
async function until(f, ms = 30000, label = 'condition') {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { const v = await f().catch(() => null); if (v) return v; await sleep(400); }
  throw new Error('timeout waiting for ' + label);
}
const expectReject = async (p, re, msg) => { try { await p; ok(false, msg + ' (was accepted)'); } catch (e) { ok(re.test(e.message), `${msg} -> "${e.message}"`); } };

const seller = newIdentity('Seller'), alice = newIdentity('Alice'), bob = newIdentity('Bob'), carol = newIdentity('Carol');
const wallets = new Map();
const bal = (u) => totalSats(wallets.get(u) || []);
const add = (u, ps) => wallets.set(u, [...(wallets.get(u) || []), ...ps]);

const stranded = [];
async function placeBid(u, au, amount, force = false) {
  const s = await c.state();
  const a = s.auctions[au];
  const { keep, locked } = await c.lockForBid(u, wallets.get(u), amount, s.params, a, { force, state: s });
  wallets.set(u, keep);
  let r;
  try { r = await c.bid(u, a, amount, locked); } catch (e) { stranded.push({ u, locked }); throw e; }
  const bid = await until(async () => { const st = await c.state(); return st.bids[r.id] && st; }, 15000, 'bid commit');
  return { id: r.id, via: r.via, state: bid };
}

const net0 = await c.network();
ok(net0.filter((v) => v.up).length === 4, 'all four validators up');

step(1, 'Seller creates an auction');
const cr = await c.createAuction(seller, { title: 'Test lot: 1-of-1 print', description: 'e2e', image: '', category: 'Art', startPrice: 100, minIncrement: 10, durationSec: 30 });
let s = await until(async () => { const st = await c.state(); return st.auctions[cr.id] && st; }, 15000, 'create');
const A = cr.id;
ok(s.auctions[A].status === 'open' && s.auctions[A].hardEnd === s.auctions[A].endAt + s.params.maxExtendSec, 'auction open with hard end');

step(2, 'Fund wallets from the fake-sats faucet and place the first bid');
for (const u of [alice, bob, carol]) add(u, await c.faucet(1000));
ok(bal(alice) === 1000 && bal(bob) === 1000 && bal(carol) === 1000, 'each bidder holds 1000 fake sats');
await expectReject(c.createAuction(seller, { title: '', startPrice: 0, minIncrement: 1, durationSec: 30 }), /title|range/, 'invalid lot rejected');
const b1 = await placeBid(alice, A, 100);
ok(b1.state.auctions[A].highBid === b1.id, 'Alice leads at 100');
await expectReject(c.claim(alice, b1.state.bids[b1.id], 'refund', s.params), /validators agreed/, 'validators refuse to refund the leading bid');

step(3, 'Outbid -> instant refund co-signed by validators');
const b2 = await placeBid(bob, A, 110);
s = b2.state;
ok(s.bids[b1.id].status === 'outbid', 'Alice marked outbid');
const r1 = await c.claim(alice, s.bids[b1.id], 'refund', s.params);
add(alice, r1.proofs);
ok(bal(alice) === 1000 && r1.cosigners.length >= 3, `Alice refunded 100 instantly by ${r1.cosigners.length} validators`);
await expectReject(c.claim(alice, s.bids[b1.id], 'refund', s.params), /already spent|spent/i, 'second refund of the same escrow rejected by mint');
await expectReject(placeBid(carol, A, 115), /at least 120/, 'under-increment bid stopped by the client before locking');
await expectReject(placeBid(carol, A, 115, true), /at least 120/, 'under-increment bid rejected by validators (sats were locked)');
await expectReject((async () => { const st = await c.state(); return c.bid(seller, st.auctions[A], 500, []); })(), /seller cannot bid/, 'seller cannot bid on own lot');

step(4, 'Late bid extends the clock (anti-sniping)');
s = await c.state();
await until(async () => { const st = await c.state(); return st.auctions[A].endAt - st.time < st.params.softCloseSec; }, 30000, 'soft-close window');
const endBefore = (await c.state()).auctions[A].endAt;
const b3 = await placeBid(carol, A, 200);
ok(b3.state.bids[b3.id].extended && b3.state.auctions[A].endAt > endBefore, `end moved ${endBefore} -> ${b3.state.auctions[A].endAt}`);
ok(b3.state.auctions[A].endAt <= b3.state.auctions[A].hardEnd, 'extension capped by hard end');

step(5, 'Stop Validator 4; bidding continues on 3 of 4');
await c.j('/api/admin/validator/4/stop', { method: 'POST' });
const h0 = (await c.state()).height;
await until(async () => (await c.state()).height >= h0 + 2, 20000, 'blocks with V4 down');
const net1 = await c.network();
ok(!net1[3].up && net1.slice(0, 3).every((v) => v.up), 'V4 down, V1-V3 producing blocks');
const b4 = await placeBid(alice, A, 250);
ok(b4.state.auctions[A].highBid === b4.id, 'Alice leads at 250 with only 3 validators');
s = b4.state;
const r3 = await c.claim(carol, s.bids[b3.id], 'refund', s.params);
add(carol, r3.proofs);
ok(!r3.cosigners.includes('Validator 4') && r3.cosigners.length === 3, 'Carol refunded by V1-V3 while V4 is offline');

step(6, 'Auction auto-closes; validators agree on the winner');
s = await until(async () => { const st = await c.state(); return st.auctions[A].status === 'closed' && st; }, 200000, 'close');
ok(s.auctions[A].winner === b4.id && s.bids[b4.id].status === 'won', 'Alice wins at 250');
const net2 = await c.network();
const hashes = new Set(net2.filter((v) => v.up).map((v) => v.appHash));
ok(hashes.size === 1, 'running validators report the same app hash');

step(7, 'Seller payout (needs 3 of 4, seller-authorised)');
await expectReject(c.claim(alice, s.bids[b4.id], 'payout', s.params), /validators agreed/, 'winner cannot redirect the payout');
await expectReject(c.claim(seller, s.bids[b2.id], 'payout', s.params), /validators agreed/, 'losing bid cannot be paid to seller');
const pay = await c.claim(seller, s.bids[b4.id], 'payout', s.params);
add(seller, pay.proofs);
ok(bal(seller) === 250, 'seller received 250');

step(8, 'Loser refunds; 2 signatures are not enough');
const neg = await c.claim(bob, s.bids[b2.id], 'refund', s.params, 2).then(() => null, (e) => e);
ok(neg && /mint|signature|not enough|witness|valid/i.test(neg.message), `mint rejects a 2-of-4 release -> "${neg && neg.message.slice(0, 80)}"`);
const r2 = await c.claim(bob, s.bids[b2.id], 'refund', s.params);
add(bob, r2.proofs);
ok(bal(bob) === 1000, 'Bob refunded 110');
await expectReject(c.claim(alice, s.bids[b4.id], 'refund', s.params), /validators agreed/, 'winning escrow cannot be refunded');

step(9, 'Restart Validator 4; it catches up from its peers');
await c.j('/api/admin/validator/4/start', { method: 'POST' });
const caught = await until(async () => {
  const n = await c.network();
  return n.every((v) => v.up) && Math.abs(n[3].height - n[0].height) <= 1 && n[3].height > h0 && n;
}, 60000, 'V4 catch-up');
ok(new Set(caught.filter((v) => v.height === caught[0].height).map((v) => v.appHash)).size === 1, `V4 back at height ${caught[3].height} with matching app hash`);

step('R', 'Rejected bid: bidder reclaims locked sats alone after locktime');
for (const { u, locked } of stranded) {
  const lt = JSON.parse(locked[0].secret)[1].tags.find((t) => t[0] === 'locktime')[1];
  await expectReject(c.reclaimExpired(u, locked), /.+/, 'reclaim before locktime refused by mint');
  const wait = Number(lt) * 1000 - Date.now() + 2000;
  console.log(`  waiting ${Math.round(wait / 1000)}s for locktime`);
  if (wait > 0) await sleep(wait);
  add(u, await c.reclaimExpired(u, locked));
  ok(true, `${u.name} reclaimed ${totalSats(locked)} after locktime`);
}

step('C', 'Conservation of fake sats');
const total = bal(seller) + bal(alice) + bal(bob) + bal(carol);
ok(total === 3000, `seller ${bal(seller)} + alice ${bal(alice)} + bob ${bal(bob)} + carol ${bal(carol)} = ${total} (3000 minted)`);
const st = await c.state();
const escrows = st.auctions[A].bids.map((b) => st.bids[b]);
const spent = await Promise.all(escrows.map((b) => c.spent(b.proofs).then((x) => x.every(Boolean))));
ok(spent.every(Boolean), 'every escrow is settled at the mint (nothing stranded)');
console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
