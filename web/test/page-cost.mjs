// v0.4.2 page-cost checks (no network): memoised public keys match a fresh
// derivation, and WalletClient routes wallet operations to its worker, passes
// worker errors through with their fields, and falls back to the page when the
// worker fails to load. Usage: node web/test/page-cost.mjs
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { getPublicKey } from 'nostr-tools/pure';
import { ArenaClient, newIdentity, idPub, walletPub } from '../src/lib/arena.js';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  PASS', m); } else { fail++; console.log('  FAIL', m); } };

const id = newIdentity('Alice');
ok(idPub(id) === getPublicKey(hexToBytes(id.nostrSk)), 'idPub matches a fresh derivation');
ok(walletPub(id) === '02' + bytesToHex(schnorr.getPublicKey(hexToBytes(id.walletSk))), 'walletPub matches a fresh derivation');
const other = newIdentity('Bob');
ok(idPub(other) !== idPub(id) && walletPub(other) !== walletPub(id), 'different keys give different public keys');
let t = performance.now(); for (let i = 0; i < 2000; i++) { idPub(id); walletPub(id); }
ok(performance.now() - t < 50, `4000 memoised lookups in ${(performance.now() - t).toFixed(1)} ms`);

// A stand-in Worker: answers in-process like wallet-worker.js would.
const sent = [];
class FakeWorker {
  constructor(url, opts) { this.url = String(url); this.opts = opts; FakeWorker.last = this; }
  postMessage(m) {
    sent.push(m); if (m.op === 'init') return;
    queueMicrotask(() => this.onmessage({ data: m.op === 'claim'
      ? { n: m.n, ok: false, e: { message: 'not enough cosigners', refusals: ['V4'] } }
      : { n: m.n, ok: true, v: { op: m.op, args: m.args } } }));
  }
  terminate() { this.dead = true; }
}
globalThis.Worker = FakeWorker;
const { WalletClient } = await import('../src/lib/wallet.js');
const w = new WalletClient('http://x');
ok(/wallet-worker\.js$/.test(FakeWorker.last.url) && FakeWorker.last.opts.type === 'module', 'starts a module worker');
ok(sent[0].op === 'init' && sent[0].args[0] === 'http://x', 'worker gets the API base');
const r = await w.balance(id);
ok(r.op === 'balance' && r.args[0].walletSk === id.walletSk, 'balance runs in the worker');
try { await w.claim(id, {}, 'refund', {}); ok(false, 'claim error passes through'); }
catch (e) { ok(e instanceof Error && e.message === 'not enough cosigners' && e.refusals[0] === 'V4', 'worker errors keep message and refusals'); }
ok(typeof w.view === 'function' && w.view === ArenaClient.prototype.view, 'reads stay on the page');

// Worker fails to load: queued and later calls run in the page.
ArenaClient.prototype.balance = async function () { return 'local:' + this.base; };
class DeadWorker extends FakeWorker { postMessage(m) { if (m.op !== 'init') queueMicrotask(() => this.onerror({ message: 'load failed', preventDefault() {} })); } }
globalThis.Worker = DeadWorker;
const d = new WalletClient('http://y');
ok((await d.balance(id)) === 'local:http://y', 'a failed worker retries the call in the page');
ok(d.worker === null && DeadWorker.last.dead, 'the failed worker is dropped');
ok((await d.balance(id)) === 'local:http://y', 'later calls run in the page');

delete globalThis.Worker;
const n = new WalletClient('http://z');
ok(n.worker === null && (await n.balance(id)) === 'local:http://z', 'no Worker at all: runs in the page');

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
