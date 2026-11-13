// v0.5.2: the wallet worker handshake. iOS WebKit can drop messages posted to
// a module worker before it has loaded; the page must wait for 'ready', and
// fall back to running the wallet in the page if 'ready' never comes.
// Runs offline with fake workers: node test/worker-ready.mjs
import { WalletClient } from '../src/lib/wallet.js';
import { ArenaClient } from '../src/lib/arena.js';
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('ok  ', m); } else { fail++; console.log('FAIL', m); } };
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
// a worker that drops everything posted before it is "loaded", like iOS
class LateWorker {
  constructor() { this.loaded = false; this.got = []; this.dropped = 0; this.client = null; }
  load() { this.loaded = true; this.onmessage({ data: { ready: true } }); }
  postMessage(d) {
    if (!this.loaded) { this.dropped++; return; }
    this.got.push(d);
    if (d.op === 'init') { this.client = d.base; return; }
    queueMicrotask(() => this.onmessage({ data: { n: d.n, ok: true, v: `${d.op}@${d.base}` } }));
  }
  terminate() { this.dead = true; }
}
const quiet = console.warn; console.warn = () => {};
{
  let w; const c = new WalletClient('http://x', { makeWorker: () => (w = new LateWorker()), readyMs: 1000 });
  const p = c.faucet({}, 100);
  await tick(20);
  ok(w.dropped === 0, 'nothing is posted before the worker says ready');
  w.load();
  ok(await p === 'faucet@http://x', 'a call made early runs once the worker is ready');
  ok(w.got[0].op === 'init' && w.client === 'http://x', 'init is sent after ready');
  ok(w.got.every((m) => m.op === 'init' || m.base === 'http://x'), 'every call carries the base URL');
  ok(await c.balance({}) === 'balance@http://x' && c.mode === 'worker', 'later calls go straight to the worker');
}
{
  let w, ran = 0;
  const orig = ArenaClient.prototype.balance;
  ArenaClient.prototype.balance = async function () { ran++; return 42; };
  const c = new WalletClient('http://y', { makeWorker: () => (w = new LateWorker()), readyMs: 50 });
  const p = c.balance({});
  ok(await p === 42 && ran === 1, 'no ready in time: the queued call runs in the page');
  ok(c.mode === 'page' && w.dead, 'the silent worker is stopped');
  w.load(); await tick(10);
  ok(w.got.length === 0, 'a late ready is ignored');
  ArenaClient.prototype.balance = orig;
}
{
  const c = new WalletClient('', { makeWorker: () => { throw new Error('no workers'); } });
  ok(c.mode === 'page', 'no Worker support: the page runs the wallet');
}
console.warn = quiet;
console.log(`${pass}/${pass + fail}`); process.exit(fail ? 1 : 0);
