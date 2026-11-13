// WalletClient: ArenaClient for the page. Reads and submits stay on the main
// thread (they are only fetches); wallet operations go to a module worker
// (wallet-worker.js). If a worker cannot start, everything runs in-page as
// before v0.4.2.
//
// v0.5.2: calls wait for the worker's 'ready' message before they are posted
// (iOS WebKit can drop earlier messages). If no 'ready' arrives within
// READY_MS, or the worker fails, the wallet runs in the page instead.
import { ArenaClient } from './arena.js';
import { WALLET_OPS } from './wallet-ops.js';

export { WALLET_OPS };
export const READY_MS = 8000;

export class WalletClient extends ArenaClient {
  constructor(base = '', { makeWorker, readyMs = READY_MS } = {}) {
    super(base);
    this.calls = new Map(); this.n = 0; this.worker = null; this.queue = [];
    this.mode = 'starting'; // 'starting' | 'worker' | 'page'
    const toPage = (why) => {
      if (this.mode === 'page') return;
      if (why) console.warn('wallet worker unavailable; using the page:', why);
      this.mode = 'page'; clearTimeout(this.readyTimer);
      try { this.worker?.terminate(); } catch {}
      this.worker = null;
      for (const [, c] of this.calls) c.retry(); this.calls.clear();
      const q = this.queue; this.queue = []; for (const c of q) c.retry();
    };
    try {
      const w = makeWorker ? makeWorker() : new Worker(new URL('./wallet-worker.js', import.meta.url), { type: 'module', name: 'arena-wallet' });
      this.worker = w;
      w.onmessage = ({ data }) => {
        if (data?.ready) {
          if (this.mode !== 'starting') return;
          this.mode = 'worker'; clearTimeout(this.readyTimer);
          w.postMessage({ op: 'init', base });
          const q = this.queue; this.queue = []; for (const c of q) this.post(c);
          return;
        }
        const { n, ok, v, e } = data;
        const c = this.calls.get(n); if (!c) return; this.calls.delete(n);
        if (ok) c.resolve(v); else c.reject(Object.assign(new Error(e.message), e));
      };
      w.onerror = (ev) => { ev.preventDefault?.(); toPage(ev.message || 'worker error'); };
      this.readyTimer = setTimeout(() => toPage('no ready message in ' + readyMs + ' ms'), readyMs);
    } catch (e) { toPage(e.message); }
    for (const op of WALLET_OPS) {
      const local = ArenaClient.prototype[op].bind(this);
      this[op] = (...args) => {
        if (this.mode === 'page') return local(...args);
        return new Promise((resolve, reject) => {
          const c = { op, args, resolve, reject, retry: () => local(...args).then(resolve, reject) };
          if (this.mode === 'worker') this.post(c); else this.queue.push(c);
        });
      };
    }
  }
  post(c) {
    const n = ++this.n; this.calls.set(n, c);
    this.worker.postMessage({ n, op: c.op, args: c.args, base: this.base });
  }
}
