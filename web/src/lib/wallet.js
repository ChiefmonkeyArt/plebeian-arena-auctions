// WalletClient: ArenaClient for the page. Reads and submits stay on the main
// thread (they are only fetches); wallet operations go to a module worker
// (wallet-worker.js). If a worker cannot start, everything runs in-page as
// before v0.4.2.
import { ArenaClient } from './arena.js';

export const WALLET_OPS = ['balance', 'receive', 'faucet', 'lockForBid', 'claim', 'reclaimExpired', 'spent', 'close'];

export class WalletClient extends ArenaClient {
  constructor(base = '') {
    super(base);
    this.calls = new Map(); this.n = 0; this.worker = null;
    try {
      const w = new Worker(new URL('./wallet-worker.js', import.meta.url), { type: 'module', name: 'arena-wallet' });
      w.onmessage = ({ data: { n, ok, v, e } }) => {
        const c = this.calls.get(n); if (!c) return; this.calls.delete(n);
        if (ok) c.resolve(v); else c.reject(Object.assign(new Error(e.message), e));
      };
      w.onerror = (ev) => { // a worker that fails to load: fall back to the page
        ev.preventDefault?.(); console.warn('wallet worker failed; using the page', ev.message);
        this.worker = null; w.terminate();
        for (const [, c] of this.calls) c.retry(); this.calls.clear();
      };
      w.postMessage({ op: 'init', args: [base] });
      this.worker = w;
    } catch (e) { console.warn('wallet worker unavailable; using the page', e.message); }
    for (const op of WALLET_OPS) {
      const local = ArenaClient.prototype[op].bind(this);
      this[op] = (...args) => (this.worker ? new Promise((resolve, reject) => {
        const n = ++this.n;
        this.calls.set(n, { resolve, reject, retry: () => local(...args).then(resolve, reject) });
        this.worker.postMessage({ n, op, args });
      }) : local(...args));
    }
  }
}
