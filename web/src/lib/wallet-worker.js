// Wallet worker (v0.4.2): the Coco wallets and every Cashu proof step
// (blinding, unblinding, P2PK locks, release signing) run here, off the page's
// main thread, so the clocks and bid buttons never wait on elliptic-curve
// maths. The page talks to it through WalletClient (lib/wallet.js).
import { ArenaClient } from './arena.js';

let client = null;
self.onmessage = async ({ data }) => {
  const { n, op, args } = data;
  if (op === 'init') { client = new ArenaClient(args[0]); return; }
  try {
    if (!client || !WALLET_OPS.has(op)) throw new Error('wallet worker: unknown op ' + op);
    self.postMessage({ n, ok: true, v: await client[op](...args) });
  } catch (e) {
    self.postMessage({ n, ok: false, e: { message: String(e?.message || e), status: e?.status, body: e?.body, refusals: e?.refusals, mint: e?.mint } });
  }
};
const WALLET_OPS = new Set(['balance', 'receive', 'faucet', 'lockForBid', 'claim', 'reclaimExpired', 'spent', 'close']);
