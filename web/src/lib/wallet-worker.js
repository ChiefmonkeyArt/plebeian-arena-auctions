// Wallet worker (v0.4.2): the Coco wallets and every Cashu proof step
// (blinding, unblinding, P2PK locks, release signing) run here, off the page's
// main thread, so the clocks and bid buttons never wait on elliptic-curve
// maths. The page talks to it through WalletClient (lib/wallet.js).
//
// v0.5.2: iOS WebKit can drop messages posted to a module worker before its
// module graph has finished loading. The worker now says 'ready' once its
// handler is installed, and every message carries the base URL, so a lost
// message can never leave the worker without a client.
import { ArenaClient } from './arena.js';
import { WALLET_OPS } from './wallet-ops.js';

const OPS = new Set(WALLET_OPS);
let client = null;
self.onmessage = async ({ data }) => {
  const { n, op, args, base = '' } = data;
  if (op === 'init') { client ||= new ArenaClient(base); return; }
  try {
    if (!OPS.has(op)) throw new Error('wallet worker: unknown op ' + op);
    client ||= new ArenaClient(base);
    self.postMessage({ n, ok: true, v: await client[op](...args) });
  } catch (e) {
    self.postMessage({ n, ok: false, e: { message: String(e?.message || e), status: e?.status, body: e?.body, refusals: e?.refusals, mint: e?.mint } });
  }
};
self.postMessage({ ready: true });
