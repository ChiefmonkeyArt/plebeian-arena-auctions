// Arena client: Nostr identity, a Coco Cashu wallet per identity (fake sats),
// escrow bids locked to the validators' FROST group key, and 3-of-4 releases.
// Works in the browser (IndexedDB) and in Node 20 (in-memory, for tests).
import { Amount, OutputData, getEncodedToken, hashToCurve } from '@cashu/cashu-ts';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';

export const KIND_CREATE = 1440;
export const KIND_BID = 1441;
export const KIND_CHAT = 1442;

export function newIdentity(name) {
  const nostrSk = bytesToHex(secp256k1.utils.randomSecretKey());
  const walletSk = bytesToHex(secp256k1.utils.randomSecretKey());
  return { name, nostrSk, walletSk, seed: bytesToHex(randomBytes(64)) };
}

// Identities saved before v0.2 have no wallet seed; give them one.
export function ensureSeed(id) { if (!id.seed) id.seed = bytesToHex(randomBytes(64)); return id; }

// Public keys are derived once per secret key: the page asks for them on every
// render, and each derivation is a full elliptic-curve multiplication (v0.4.2).
const pubMemo = new Map();
const memoPub = (tag, sk, f) => { const k = tag + sk; let v = pubMemo.get(k); if (v === undefined) { v = f(); pubMemo.set(k, v); } return v; };
// A logged-in Nostr user (ADR 0010) has no secret key here: `pubkey` comes
// from their signer (NIP-07 extension or NIP-46 bunker), which signs events.
// Their fake-sats wallet key is still local to this browser.
export function idPub(id) { return id.pubkey || memoPub('n', id.nostrSk, () => getPublicKey(hexToBytes(id.nostrSk))); }
export function walletPub(id) { return memoPub('w', id.walletSk, () => '02' + bytesToHex(schnorr.getPublicKey(hexToBytes(id.walletSk)))); }

const num = (a) => (a && typeof a.toNumber === 'function' ? a.toNumber() : Number(a));
const sum = (ps) => ps.reduce((a, p) => a + num(p.amount), 0);
const plain = (p) => ({ id: p.id, amount: num(p.amount), secret: p.secret, C: p.C, ...(p.dleq ? { dleq: { e: p.dleq.e, s: p.dleq.s, r: p.dleq.r } } : {}) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const keysetOf = (params) => ({ id: params.keysetId, keys: params.keys });
// NUT-11 SIG_ALL message, as Nutshell 0.21 checks it: each input's secret and C,
// then each output's amount and B_ (amounts covered: internal audit A6).
const sigAllHash = (inputs, outputs) => sha256(new TextEncoder().encode(inputs.map((p) => p.secret + p.C).join('') + outputs.map((o) => String(o.amount) + o.B_).join('')));
// Turn the mint's blind signatures into proofs (cashu-ts 5 wants Amount objects).
const unblind = (outs, sigs, params) => outs.map((o, i) => plain(o.toProof({ ...sigs[i], amount: Amount.from(sigs[i].amount) }, keysetOf(params))));
const blank = (amount, params) => {
  const outs = OutputData.createRandomData(amount, keysetOf(params));
  return { outs, outputs: outs.map((o) => ({ amount: num(o.blindedMessage.amount), id: o.blindedMessage.id, B_: o.blindedMessage.B_ })) };
};

export class ArenaClient {
  constructor(base = '') {
    this.base = base;
    this.mintUrl = (base || (typeof location !== 'undefined' ? location.origin : '')) + '/mint';
    this.cocos = new Map();
    this.signers = new Map(); // pubkey -> async (template) => signed event, for remote signers
  }

  async j(path, opts) {
    const r = await fetch(this.base + path, opts);
    const t = await r.text();
    let body; try { body = JSON.parse(t); } catch { body = { error: t }; }
    if (!r.ok) { const e = new Error(body.error || r.statusText); e.status = r.status; e.body = body; throw e; }
    return body;
  }

  state() { return this.j('/api/state'); }
  // Slim view the page polls (v0.3.1): open lots, recent results and the
  // caller's unsettled ones, bids without proofs. Resolves to null when the
  // view is unchanged since etag (HTTP 304).
  async view(bidders = [], etag = '', closed = 12) {
    const q = new URLSearchParams({ view: 'client', closed: String(closed) });
    if (bidders.length) q.set('bidders', bidders.join(','));
    const r = await fetch(this.base + '/api/state?' + q, { cache: 'no-store', headers: etag ? { 'if-none-match': etag } : {} });
    if (r.status === 304) return null;
    if (!r.ok) throw new Error('state ' + r.status);
    return { state: await r.json(), etag: r.headers.get('etag') || '' };
  }
  // One committed bid with its proofs.
  bidWithProofs(id) { return this.j('/api/bid?id=' + encodeURIComponent(id)); }
  network() { return this.j('/api/network'); }
  chat() { return this.j('/api/chat'); }

  // One Coco wallet per identity: IndexedDB in the browser, memory in Node.
  coco(id) {
    ensureSeed(id);
    const key = walletPub(id);
    if (!this.cocos.has(key)) {
      this.cocos.set(key, (async () => {
        // Loaded on first use: the page's main bundle leaves Coco to the wallet worker.
        const { initializeCoco, MemoryRepositories } = await import('@cashu/coco-core');
        let repo;
        if (typeof indexedDB !== 'undefined') {
          const { IndexedDbRepositories } = await import('@cashu/coco-indexeddb');
          repo = new IndexedDbRepositories({ name: 'arena-coco-' + key.slice(2, 18) });
          await repo.init();
        } else repo = new MemoryRepositories();
        const m = await initializeCoco({
          repo, seedGetter: async () => hexToBytes(id.seed),
          // Paid quotes are claimed explicitly by faucet(); see the note there.
          processors: { mintOperationProcessor: { autoClaimMintQuotes: false } },
        });
        await m.mint.addMint(this.mintUrl, { trusted: true });
        await m.keyring.addKeyPair(hexToBytes(id.walletSk)).catch(() => {});
        return m;
      })());
    }
    return this.cocos.get(key);
  }

  async balance(id) {
    const m = await this.coco(id);
    const b = await m.wallet.balances.byMint();
    const k = Object.keys(b).find((u) => u.replace(/\/$/, '') === this.mintUrl.replace(/\/$/, ''));
    return k ? num(b[k].spendable ?? b[k].total ?? 0) : 0;
  }

  // Bring plain proofs (a release, a reclaim, or ecash the validators pushed:
  // P2PK-locked to this wallet key, which Coco's keyring signs for) into the
  // identity's Coco wallet.
  async receive(id, proofs) {
    const m = await this.coco(id);
    await m.wallet.receive(getEncodedToken({ mint: this.mintUrl, unit: 'sat', proofs }));
    return sum(proofs);
  }

  // Fake sats: the test mint's FakeWallet pays its own invoices. Nutshell 0.20
  // does not move `updated_at` when that happens, which Coco 2 treats as a
  // conflicting observation, so we wait for PAID ourselves and import the
  // settled quote into Coco, then let Coco mint it.
  async faucet(id, amount) {
    const m = await this.coco(id);
    const pj = (u, b) => fetch(this.mintUrl + u, b ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) } : {}).then((r) => r.json());
    let q = await pj('/v1/mint/quote/bolt11', { amount, unit: 'sat' });
    for (let i = 0; i < 40 && q.state !== 'PAID'; i++) { await sleep(250); q = await pj('/v1/mint/quote/bolt11/' + q.quote); }
    if (q.state !== 'PAID') throw new Error('faucet invoice was not paid');
    const quote = await m.quotes.mint.import({ mintUrl: this.mintUrl, method: 'bolt11', quote: q });
    const op = await m.ops.mint.prepare({ quote, amount });
    let done = await m.ops.mint.execute(op.id);
    for (let i = 0; i < 20 && done.state !== 'finalized'; i++) { await sleep(250); done = await m.ops.mint.get(op.id); }
    if (done.state !== 'finalized') throw new Error('faucet mint did not finish');
    return this.balance(id);
  }

  // Sign a Nostr event as id: with its local key, or through its remote signer.
  async signEvent(id, tmpl) {
    if (id.nostrSk) return finalizeEvent(tmpl, hexToBytes(id.nostrSk));
    const f = this.signers.get(id.pubkey);
    if (!f) throw new Error('log in again: no signer for this Nostr key');
    const ev = await f(tmpl);
    if (!ev || ev.pubkey !== id.pubkey) throw new Error('the signer returned another key');
    return ev;
  }

  sign(id, kind, content, tags = []) {
    return this.signEvent(id, { kind, created_at: Math.floor(Date.now() / 1000), tags, content: JSON.stringify(content) });
  }

  async submit(ev) { return this.j('/api/tx', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(ev) }); }

  async createAuction(id, lot) {
    const ev = await this.sign(id, KIND_CREATE, { ...lot, sellerWallet: walletPub(id), name: lot.name || id.name });
    const res = await this.submit(ev);
    return { ...res, id: ev.id };
  }

  // Coco locks `amount` to the validators' FROST group key (one key; 3 of the 4
  // validators must cooperate to sign for it), SIG_ALL, refundable to the
  // bidder's own wallet key after locktime.
  // Locktime (ADR 0009): a fixed lot ends when it says, so its escrows stay
  // locked until end + margin. An anti-snipe lot has no end in advance: the
  // lock runs margin from now (chain time `now`) and the validators re-lock a
  // leading escrow before it gets near.
  async lockForBid(id, amount, params, auction, { force = false, state, now = Date.now() / 1000 } = {}) {
    if (!force) {
      const min = auction.highBid ? auction.highAmount + auction.minIncrement : auction.startPrice;
      if (auction.status !== 'open') throw new Error('auction closed');
      if (amount < min) throw new Error(`bid must be at least ${min} sats`);
      if (state && auction.highBid && state.bids[auction.highBid].bidder === idPub(id)) throw new Error('you are already the highest bidder');
      if ((await this.balance(id)) < amount) throw new Error('not enough sats in wallet');
    }
    const m = await this.coco(id);
    const locktime = Math.ceil(auction.mode === 'antisnipe' ? now + params.lockMarginSec + 60 : auction.endAt + params.lockMarginSec + 15);
    const prep = await m.ops.send.prepare({
      mintUrl: this.mintUrl, amount,
      target: { type: 'p2pk', options: { kind: 'P2PK', data: params.groupKey, locktime, refundKeys: [walletPub(id)], sigFlag: 'SIG_ALL' } },
    });
    const { token } = await m.ops.send.execute(prep);
    return { locked: token.proofs.map(plain) };
  }

  async bid(id, auction, amount, locked) {
    const ev = await this.sign(id, KIND_BID, { auction: auction.id, amount, wallet: walletPub(id), name: id.name, proofs: locked }, [['e', auction.id]]);
    const res = await this.submit(ev);
    return { ...res, id: ev.id };
  }

  // Release an escrow (refund to the bidder, or payout to the seller). The
  // wallet that may receive it authorises the exact outputs; the gateway runs
  // one FROST round and returns a single aggregated BIP-340 signature, which
  // the mint checks against the group key like any one-key P2PK lock.
  async claim(id, bid, purpose, params) {
    if (!Array.isArray(bid.proofs)) bid = await this.bidWithProofs(bid.id);
    const { outs, outputs } = blank(bid.amount, params);
    const auth = bytesToHex(schnorr.sign(sigAllHash(bid.proofs, outputs), hexToBytes(id.walletSk)));
    let rel;
    try { rel = await this.j('/api/release', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bid: bid.id, purpose, outputs, auth }) }); }
    catch (e) { e.refusals = e.body?.refusals; throw e; }
    const jr = await this.swap(bid.proofs, outputs, [rel.signature]);
    if (!jr.signatures) { const e = new Error(jr.detail || 'mint rejected release'); e.mint = jr; throw e; }
    const proofs = unblind(outs, jr.signatures, params);
    await this.receive(id, proofs);
    return { amount: sum(proofs), cosigners: rel.cosigners, refusals: rel.refusals, signature: rel.signature };
  }

  async swap(inputs, outputs, signatures) {
    const ins = inputs.map((p, i) => ({ id: p.id, amount: p.amount, secret: p.secret, C: p.C, ...(i === 0 ? { witness: JSON.stringify({ signatures }) } : {}) }));
    const r = await fetch(this.mintUrl + '/v1/swap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ inputs: ins, outputs }) });
    return r.json();
  }

  // Refund path: after locktime the bidder alone can reclaim a lock (for
  // example a bid the chain never recorded), with no validator involved.
  async reclaimExpired(id, locked, params) {
    const { outs, outputs } = blank(sum(locked), params);
    const sig = bytesToHex(schnorr.sign(sigAllHash(locked, outputs), hexToBytes(id.walletSk)));
    const jr = await this.swap(locked, outputs, [sig]);
    if (!jr.signatures) throw new Error(jr.detail || 'mint rejected reclaim');
    const proofs = unblind(outs, jr.signatures, params);
    await this.receive(id, proofs);
    return sum(proofs);
  }

  // Raw swap with chosen witness signatures (negative tests).
  async rawRelease(bid, sigs, params) {
    const { outputs } = blank(bid.amount, params);
    return { body: await this.swap(bid.proofs, outputs, sigs), outputs };
  }

  // Which escrowed proofs are already spent at the mint (NUT-07).
  async spent(proofs) {
    const Ys = proofs.map((p) => hashToCurve(new TextEncoder().encode(p.secret)).toHex(true));
    const r = await fetch(this.mintUrl + '/v1/checkstate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ Ys }) });
    const j = await r.json();
    return (j.states || []).map((s) => s.state === 'SPENT');
  }

  async close() { for (const p of this.cocos.values()) (await p).dispose(); this.cocos.clear(); }

  async postChat(id, auctionId, text) {
    const ev = await this.signEvent(id, { kind: KIND_CHAT, created_at: Math.floor(Date.now() / 1000), tags: [['e', auctionId], ['name', id.name]], content: text });
    return this.j('/api/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(ev) });
  }
}

export { sum as totalSats, num };

export function lockOf(p) { try { const [k, b] = JSON.parse(p.secret); if (k !== 'P2PK') return null; const lt = b.tags.find((t) => t[0] === 'locktime'); return { locktime: lt ? Number(lt[1]) : 0 }; } catch { return null; } }
