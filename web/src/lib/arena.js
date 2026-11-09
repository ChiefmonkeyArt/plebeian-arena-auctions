// Arena client: Nostr identity, fake-sats Cashu wallet, escrow bids and 3-of-4 releases.
// Works in the browser and in Node 20 (tests).
import { Wallet, P2PKBuilder, OutputData } from '@cashu/cashu-ts';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';

export const KIND_CREATE = 1440;
export const KIND_BID = 1441;
export const KIND_CHAT = 1442;

export function newIdentity(name) {
  const nostrSk = bytesToHex(secp256k1.utils.randomSecretKey());
  const walletSk = bytesToHex(secp256k1.utils.randomSecretKey());
  return { name, nostrSk, walletSk };
}

export function idPub(id) { return getPublicKey(hexToBytes(id.nostrSk)); }
export function walletPub(id) { return '02' + bytesToHex(schnorr.getPublicKey(hexToBytes(id.walletSk))); }

const num = (a) => (a && typeof a.toNumber === 'function' ? a.toNumber() : Number(a));
const sum = (ps) => ps.reduce((a, p) => a + num(p.amount), 0);
const plain = (p) => ({ id: p.id, amount: num(p.amount), secret: p.secret, C: p.C, ...(p.dleq ? { dleq: { e: p.dleq.e, s: p.dleq.s, r: p.dleq.r } } : {}) });

export class ArenaClient {
  constructor(base = '') {
    this.base = base;
    this.mintUrl = (base || (typeof location !== 'undefined' ? location.origin : '')) + '/mint';
    this.wallet = null;
  }

  async j(path, opts) {
    const r = await fetch(this.base + path, opts);
    const t = await r.text();
    let body; try { body = JSON.parse(t); } catch { body = { error: t }; }
    if (!r.ok) { const e = new Error(body.error || r.statusText); e.status = r.status; e.body = body; throw e; }
    return body;
  }

  state() { return this.j('/api/state'); }
  network() { return this.j('/api/network'); }
  chat() { return this.j('/api/chat'); }

  async ensureWallet() {
    if (!this.wallet) { this.wallet = new Wallet(this.mintUrl, { unit: 'sat' }); await this.wallet.loadMint(); }
    return this.wallet;
  }

  // Fake sats: the test mint's FakeWallet pays invoices instantly.
  async faucet(amount) {
    const w = await this.ensureWallet();
    const q = await w.createMintQuoteBolt11(amount);
    for (let i = 0; i < 40; i++) {
      const st = await w.checkMintQuoteBolt11(q.quote);
      if (st.state === 'PAID') break;
      await new Promise((r) => setTimeout(r, 250));
    }
    const proofs = await w.mintProofsBolt11(amount, q.quote);
    return proofs.map(plain);
  }

  sign(id, kind, content, tags = []) {
    return finalizeEvent({ kind, created_at: Math.floor(Date.now() / 1000), tags, content: JSON.stringify(content) }, hexToBytes(id.nostrSk));
  }

  async submit(ev) { return this.j('/api/tx', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(ev) }); }

  async createAuction(id, lot) {
    const ev = this.sign(id, KIND_CREATE, { ...lot, sellerWallet: walletPub(id), name: id.name });
    const res = await this.submit(ev);
    return { ...res, id: ev.id };
  }

  // Lock `amount` of the user's proofs to the validators (3-of-4, SIG_ALL), refundable to the bidder after locktime.
  async lockForBid(id, proofs, amount, params, auction, { force = false, state } = {}) {
    if (!force) {
      const min = auction.highBid ? auction.highAmount + auction.minIncrement : auction.startPrice;
      if (auction.status !== 'open') throw new Error('auction closed');
      if (amount < min) throw new Error(`bid must be at least ${min} sats`);
      if (state && auction.highBid && state.bids[auction.highBid].bidder === idPub(id)) throw new Error('you are already the highest bidder');
      if (sum(proofs) < amount) throw new Error('not enough sats in wallet');
    }
    const w = await this.ensureWallet();
    const locktime = auction.hardEnd + params.lockMarginSec + 15;
    const opts = new P2PKBuilder().addLockPubkey(params.validators).requireLockSignatures(params.threshold)
      .addRefundPubkey(walletPub(id)).lockUntil(locktime).sigAll().toOptions();
    const { keep, send } = await w.ops.send(amount, proofs).asP2PK(opts).run();
    return { keep: keep.map(plain), locked: send.map(plain) };
  }

  async bid(id, auction, amount, locked) {
    const ev = this.sign(id, KIND_BID, { auction: auction.id, amount, wallet: walletPub(id), name: id.name, proofs: locked }, [['e', auction.id]]);
    const res = await this.submit(ev);
    return { ...res, id: ev.id };
  }

  // Ask all four validators to co-sign a release; needs `threshold` signatures for the mint to accept.
  async claim(id, bid, purpose, params, n = params.threshold) {
    const w = await this.ensureWallet();
    const ks = w.getKeyset();
    const outs = OutputData.createRandomData(bid.amount, ks);
    const outputs = outs.map((o) => ({ amount: num(o.blindedMessage.amount), id: o.blindedMessage.id, B_: o.blindedMessage.B_ }));
    const msg = bid.proofs.map((p) => p.secret).join('') + outputs.map((o) => o.B_).join('');
    const h = sha256(new TextEncoder().encode(msg));
    const auth = bytesToHex(schnorr.sign(h, hexToBytes(id.walletSk)));
    const replies = await this.j('/api/sign', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bid: bid.id, purpose, outputs, auth }) });
    const sigs = replies.filter((r) => r.signature).map((r) => r.signature);
    if (sigs.length < n) {
      const e = new Error(`only ${sigs.length} of 4 validators agreed: ` + replies.map((r) => r.error).filter(Boolean).join('; '));
      e.replies = replies; throw e;
    }
    const inputs = bid.proofs.map((p, i) => ({ id: p.id, amount: p.amount, secret: p.secret, C: p.C, ...(i === 0 ? { witness: JSON.stringify({ signatures: sigs.slice(0, n) }) } : {}) }));
    const r = await fetch(this.mintUrl + '/v1/swap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ inputs, outputs }) });
    const jr = await r.json();
    if (!jr.signatures) { const e = new Error(jr.detail || 'mint rejected release'); e.mint = jr; throw e; }
    return { proofs: outs.map((o, i) => plain(o.toProof(jr.signatures[i], ks))), cosigners: replies.filter((r) => r.signature).map((r) => r.validator) };
  }

  // Refund path: after locktime the bidder alone can reclaim a lock the chain never recorded.
  async reclaimExpired(id, locked) {
    const w = await this.ensureWallet();
    const ks = w.getKeyset();
    const amount = sum(locked);
    const outs = OutputData.createRandomData(amount, ks);
    const outputs = outs.map((o) => ({ amount: num(o.blindedMessage.amount), id: o.blindedMessage.id, B_: o.blindedMessage.B_ }));
    const msg = locked.map((p) => p.secret).join('') + outputs.map((o) => o.B_).join('');
    const sig = bytesToHex(schnorr.sign(sha256(new TextEncoder().encode(msg)), hexToBytes(id.walletSk)));
    const inputs = locked.map((p, i) => ({ id: p.id, amount: p.amount, secret: p.secret, C: p.C, ...(i === 0 ? { witness: JSON.stringify({ signatures: [sig] }) } : {}) }));
    const r = await fetch(this.mintUrl + '/v1/swap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ inputs, outputs }) });
    const jr = await r.json();
    if (!jr.signatures) throw new Error(jr.detail || 'mint rejected reclaim');
    return outs.map((o, i) => plain(o.toProof(jr.signatures[i], ks)));
  }

  // Raw swap with a chosen signature set (used by the negative test).
  async rawRelease(bid, sigs) {
    const w = await this.ensureWallet();
    const outs = OutputData.createRandomData(bid.amount, w.getKeyset());
    const outputs = outs.map((o) => ({ amount: num(o.blindedMessage.amount), id: o.blindedMessage.id, B_: o.blindedMessage.B_ }));
    const inputs = bid.proofs.map((p, i) => ({ id: p.id, amount: p.amount, secret: p.secret, C: p.C, ...(i === 0 ? { witness: JSON.stringify({ signatures: sigs }) } : {}) }));
    const r = await fetch(this.mintUrl + '/v1/swap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ inputs, outputs }) });
    return { status: r.status, body: await r.json(), outputs };
  }

  // Which escrowed proofs are already spent at the mint (NUT-07).
  async spent(proofs) {
    const w = await this.ensureWallet();
    const st = await w.checkProofsStates(proofs);
    return st.map((s) => s.state === 'SPENT');
  }

  async postChat(id, auctionId, text) {
    const ev = finalizeEvent({ kind: KIND_CHAT, created_at: Math.floor(Date.now() / 1000), tags: [['e', auctionId], ['name', id.name]], content: text }, hexToBytes(id.nostrSk));
    return this.j('/api/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(ev) });
  }
}

export { sum as totalSats, num };

export function lockOf(p) { try { const [k, b] = JSON.parse(p.secret); if (k !== 'P2PK') return null; const lt = b.tags.find((t) => t[0] === 'locktime'); return { locktime: lt ? Number(lt[1]) : 0 }; } catch { return null; } }
