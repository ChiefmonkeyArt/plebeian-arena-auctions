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
export const KIND_REFUND = 1443;
export const KIND_SETTLE = 1444;
export const KIND_OUTCOME = 1445;
export const KIND_FUNDING_ABORT = 1446;
export const KIND_STATE_COMMIT = 1447;

// One kind map for the 1440 series (owner decision 2026-11-12, spec §7). All
// regular kinds (1000 <= n < 10000), never the NIP-01 ephemeral range. The
// numbers live here and nowhere else in the client.
export const AUCTION_KINDS = {
  create: KIND_CREATE, bid: KIND_BID, chat: KIND_CHAT, refund: KIND_REFUND,
  settle: KIND_SETTLE, outcome: KIND_OUTCOME, funding_abort: KIND_FUNDING_ABORT, state_commit: KIND_STATE_COMMIT,
};

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
// B_ = hash_to_curve(secret) + r*G, the point the mint signs for an output.
const sigAllOutputPoint = (secret, rHex) => {
  const Y = secp256k1.Point.fromHex(hashToCurve(new TextEncoder().encode(secret)).toHex(true));
  const B_ = Y.add(secp256k1.Point.BASE.multiply(BigInt('0x' + rHex)));
  return bytesToHex(B_.toBytes(true));
};
// The layout-B digest of one exact outcome template (inputs secret+C, outputs amount+B_).
const sigAllTemplateDigest = (t) => bytesToHex(sigAllHash(t.inputs, t.outputs.map((o) => ({ amount: o.amount, B_: sigAllOutputPoint(o.secret, o.r) }))));
// A NUT-10 P2PK output secret locked to one compressed recipient key.
const buildP2PKOutputSecret = (recipient, nonce) => JSON.stringify(['P2PK', { nonce, data: recipient, tags: [['sigflag', 'SIG_INPUTS']] }]);
const signDigest = (digestHex, sk) => bytesToHex(schnorr.sign(hexToBytes(digestHex), sk));
const hex32 = () => bytesToHex(secp256k1.utils.randomSecretKey());
// Rebuild the unblinded proofs for an outcome from the committed template: the
// destination and the opening (secret + r) are the bidder's, not the caller's.
const unblindCommitted = (template, sigs, params) => template.outputs.map((o, i) => {
  const s = sigs[i];
  const A = secp256k1.Point.fromHex(params.keys[String(s.amount)]);
  const C = secp256k1.Point.fromHex(s.C_).subtract(A.multiply(BigInt('0x' + o.r)));
  return { id: s.id, amount: s.amount, secret: o.secret, C: bytesToHex(C.toBytes(true)) };
});
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

  // Coco makes its outputs from the identity's seed with counters it keeps in
  // IndexedDB. A browser can drop IndexedDB but keep localStorage (where the
  // seed lives); the counters then start again at 0 and the mint refuses
  // every new output as "already signed", so top-ups, received refunds and
  // bids all fail. v0.5.1: on that refusal, run Cashu restore (NUT-09), which
  // moves the counters past every output the mint has signed and brings back
  // the identity's unspent ecash, then try once more.
  async resync(id) {
    const key = walletPub(id);
    this.resyncs ??= new Map();
    if (!this.resyncs.has(key)) {
      this.resyncs.set(key, (async () => { const m = await this.coco(id); await m.wallet.restore(this.mintUrl); })()
        .finally(() => this.resyncs.delete(key)));
    }
    return this.resyncs.get(key);
  }
  async resynced(id, fn) {
    try { return await fn(); } catch (e) {
      if (!/already signed/i.test(String(e?.message || e))) throw e;
      console.warn('wallet counters behind the mint; restoring', e.message);
      await this.resync(id);
      return fn();
    }
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
    await this.resynced(id, () => m.wallet.receive(getEncodedToken({ mint: this.mintUrl, unit: 'sat', proofs })));
    return sum(proofs);
  }

  // Fake sats: the test mint's FakeWallet pays its own invoices. Nutshell 0.20
  // does not move `updated_at` when that happens, which Coco 2 treats as a
  // conflicting observation, so we wait for PAID ourselves and import the
  // settled quote into Coco, then let Coco mint it.
  async faucet(id, amount) { return this.resynced(id, () => this.faucetOnce(id, amount)); }
  async faucetOnce(id, amount) {
    const m = await this.coco(id);
    const pj = (u, b) => fetch(this.mintUrl + u, b ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) } : {}).then((r) => r.json());
    let q = await pj('/v1/mint/quote/bolt11', { amount, unit: 'sat' });
    for (let i = 0; i < 40 && q.state !== 'PAID'; i++) { await sleep(250); q = await pj('/v1/mint/quote/bolt11/' + q.quote); }
    if (q.state !== 'PAID') throw new Error('faucet invoice was not paid');
    const quote = await m.quotes.mint.import({ mintUrl: this.mintUrl, method: 'bolt11', quote: q });
    const op = await m.ops.mint.prepare({ quote, amount });
    let done = await m.ops.mint.execute(op.id);
    for (let i = 0; i < 20 && done.state !== 'finalized'; i++) { await sleep(250); done = await m.ops.mint.get(op.id); }
    if (done.state !== 'finalized') throw new Error('faucet mint did not finish' + (done.error ? ': ' + done.error : ''));
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

  // The auction's identity is (seller, d) — our own coordinate
  // a = 1440:<seller>:<d>, not NIP-01 addressability (1440 is a REGULAR kind,
  // so the relay replaces nothing). The FIRST 1440 for a (seller, d) is the
  // root; its event id is auction_root_event_id, and later 1440s for the same
  // coordinate are supersessions that must carry e = <root> and may change only
  // the display fields (title, description, image, category, name).
  async createAuction(id, lot, d = lot.d) {
    // Every auction needs an auction_id (d); generate one if the caller did
    // not supply it. NIP-01 charset [A-Za-z0-9_-], 1..64 chars.
    if (!d) d = bytesToHex(randomBytes(12));
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(d)) throw new Error('auction d must be 1..64 of [A-Za-z0-9_-]');
    const coord = `${KIND_CREATE}:${idPub(id)}:${d}`;
    const ev = await this.sign(id, KIND_CREATE, { ...lot, sellerWallet: walletPub(id), name: lot.name || id.name }, [['d', d]]);
    const res = await this.submit(ev);
    return { ...res, id: ev.id, rootId: ev.id, d, coord };
  }

  // Supersede an existing auction: same (seller, d), e = the root id, display
  // fields only. A change to an immutable field (start price, increment, mode,
  // window, duration, seller wallet) is refused by the chain with
  // immutable_field_changed and the edit is ignored.
  async editAuction(id, current, patch) {
    const tags = [['d', current.d], ['e', current.rootId]];
    const body = {
      title: patch.title ?? current.title, description: patch.description ?? current.description,
      image: patch.image ?? current.image, category: patch.category ?? current.category,
      startPrice: current.startPrice, minIncrement: current.minIncrement, durationSec: current.durationSec,
      mode: current.mode, windowSec: current.windowSec, sellerWallet: current.sellerWallet,
      name: patch.name ?? current.sellerName,
    };
    const ev = await this.sign(id, KIND_CREATE, body, tags);
    return this.submit(ev);
  }

  // Coco locks `amount` to a 2-of-2 [bidder, committee] SIG_ALL condition: the
  // bidder's own wallet key is the first main key, the validators' FROST group
  // key is the second (one key; 3 of the 4 validators must cooperate to sign
  // for it), n_sigs = 2, refundable to the bidder's own wallet key after
  // locktime. cashu-ts emits exactly the canonical five-tag secret for these
  // options (locktime, pubkeys, n_sigs, refund, sigflag), which is what the
  // chain's strict parser and the mint both require (spec §1.1).
  // Locktime (spec §2.1): minLock = max(end, now + window) + settlement_safety
  // + bid_to_consensus_latency, where `end` is the end THIS bid establishes --
  // an anti-snipe bid with less than the window left resets the clock to the
  // window, so the lock must clear now + window + safety + latency, not the old
  // end.
  async lockForBid(id, amount, params, auction, { force = false, state, now = Date.now() / 1000 } = {}) {
    if (!force) {
      const min = auction.highBid ? auction.highAmount + auction.minIncrement : auction.startPrice;
      if (auction.status !== 'open') throw new Error('auction closed');
      if (amount < min) throw new Error(`bid must be at least ${min} sats`);
      if (state && auction.highBid && state.bids[auction.highBid].bidder === idPub(id)) throw new Error('you are already the highest bidder');
      if ((await this.balance(id)) < amount) throw new Error('not enough sats in wallet');
    }
    return this.resynced(id, () => this.lockOnce(id, amount, params, auction, now));
  }
  async lockOnce(id, amount, params, auction, now) {
    const m = await this.coco(id);
    const safety = num(params.settlementSafetySec ?? 900);
    const latency = num(params.bidToConsensusLatencySec ?? 15);
    // the end this bid establishes: an anti-snipe bid inside the window resets
    // the clock to the window (chain §3), so the lock must clear now+window.
    const window = auction.mode === 'antisnipe' ? num(auction.windowSec) : 0;
    const end = auction.mode === 'antisnipe' ? Math.max(auction.endAt, now + window) : auction.endAt;
    const locktime = Math.ceil(Math.max(end, now + window) + safety + latency);
    const prep = await m.ops.send.prepare({
      mintUrl: this.mintUrl, amount,
      target: { type: 'p2pk', options: {
        kind: 'P2PK',
        data: walletPub(id),                 // first main key: the bidder
        pubkeys: [params.groupKey],          // the rest: the committee (FROST group key)
        requiredSignatures: 2,               // n_sigs = 2
        refundKeys: [walletPub(id)],         // refund branch: the bidder alone, after locktime
        locktime,
        sigFlag: 'SIG_ALL',
      } },
    });
    const { token } = await m.ops.send.execute(prep);
    return { locked: token.proofs.map(plain) };
  }

  // The two exact transactions the bidder pre-signs: settle pays the auction's
  // committed seller payout key, refund returns to the bidder's own wallet key.
  // They travel INSIDE the bid content (json `outcome_templates`), so every
  // validator re-derives each digest and re-checks the bidder's signature at
  // admission, and the committee can submit one of these two transactions with
  // the bidder offline -- without ever choosing a destination itself (spec §1.2).
  buildOutcomeTemplates(id, locked, sellerKey) {
    const spendKey = hexToBytes(id.walletSk);
    const build = (recipient) => {
      if (!/^0[23][0-9a-f]{64}$/.test(recipient)) throw new Error('output recipient must be a compressed secp256k1 key');
      const inputs = locked.map((p) => ({ amount: num(p.amount), id: p.id, secret: String(p.secret), C: String(p.C) }));
      const outputs = locked.map((p) => ({ amount: num(p.amount), id: p.id, secret: buildP2PKOutputSecret(recipient, hex32()), r: hex32() }));
      const unsigned = { inputs, outputs, digest: '', bidder_signature: '' };
      const digest = sigAllTemplateDigest(unsigned);
      return { inputs, outputs, digest, bidder_signature: signDigest(digest, spendKey) };
    };
    return { settle: build(sellerKey), refund: build(walletPub(id)) };
  }

  async bid(id, auction, amount, locked) {
    // Two things ride together here: the bid binds to the auction ROOT, not to
    // the latest version (e = auction_root_event_id), which is what makes an
    // edit non-destructive — and it carries the bidder's two pre-signed
    // outcome templates, which is what pins the destinations (spec §1).
    const root = auction.rootId || auction.rootEventId || auction.id;
    const content = { auction: auction.id, amount, wallet: walletPub(id), name: id.name, proofs: locked,
      outcome_templates: this.buildOutcomeTemplates(id, locked, auction.sellerWallet) };
    const ev = await this.sign(id, KIND_BID, content,
      [['e', root], ...(auction.id && auction.id.includes(':') ? [['a', auction.id]] : [])]);
    const res = await this.submit(ev);
    return { ...res, id: ev.id };
  }

  // Submit one of the two COMMITTED outcome templates. The caller names the bid
  // and the outcome only -- never outputs (the endpoint is deleted, spec §5).
  // The gateway runs one FROST round over the committed template and returns a
  // single aggregated BIP-340 signature; the mint then checks it against the
  // lock (n_sigs=2 for settle, or the refund branch after locktime).
  async claim(id, bid, outcome, params) {
    if (!Array.isArray(bid.proofs) || !bid.outcome_templates) bid = await this.bidWithProofs(bid.id);
    const template = bid.outcome_templates && bid.outcome_templates[outcome];
    if (!template) throw new Error(`bid has no committed ${outcome} template`);
    const outputs = template.outputs.map((o) => ({ amount: o.amount, id: o.id, B_: sigAllOutputPoint(o.secret, o.r) }));
    const sigs = [template.bidder_signature];
    let cosigners, refusals;
    if (outcome === 'settle' || !this.afterLocktime(bid)) {
      // the committee's half is required; ask for it. After locktime the refund
      // needs only the bidder, but going through the template is also fine.
      const rel = await this.submitOutcome(bid.id, outcome);
      sigs.unshift(rel.signature);
      cosigners = rel.cosigners; refusals = rel.refusals;
    }
    const jr = await this.swap(bid.proofs, outputs, sigs);
    if (!jr.signatures) { const e = new Error(jr.detail || 'mint rejected release'); e.mint = jr; throw e; }
    const proofs = unblindCommitted(template, jr.signatures, params);
    await this.receive(id, proofs);
    return { amount: sum(proofs), cosigners, refusals, signature: sigs[0] };
  }

  afterLocktime(bid) { const lt = num(bid.locktime || 0); return lt > 0 && Date.now() / 1000 >= lt; }

  // The committee's half of a release (FROST round over the bid's COMMITTED
  // template). The caller names the bid and the outcome only -- never outputs,
  // and there is no auth: the bidder's half is already inside the template
  // (spec §5). The gateway relays this to every validator's signer and the
  // browser assembles the aggregate signature.
  //
  // NOTE: this is the automated path the settler uses. A page should normally
  // NOT need it -- the settler pushes refunds and the payout, so by the time a
  // bid is due the money has usually already moved. It stays available for the
  // operations view, which is why the route exists at all.
  async submitOutcome(bidId, outcome) {
    try { return await this.j('/api/settle', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bid: bidId, outcome }) }); }
    catch (e) { e.refusals = e.body?.refusals; throw e; }
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
