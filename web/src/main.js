import './template.css';
import './arena.css';
import { newIdentity, ensureSeed, idPub, walletPub, totalSats, lockOf } from './lib/arena.js';
import { WalletClient } from './lib/wallet.js';
import { CATALOGUE, PARODY, randomLot } from './lib/catalogue.js';
import { loginExtension, loginBunker, loginNostrConnect, signerFor, logoutSigner, fetchProfile } from './lib/login.js';

// ---------- basics ----------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const NUM = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 0 });
const fmt = (n) => NUM.format(Math.round(n || 0));
const esc = (t) => String(t ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Listing images: same-site paths only (matches the chain rule and the CSP); anything else shows the placeholder.
const safeSrc = (s) => (/^(\.\/|\/(?!\/))[A-Za-z0-9._~\/-]*$/.test(String(s || '')) ? s : './assets/watch-1.jpg');
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const HMS = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const clock = (s) => HMS.format(new Date(s * 1000));
const rawApi = window.__API_BASE__ || '';
const base = (rawApi && !rawApi.startsWith('__PORT_'))
  ? new URL(rawApi, location.href).href.replace(/\/$/, '')
  : new URL('.', location.href).href.replace(/\/$/, '');
const api = new WalletClient(base); // wallet maths runs in a worker (v0.4.2)
const LS = 'arena.v1.';
// Hosted previews run in a sandboxed iframe without localStorage; fall back to memory.
const store = (() => { try { const t = LS + 'probe'; localStorage.setItem(t, '1'); localStorage.removeItem(t); return localStorage; }
  catch { const m = new Map(); return { getItem: k => m.has(k) ? m.get(k) : null, setItem: (k, v) => m.set(k, String(v)) }; } })();
const load = (k, d) => { try { return JSON.parse(store.getItem(LS + k)) ?? d; } catch { return d; } };
const short = (t, n) => { if (t.length <= n) return t; const c = t.slice(0, n); const sp = c.lastIndexOf(' '); return (sp > 8 ? c.slice(0, sp) : c).replace(/[,·\s]+$/, '') + '…'; };
const save = (k, v) => { try { store.setItem(LS + k, JSON.stringify(v)); } catch {} };

const USERS = ['Seller', 'Alice', 'Bob', 'Carol']; // the demo characters (the bots bid as these)
const COLORS = { Seller: '#FF3EB5', Alice: '#16A35A', Bob: '#F7931A', Carol: '#6C5CE7', You: '#C6FF3D' };
const ids = load('ids', null) || Object.fromEntries(USERS.map((n) => [n, newIdentity(n)]));
delete ids.You;
USERS.forEach((n) => ensureSeed(ids[n]));
save('ids', ids);
const pubToUser = {};
USERS.forEach((n) => { pubToUser[idPub(ids[n])] = n; });

// per-user wallet history: { ledger:[], stranded:[{locked, auction, at}] }; the ecash itself lives in each user's Coco wallet.
// (`proofs` is only read once, to move a pre-Coco v0.1 wallet into Coco.)
const W = load('wallets', {});
USERS.forEach((n) => { W[n] = W[n] || { proofs: [], ledger: [], stranded: [] }; });

// ---------- You: a Nostr login (ADR 0010) ----------
// The login signs events only; the wallet key and Coco seed are made here
// and kept per npub, so logging out and back in keeps the fake sats.
const youKeys = load('youkeys', {}); // pubkey -> { walletSk, seed, ledger, stranded }
let you = load('you', null);         // { signer, pubkey, clientSk?, bunker?, relays, profile? }
const people = () => (ids.You ? [...USERS, 'You'] : USERS);
function adoptYou(login) {
  you = login;
  const k = youKeys[you.pubkey] || (youKeys[you.pubkey] = (({ walletSk, seed }) => ({ walletSk, seed, ledger: [], stranded: [] }))(newIdentity('You')));
  ids.You = { name: you.profile?.name || 'npub ' + you.pubkey.slice(0, 8), pubkey: you.pubkey, walletSk: k.walletSk, seed: k.seed };
  W.You = k; // same object: history saved with the keys
  pubToUser[you.pubkey] = 'You';
  api.signers.set(you.pubkey, signerFor(you, (url) => toast(`Your signer asks you to approve: <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">open</a>`, 'info')));
  save('you', you); save('youkeys', youKeys);
}
const claimed = new Set(load('claimed', []));
const saveW = () => { const { You, ...rest } = W; save('wallets', rest); if (You) save('youkeys', youKeys); save('claimed', [...claimed]); };

const ui = {
  me: load('me', 'Alice'), lot: null, mode: 'bid', ctab: 'bids', img: 0, showLive: true, bots: load('bots', 'chill'),
  autotopup: load('autotopup', true), max: load('max', {}), otab: null,
};
let S = null; // latest chain state
let NET = [];
let CHAT = [];
let offsetMs = 0; // chain time - local time
let busy = new Set();
const seenBids = new Set();
const seenClosed = new Set();
let firstState = true;

const chainNow = () => (Date.now() + offsetMs) / 1000;
const meId = () => ids[ui.me];
const mePub = () => idPub(meId());
const nameOfPub = (pk) => pubToUser[pk] || pk.slice(0, 8);
const nameOfBid = (b) => pubToUser[b.bidder] || `${b.name || 'Guest'} ·${b.bidder.slice(0, 4)}`;
const BAL = {};
const bal = (n) => BAL[n] || 0;
async function refreshBal(n) { BAL[n] = await api.balance(ids[n]); return BAL[n]; }
const ledger = (n, type, amount, note) => { W[n].ledger.unshift({ type, amount, note, ts: Date.now() / 1000 }); W[n].ledger = W[n].ledger.slice(0, 60); };

function avatar(name, size = 28) {
  if (name === 'You' && you?.profile?.picture) return `<span class="av" style="width:${size}px;height:${size}px;background:${COLORS.You};color:#1B1718"><img src="${esc(you.profile.picture)}" alt="" referrerpolicy="no-referrer" loading="lazy" onerror="this.remove()"></span>`;
  if (name === 'Seller') return `<span class="av" style="width:${size}px;height:${size}px"><img src="./assets/live-frame.jpg" alt=""></span>`;
  const c = COLORS[name] || '#7a6f66';
  return `<span class="av" style="width:${size}px;height:${size}px;background:${c}${name === 'You' ? ';color:#1B1718' : ''}">${esc((name || '?')[0].toUpperCase())}</span>`;
}

// ---------- toasts / fx (from the template) ----------
function toast(html, kind = '', action) {
  const box = $('.toasts');
  const t = document.createElement('div');
  t.className = 'toast ' + kind;
  t.innerHTML = `<span>${html}</span>` + (action ? `<button data-act="${action[1]}">${action[0]}</button>` : '');
  box.appendChild(t);
  while (box.children.length > 3) box.firstElementChild.remove();
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 400); }, kind === 'danger' ? 4800 : 3400);
}
function pulse(el, cls) { if (!el) return; el.classList.remove(cls); void el.offsetWidth; el.classList.add(cls); }
function flyCoins(fromEl, n = 7) {
  if (reduce) return pulse($('.wallet-chip'), 'got');
  const to = $('.wallet-chip').getBoundingClientRect();
  const fr = fromEl ? fromEl.getBoundingClientRect() : { left: innerWidth / 2, top: innerHeight / 2, width: 0, height: 0 };
  const layer = $('.fly-layer');
  for (let i = 0; i < n; i++) {
    const c = document.createElement('span'); c.className = 'coin'; c.textContent = '₿';
    layer.appendChild(c);
    const sx = fr.left + fr.width / 2 + (Math.random() - 0.5) * 60, sy = fr.top + fr.height / 2 + (Math.random() - 0.5) * 20;
    const ex = to.left + to.width / 2, ey = to.top + to.height / 2;
    c.animate([
      { transform: `translate(${sx}px,${sy}px) scale(.6)`, opacity: 0 },
      { transform: `translate(${(sx + ex) / 2 + (Math.random() - 0.5) * 120}px,${Math.min(sy, ey) - 60}px) scale(1.1)`, opacity: 1, offset: 0.45 },
      { transform: `translate(${ex}px,${ey}px) scale(.5)`, opacity: 0.2 },
    ], { duration: 900 + i * 70, easing: 'cubic-bezier(.5,0,.3,1)', fill: 'forwards' }).onfinish = () => c.remove();
  }
  setTimeout(() => pulse($('.wallet-chip'), 'got'), 900);
}
const cv = $('.confetti'), cx = cv.getContext('2d'); let parts = [], confRAF = 0;
function confetti() {
  if (reduce) return;
  cv.width = innerWidth * devicePixelRatio; cv.height = innerHeight * devicePixelRatio; cv.style.display = 'block';
  const cols = ['#FF3EB5', '#F7931A', '#C6FF3D', '#FFF4E8', '#6C5CE7', '#00B894'];
  for (let i = 0; i < 220; i++) {
    const left = i % 2 === 0;
    parts.push({ x: (left ? 0.05 : 0.95) * cv.width, y: cv.height * 0.75, vx: (left ? 1 : -1) * (6 + Math.random() * 14) * devicePixelRatio, vy: -(14 + Math.random() * 16) * devicePixelRatio, r: (4 + Math.random() * 6) * devicePixelRatio, c: cols[i % cols.length], a: Math.random() * 6, va: Math.random() * 0.3 - 0.15, life: 0 });
  }
  cancelAnimationFrame(confRAF);
  const step = () => {
    cx.clearRect(0, 0, cv.width, cv.height);
    parts.forEach((p) => { p.vy += 0.42 * devicePixelRatio; p.vx *= 0.985; p.x += p.vx; p.y += p.vy; p.a += p.va; p.life++; cx.save(); cx.translate(p.x, p.y); cx.rotate(p.a); cx.fillStyle = p.c; cx.fillRect(-p.r / 2, -p.r / 4, p.r, p.r / 2); cx.restore(); });
    parts = parts.filter((p) => p.y < cv.height + 40 && p.life < 400);
    if (parts.length) confRAF = requestAnimationFrame(step); else cv.style.display = 'none';
  };
  step();
}
let goingStage = 0;
function going(stage) {
  const g = $('.going');
  if (!stage) { g.classList.remove('show'); return; }
  g.firstElementChild.textContent = ['', 'Going once…', 'Going twice…', 'Last call!'][stage];
  pulse(g, 'show');
}

// ---------- derived state ----------
function lotImages(a) {
  if (!a) return ['./assets/watch-1.jpg'];
  if (!a.image || a.image.includes('watch')) return ['./assets/watch-1.jpg', './assets/watch-2.jpg', './assets/watch-3.jpg', './assets/watch-4.jpg'];
  return [safeSrc(a.image)];
}
const hasVideo = (a) => !a || !a.image || a.image.includes('watch');
function currentLot() {
  if (!S) return null;
  if (ui.lot && S.auctions[ui.lot]) {
    const a = S.auctions[ui.lot];
    if (a.status === 'open' || chainNow() - a.closedAt < 12 || ui.pinned) return a;
  }
  const open = S.order.map((id) => S.auctions[id]).filter((a) => a.status === 'open').sort((x, y) => x.endAt - y.endAt);
  const a = open[0] || S.auctions[S.order[S.order.length - 1]] || null;
  ui.lot = a && a.id; ui.pinned = false;
  return a;
}
// outbid and lost bids are refunded; so are late ("void") ones (ADR 0007)
const refundable = (b) => b.status === 'outbid' || b.status === 'lost' || b.status === 'void';
const proofsOf = (b) => b.proofCount ?? b.proofs?.length ?? 0;
const bidsOf = (a) => (a ? a.bids.map((id) => S.bids[id]) : []);
const minNext = (a) => (a.highBid ? a.highAmount + a.minIncrement : a.startPrice);
const stepAmt = (a, steps) => minNext(a) + steps * a.minIncrement;
const remaining = (a) => Math.max(0, a.endAt - chainNow());
function heldBy(n) {
  if (!S) return 0;
  const pk = idPub(ids[n]);
  return Object.values(S.bids).filter((b) => b.bidder === pk && (b.status === 'leading' || (refundable(b) && !claimed.has(b.id)))).reduce((s, b) => s + b.amount, 0)
    + W[n].stranded.reduce((s, x) => s + totalSats(x.locked), 0);
}
function role(a, n = ui.me) {
  if (!a) return '';
  const pk = idPub(ids[n]);
  if (a.seller === pk) return 'seller';
  const mine = bidsOf(a).filter((b) => b.bidder === pk);
  if (a.status === 'closed') return a.winner && S.bids[a.winner].bidder === pk ? 'winner' : mine.length ? 'loser' : '';
  if (a.highBid && S.bids[a.highBid].bidder === pk) return 'winning';
  return mine.length ? 'outbid' : '';
}

// ---------- wallet ops ----------
const topping = {}; // in-flight faucet per user; a bid waits for it rather than racing the wallet
function topup(n, amount, quiet) {
  if (topping[n]) return topping[n];
  topping[n] = topupNow(n, amount, quiet).finally(() => { delete topping[n]; });
  return topping[n];
}
async function topupNow(n, amount, quiet) {
  BAL[n] = await api.faucet(ids[n], amount);
  ledger(n, 'topup', amount, 'Fake-sats faucet (test mint) · Coco wallet'); saveW();
  if (!quiet && n === ui.me) { pulse($('.wallet-chip'), 'got'); toast(`+${fmt(amount)} fake sats minted`, 'good'); }
}

async function placeBid(n, a, amount, { quiet = false, auto = false, steps = null, maxAmount = Infinity, onAmount, onSent } = {}) {
  const key = 'bid:' + n;
  if (busy.has(key)) return { ok: false, reason: 'previous bid still settling' };
  busy.add(key);
  try {
    if (topping[n]) await topping[n];
    const id = ids[n];
    if (a.seller === idPub(id)) throw new Error("You're the seller of this lot");
    if (bal(n) < amount) {
      if (n !== ui.me || ui.autotopup) await topup(n, Math.max(amount - bal(n) + 1000, 5000), true);
      else throw new Error('Not enough fake sats. Top up in the wallet.');
    }
    // slim view (no proofs): a few KB instead of the full state, so the
    // check-then-lock window is short and bots don't pull MBs per bid
    const fresh = (await api.view([idPub(id)])).state;
    const fa = fresh.auctions[a.id];
    if (!fa) throw new Error('auction closed');
    // one-tap buttons mean "N steps above the current bid", so price them
    // against the view we just read, not the one on screen (ADR 0006)
    if (steps !== null) {
      amount = stepAmt(fa, steps);
      // never more than two increments above what the button showed
      if (amount > maxAmount) throw new Error(`Price moved to ${fmt(fa.highAmount)} · tap again to bid ${fmt(amount)}`);
      onAmount?.(amount);
    }
    if (bal(n) < amount) {
      if (n !== ui.me || ui.autotopup) await topup(n, Math.max(amount - bal(n) + 1000, 5000), true);
      else throw new Error('Not enough fake sats. Top up in the wallet.');
    }
    const { locked } = await api.lockForBid(id, amount, fresh.params, fa, { state: fresh, now: chainNow() });
    try {
      const r = await api.bid(id, fa, amount, locked);
      onSent?.(amount, r);
      if (r.late) {
        // on chain as a void bid: the validators refund it as soon as it lands
        ledger(n, 'hold', amount, `Too late (${r.late}) · refund on its way`);
        saveW(); refreshBal(n).catch(() => {});
        if (n === ui.me && !quiet) toast(`Too late: ${esc(r.late)} · your ${fmt(amount)} sats come straight back`, 'danger');
        return { ok: false, late: true, reason: r.late };
      }
      ledger(n, 'hold', amount, `Locked to the validators' FROST key · ${short(fa.title, 30)}`);
      saveW(); refreshBal(n).catch(() => {});
      if (!quiet || n === ui.me) burst();
      if (n === ui.me && !quiet) toast(`${auto ? 'Max bid raised you to' : 'Bid'} <b>${fmt(amount)}</b> sent · checked by ${esc(r.via)}`, 'good');
      return { ok: true };
    } catch (e) {
      W[n].stranded.push({ locked, auction: a.id, at: Date.now() / 1000 });
      refreshBal(n).catch(() => {});
      ledger(n, 'hold', amount, 'Rejected by validators · reclaimable after locktime');
      saveW();
      throw e;
    }
  } catch (e) {
    const msg = String(e.message || e).replace(/^.*log='([^']+)'.*$/, '$1');
    if (n === ui.me && !quiet) toast(esc(msg), 'danger');
    return { ok: false, reason: msg };
  } finally { busy.delete(key); }
}

// ---------- your bids: instant feedback (ADR 0006) ----------
// `pending` is what the page shows between your tap and the block that
// records it; `queued` is the latest tap made while a bid was in flight.
let pending = null; // { lot, amount, state: 'sending' | 'sent', at }
let queued = null;  // { lot, steps } or { lot, amount }
let humanAt = 0;    // the demo bots in this browser hold off while you bid
const BOT_HOLD_MS = 5000;
const pendingFor = (a) => (pending && a && pending.lot === a.id ? pending : null);
function tapBid(intent, el) {
  const a = currentLot();
  if (!a || a.status !== 'open') return;
  humanAt = Date.now();
  intent = { ...intent, t0: performance.now() };
  navigator.vibrate?.(10);
  pulse(el, 'hit');
  if (role(a) === 'seller') return toast("You're the seller of this lot", 'danger');
  if (pending || busy.has('bid:' + ui.me)) {
    queued = { ...intent, lot: a.id };
    toast('Got it · your next bid goes in as soon as this one lands', 'info');
    return;
  }
  humanBid({ ...intent, lot: a.id }, el);
}
async function humanBid(intent, el) {
  const a = S && S.auctions[intent.lot];
  if (!a) return;
  const shown = intent.amount ?? stepAmt(a, intent.steps);
  const t0 = intent.t0 ?? performance.now();
  const tm = { t0, amount: shown, at: Date.now() };
  timing.unshift(tm); timing.length = Math.min(timing.length, 20);
  pending = { lot: a.id, amount: shown, state: 'sending', at: Date.now(), tm };
  el?.classList.add('sending');
  renderFeeds(currentLot()); kick();
  requestAnimationFrame(() => { tm.shown = performance.now() - t0; renderTimings(); });
  const r = await placeBid(ui.me, a, intent.amount ?? 0, {
    steps: intent.amount == null ? intent.steps : null,
    maxAmount: shown + 2 * a.minIncrement,
    onAmount: (amt) => { if (pending) pending.amount = amt; },
    onSent: (amt, res) => {
      tm.amount = amt; tm.accepted = performance.now() - t0; tm.late = res?.late; tm.id = res?.id;
      if (pending) Object.assign(pending, { amount: amt, state: 'sent', at: Date.now(), id: res?.id });
      renderFeeds(currentLot()); renderTimings(); kick();
    },
  });
  if (!r.ok && !r.late) { tm.failed = r.reason; renderTimings(); }
  el?.classList.remove('sending');
  humanAt = Date.now();
  if (r.ok) pulse(el, 'done');
  else { pending = null; pulse(el, 'shake'); renderFeeds(currentLot()); reconcilePending(); }
}
// Called on every new state: drop the pending bid once its block shows it
// (or it plainly will not), then send a queued tap if you are not leading.
function reconcilePending() {
  if (pending) {
    const a = S.auctions[pending.lot];
    const landed = (pending.id && S.bids[pending.id]) || (a && bidsOf(a).some((b) => b.bidder === mePub() && b.amount === pending.amount));
    if (landed && pending.tm && pending.tm.chain == null) { pending.tm.chain = performance.now() - pending.tm.t0; renderTimings(); }
    if (landed || !a || a.status !== 'open' || (pending.state === 'sent' && Date.now() - pending.at > 10000)) pending = null;
  }
  if (pending || !queued || busy.has('bid:' + ui.me)) return;
  const q = queued; queued = null;
  const a = S.auctions[q.lot];
  if (!a || a.status !== 'open') return;
  if (role(a) === 'winning') return toast("You're leading · extra tap skipped", 'info');
  humanBid(q, null);
}

// refunds, payouts and expired-lock reclaims for every local user
const firstRefundable = new Map(); // bid id -> when this page first saw it refundable
async function settleLoop() {
  if (!S) return;
  const cur = currentLot();
  if (ui.autotopup && cur && cur.status === 'open' && !topping[ui.me] && !busy.has('bid:' + ui.me) && role(cur) !== 'seller' && bal(ui.me) < 2 * stepAmt(cur, 5)) {
    topup(ui.me, Math.max(5000, 3 * stepAmt(cur, 5)), true).catch(() => {});
  }
  for (const n of people()) {
    const pk = idPub(ids[n]);
    for (const b of Object.values(S.bids)) {
      if (claimed.has(b.id) || busy.has('c:' + b.id)) continue;
      const au = S.auctions[b.auction];
      let purpose = null;
      if (b.bidder === pk && refundable(b)) purpose = 'refund';
      if (au.seller === pk && b.status === 'won' && au.sellerWallet === walletPub(ids[n])) purpose = 'payout';
      if (!purpose) continue;
      // ADR 0009: the validators push refunds and payouts. A settled bid's new
      // ecash is collected from the chain if the push was missed; the old
      // pull claim is only the backstop, after 10 s without a push.
      if (!b.settled) {
        const since = firstRefundable.get(b.id) || (firstRefundable.set(b.id, Date.now()), Date.now());
        if (Date.now() - since < 10000) continue;
      }
      busy.add('c:' + b.id);
      try {
        if (b.settled) {
          const full = await api.bidWithProofs(b.id);
          if (claimed.has(b.id) || !full.out?.length) continue;
          await api.receive(ids[n], full.out);
          claimed.add(b.id); await refreshBal(n);
          ledger(n, b.settled === 'payout' ? 'pay' : 'refund', b.amount, `${b.settled === 'payout' ? 'Payout' : 'Refund'} · pushed by the validators (collected)`);
          saveW(); continue;
        }
        const r = await api.claim(ids[n], b, purpose, S.params);
        claimed.add(b.id); await refreshBal(n);
        const who = r.cosigners.map((v) => v.replace('Validator ', 'V')).join(', ');
        if (purpose === 'refund') {
          ledger(n, 'refund', b.amount, `Refund · FROST signature by ${who}`);
          if (n === ui.me) {
            const by = au.highBid && S.bids[au.highBid] ? nameOfBid(S.bids[au.highBid]) : 'the winner';
            toast(b.status === 'void' ? `Late bid · ${fmt(b.amount)} sats refunded by ${who}` : b.status === 'outbid' ? `Outbid by <b>${esc(by)}</b> · ${fmt(b.amount)} sats refunded by ${who}` : `${fmt(b.amount)} sats returned · signed by ${who}`, 'danger', b.status === 'outbid' && au.status === 'open' ? ['Bid again', 'bid-next'] : null);
            flyCoins($('.c-price'));
          }
        } else {
          ledger(n, 'pay', b.amount, `Payout for “${short(au.title, 26)}” · ${who}`);
          if (n === ui.me) { toast(`Payout <b>${fmt(b.amount)}</b> sats received · signed by ${who}`, 'good'); flyCoins($('.c-price'), 10); }
        }
        saveW();
      } catch (e) {
        // spent: the validators pushed it meanwhile; the next state says settled
        if (!/spent|settled/i.test(e.message)) console.warn('claim', b.id, e.message);
      } finally { busy.delete('c:' + b.id); }
    }
    // stranded locks (bid rejected after locking): reclaim alone after locktime
    for (const s of [...W[n].stranded]) {
      const lt = lockOf(s.locked[0])?.locktime || 0;
      if (Date.now() / 1000 < lt + 2 || busy.has('s:' + lt)) continue;
      busy.add('s:' + lt);
      try {
        const got = await api.reclaimExpired(ids[n], s.locked, S.params);
        W[n].stranded = W[n].stranded.filter((x) => x !== s); await refreshBal(n);
        ledger(n, 'refund', got, 'Reclaimed alone after locktime'); saveW();
      } catch (e) { if (/spent/i.test(e.message)) { W[n].stranded = W[n].stranded.filter((x) => x !== s); saveW(); } }
      finally { busy.delete('s:' + lt); }
    }
  }
}

// rivals and max-bid proxy, all through the real flow
let botAt = 0;
async function botLoop() {
  const a = currentLot();
  if (!S || !a || a.status !== 'open') return;
  // my max-bid proxy
  const mx = ui.max[a.id];
  if (mx && role(a) === 'outbid' && minNext(a) <= mx && !busy.has('bid:' + ui.me)) placeBid(ui.me, a, minNext(a), { auto: true });
  if (ui.bots === 'off' || Date.now() < botAt) return;
  if (pending || busy.has('bid:' + ui.me) || Date.now() - humanAt < BOT_HOLD_MS) return;
  const gap = { chill: [6000, 12000], busy: [3000, 6000], frenzy: [1200, 2600] }[ui.bots];
  botAt = Date.now() + gap[0] + Math.random() * (gap[1] - gap[0]);
  const rivals = USERS.filter((n) => n !== ui.me && idPub(ids[n]) !== a.seller && !(a.highBid && S.bids[a.highBid].bidder === idPub(ids[n])));
  if (!rivals.length) return;
  const ceiling = a.startPrice * (ui.bots === 'frenzy' ? 40 : 12);
  if (minNext(a) > ceiling && Math.random() < 0.8) return;
  const n = rivals[Math.floor(Math.random() * rivals.length)];
  const steps = Math.random() < 0.2 ? 2 : 0;
  placeBid(n, a, stepAmt(a, steps), { quiet: true });
}

// ---------- rendering ----------
// [data-v] slots are all in index.html, so each key's elements are looked up once.
const slots = new Map();
function setV(k, v, html = false) {
  let els = slots.get(k);
  if (!els) { els = $$(`[data-v="${k}"]`); slots.set(k, els); }
  els.forEach((el) => {
    if (el._v === v) return; el._v = v;
    if (k === 'ring') el.style.strokeDashoffset = v;
    else if (el.tagName === 'IMG') el.src = v;
    else if (html) el.innerHTML = v; else el.textContent = v;
  });
}

function renderUsers() {
  $('[data-users]').innerHTML = people().map((n) => n === 'You'
    ? `<button role="tab" class="you" aria-selected="${n === ui.me}" data-act="user" data-u="You" title="${esc(ids.You.name)}">${avatar('You', 22)}<span>You</span></button>`
    : `<button role="tab" aria-selected="${n === ui.me}" data-act="user" data-u="${n}"><b>${n[0]}</b><span>${n}</span></button>`).join('')
    + (you ? '' : '<button class="login-chip" data-act="login">Log in</button>');
  setV('youname', you ? ids.You.name : '');
  $('[data-slot=you-row]').hidden = !you;
}

function myStatusHTML(a) {
  const r = role(a);
  if (!a) return '';
  if (r === 'seller') return a.status === 'closed'
    ? `<div class="ms win">${a.winner ? `Sold for ${fmt(a.highAmount)} sats · payout ${claimed.has(a.winner) ? 'received' : 'settling'}` : 'Ended without bids'} <button data-act="outcome">Outcome →</button></div>`
    : `<div class="ms neutral">You're the seller · bidding disabled on your own lot</div>`;
  if (a.status === 'closed') {
    if (r === 'winner') return `<div class="ms win">You won for ${fmt(a.highAmount)} sats <button data-act="outcome">What happens next →</button></div>`;
    if (r === 'loser') return `<div class="ms lose">${esc(nameOfBid(S.bids[a.winner]))} won. Your sats are back. <button data-act="outcome">See outcome →</button></div>`;
    return `<div class="ms neutral">${a.winner ? `Sold to ${esc(nameOfBid(S.bids[a.winner]))} for ${fmt(a.highAmount)}` : 'Ended without bids'} <button data-act="outcome">See outcome →</button></div>`;
  }
  if (r === 'winning') return `<div class="ms win"><span class="pulse"></span>You're the top bidder${ui.max[a.id] ? ' · max ' + fmt(ui.max[a.id]) : ''}</div>`;
  if (r === 'outbid') return `<div class="ms lose">You've been outbid · refund pushed instantly. Bid again?</div>`;
  return '';
}

function timerText(a) {
  if (!a) return '–:––';
  if (a.status !== 'open') return 'Ended';
  const r = remaining(a);
  if (r <= 0) return 'Closing…';
  if (r < 10) return r.toFixed(1) + 's';
  const s = Math.ceil(r), m = Math.floor(s / 60);
  return m + ':' + String(s % 60).padStart(2, '0');
}

// The frame renders ten times a second (the clocks show tenths), and at once
// on the next animation frame after a tap, a key or a new state (kick).
// v0.4.2: it used to run on every animation frame, 60 times a second.
let frameReq = 0, frameTimer = 0;
function kick() { if (!frameReq) frameReq = requestAnimationFrame(() => { frameReq = 0; renderFrame(); }); }
function renderFrame() {
  clearTimeout(frameTimer); frameTimer = setTimeout(kick, 100);
  const a = currentLot();
  if (!S) return;
  const live = a && a.status === 'open';
  setV('balance', fmt(bal(ui.me)));
  setV('held', fmt(heldBy(ui.me)));
  setV('username', ui.me === 'You' ? ids.You.name : ui.me);
  const up = NET.filter((v) => v.up).length;
  setV('netdots', NET.map((v) => `<i class="${v.up ? 'on' : ''}"></i>`).join(''), true);
  setV('consensus', `${up}/4 validators · needs 3`);
  if (a) {
    setV('lotno', a.id.slice(0, 4).toUpperCase());
    setV('title', a.title);
    setV('sellername', a.sellerName || nameOfPub(a.seller));
    // parody lots: show the product, never a face beside a real leader's name
    setV('sellerimg', /^\.\/assets\/merch\//.test(a.image || '') ? safeSrc(a.image) : './assets/live-frame.jpg');
    setV('sellermeta', `npub ${a.seller.slice(0, 8)}… · signed listing`);
    setV('closemode', a.mode === 'antisnipe' ? `Anti-snipe · ${a.windowSec}s` : 'Fixed time');
    setV('parody', /^\.\/assets\/merch\//.test(a.image || '') ? PARODY : '');
    setV('timer', timerText(a));
    const total = Math.max(1, (a.endAt - a.createdAt));
    setV('ring', String(553 * (1 - Math.min(1, remaining(a) / Math.min(total, 120)))));
    setV('ringlabel', a.status !== 'open' ? 'ended' : a.mode === 'antisnipe' ? (a.extensions ? `${a.extensions} reset${a.extensions > 1 ? 's' : ''}` : 'anti-snipe') : 'fixed');
    const pend = live && pendingFor(a) && (!a.highBid || pendingFor(a).amount > a.highAmount) ? pendingFor(a) : null;
    document.body.classList.toggle('is-pending', !!pend);
    setV('pricelabel', pend ? (pend.state === 'sending' ? 'Your bid · sending' : 'Your bid · sent, next block') : live ? (a.highBid ? 'Current bid' : 'Starting bid') : a.winner ? 'Sold for' : 'Final');
    setV('price', fmt(pend ? pend.amount : a.highBid ? a.highAmount : a.startPrice));
    const lead = a.highBid ? S.bids[a.highBid] : null;
    setV('leaderline', pend ? `${avatar(ui.me, 18)} <b>You</b> · ${pend.state === 'sending' ? 'locking sats to the FROST key…' : 'checked by a validator, waiting for the block…'}` : !lead ? `No bids yet · starts at ${fmt(a.startPrice)}` : a.status === 'closed' ? `${avatar(nameOfBid(lead), 18)} <b>${esc(nameOfBid(lead))}</b> won` : `${avatar(nameOfBid(lead), 18)} <b>${esc(nameOfBid(lead))}</b> ${lead.bidder === mePub() ? 'are' : 'is'} winning <span class="crown">♛</span>`, true);
    setV('mystatus', myStatusHTML(a), true);
    setV('step0', fmt(stepAmt(a, 0))); setV('step0b', fmt(stepAmt(a, 0))); setV('step2', fmt(stepAmt(a, 2))); setV('step5', fmt(stepAmt(a, 5)));
    setV('bidcta', ui.mode === 'max' ? 'Set max bid' : 'Place bid');
    const bs = bidsOf(a);
    setV('bidcountn', String(bs.length));
    setV('bidders', String(new Set(bs.map((b) => b.bidder)).size));
    setV('extensionsn', String(a.extensions));
    setV('escrownote', `Bids lock ecash to one FROST key the 4 validators share; any 3 can sign. Outbid? The validators sign and push your refund at once; the winner's sats go to the seller the moment the clock hits zero. Fallback: ${a.mode === 'antisnipe' ? 'while the clock keeps resetting the validators re-lock the leading bid, and you can reclaim alone after its locktime' : `you can reclaim alone after ${clock(a.endAt + S.params.lockMarginSec + 15)}`}.`);
    const r = remaining(a);
    $$('[data-urgent]').forEach((el) => { el.classList.toggle('urgent', live && r < 10); el.classList.toggle('ended', !live); });
    document.body.classList.toggle('is-ended', !live);
    document.body.classList.toggle('is-winning', live && role(a) === 'winning');
    const block = !live || role(a) === 'seller';
    $$('[data-act^=bid], [data-swipe]').forEach((b) => { b.toggleAttribute('disabled', block); b.classList.toggle('disabled', block); });
    $$('[data-in=bid]').forEach((inp) => {
      const v = parseInt((inp.value || '').replace(/\D/g, ''), 10) || 0;
      if (document.activeElement !== inp && (!inp._dirty || v < minNext(a))) { inp.value = fmt(minNext(a)); inp._dirty = false; }
    });
    // going once / twice
    if (live && a.extensions >= 0) {
      const st = r < 2 ? 3 : r < 4 ? 2 : r < 6 ? 1 : 0;
      if (st !== goingStage) { goingStage = st; if (st) going(st); }
    }
  }
}

function renderMedia(a) {
  const imgs = lotImages(a);
  const vid = hasVideo(a) && ui.showLive;
  $('.c-video').hidden = !vid;
  $('.c-still').hidden = vid;
  $('.c-strip-live').hidden = !hasVideo(a);
  $('.c-strip-live').classList.toggle('on', vid);
  setV('mainimg', imgs[ui.img % imgs.length]);
  const html = imgs.map((src, i) => `<button class="thumb ${!vid && i === ui.img % imgs.length ? 'on' : ''}" data-act="img" data-i="${i}" aria-label="Photo ${i + 1}"><img src="${esc(safeSrc(src))}" alt=""></button>`).join('');
  const box = $('[data-thumbs]'); if (box._h !== html) { box.innerHTML = html; box._h = html; }
}

function renderFeeds(a) {
  const ol = $('[data-feed=bids]');
  const bs = bidsOf(a).slice().reverse();
  const pend = pendingFor(a);
  const key = (a ? a.id : '') + bs.map((b) => b.id + b.status).join() + (pend ? pend.state + pend.amount : '');
  if (ol._k !== key) {
    const fresh = ol._lot === (a && a.id);
    const prow = pend ? `<li class="bid-item top mine pending">${avatar(ui.me)}<span class="bi-name">You<em class="tag-auto">${pend.state === 'sending' ? 'sending' : 'next block'}</em></span><span class="bi-amt">${fmt(pend.amount)}</span><time>now</time></li>` : '';
    ol.innerHTML = prow + (bs.length || pend ? '' : '<li class="empty">The arena is quiet…</li>') + (!bs.length ? '' : bs.map((b, i) => `<li class="bid-item ${i === 0 && !pend ? 'top' : ''} ${b.bidder === mePub() ? 'mine' : ''} ${fresh && !ol._seen?.has(b.id) ? 'enter' : ''}">${avatar(nameOfBid(b))}<span class="bi-name">${esc(nameOfBid(b))}${b.extended ? '<em class="tag-jump">reset</em>' : ''}${b.status === 'outbid' || b.status === 'lost' ? `<em class="tag-auto">${claimed.has(b.id) || b.settled ? 'refunded' : 'refunding'}</em>` : ''}</span><span class="bi-amt">${fmt(b.amount)}</span><time>${clock(b.time)}</time></li>`).join(''));
    ol._k = key; ol._lot = a && a.id; ol._seen = new Set(bs.map((b) => b.id));
  }
  // leaderboard
  const top = {};
  bidsOf(a).forEach((b) => { const n = nameOfBid(b); top[n] = Math.max(top[n] || 0, b.amount); });
  const rows = Object.entries(top).sort((x, y) => y[1] - x[1]).slice(0, 8);
  const lb = $('[data-slot=leaderboard]');
  const lk = JSON.stringify(rows) + ui.me;
  if (lb._k !== lk) {
    lb._k = lk;
    const max = rows.length ? rows[0][1] : 1;
    lb.innerHTML = rows.length ? rows.map(([n, amt], i) => `<li class="lb ${n === ui.me ? 'mine' : ''} ${i === 0 ? 'first' : ''}"><span class="lb-rank">${i + 1}</span>${avatar(n, 26)}<span class="lb-name">${esc(n)}</span><span class="lb-bar"><i style="width:${(amt / max) * 100}%"></i></span><span class="lb-amt">${fmt(amt)}</span></li>`).join('') : '<li class="empty">No bidders yet</li>';
  }
  // ticker
  const tk = $('[data-ticker]');
  const items = Object.values(S.bids).sort((x, y) => y.height - x.height).slice(0, 8).map((b) => `<span>${esc(nameOfBid(b)).toUpperCase()} → <b>${fmt(b.amount)}</b> · ${esc(short(S.auctions[b.auction].title, 26))}</span>`);
  const th = (items.length ? items : ['<span>NO BIDS YET</span>', '<span>BE FIRST</span>']).concat(`<span>BLOCK <b>${S.height}</b> · ${NET.filter((v) => v.up).length}/4 VALIDATORS</span>`).join('');
  if (tk._h !== th) { tk.innerHTML = th + th; tk._h = th; }
  // chain feed
  const cf = $('[data-feed=chain]');
  const rej = S.rejections.slice().reverse().slice(0, 6).map((r) => `<li class="chain-item bad"><b>Rejected</b> ${esc(r.reason)}<time>block ${r.height}</time></li>`);
  const evs = Object.values(S.bids).filter((b) => b.auction === (a && a.id)).sort((x, y) => y.height - x.height).slice(0, 10).map((b) => `<li class="chain-item"><b>${esc(nameOfBid(b))} ${fmt(b.amount)}</b> · ${proofsOf(b)} proofs locked to FROST key · DLEQ ok<time>block ${b.height} · ${b.id.slice(0, 10)}…</time></li>`);
  const ch = [`<li class="chain-item head">Height <b>${S.height}</b> · ${S.txCount} txs accepted · app hash agreed by ${new Set(NET.filter((v) => v.up && v.height === S.height).map((v) => v.appHash)).size === 1 ? NET.filter((v) => v.up && v.height === S.height).length : '–'} nodes</li>`, ...evs, ...rej].join('');
  if (cf._h !== ch) { cf.innerHTML = ch; cf._h = ch; }
}

function renderChat(a) {
  const ol = $('[data-feed=comments]');
  const msgs = CHAT.filter((m) => m.tags?.some((t) => t[0] === 'e' && t[1] === (a && a.id))).slice(-60).reverse();
  const k = msgs.map((m) => m.id).join();
  if (ol._k === k) return; ol._k = k;
  ol.innerHTML = msgs.length ? msgs.map((m) => { const n = nameOfPub(m.pubkey); const seller = a && m.pubkey === a.seller; return `<li class="com-item ${seller ? 'seller' : ''} ${m.pubkey === mePub() ? 'mine' : ''}">${avatar(n, 26)}<div><b>${esc(n)}${seller ? ' <span class="badge">Seller</span>' : ''}</b><p>${esc(m.content)}</p></div></li>`; }).join('') : '<li class="empty">Say hello. Messages are signed Nostr events.</li>';
}

function renderQueue(a) {
  const others = S.order.map((id) => S.auctions[id]).filter((x) => x.id !== (a && a.id)).sort((x, y) => (x.status === y.status ? x.endAt - y.endAt : x.status === 'open' ? -1 : 1)).slice(0, 8);
  const h = others.map((x) => `<button class="nx ${x.status}" data-act="pick-lot" data-id="${esc(x.id)}"><img src="${esc(lotImages(x)[0])}" alt=""><div><b>${esc(x.title)}</b><small>${x.status === 'open' ? `${fmt(x.highBid ? x.highAmount : x.startPrice)} sats · ${timerText(x)}` : x.winner ? `Sold ${fmt(x.highAmount)} sats` : 'Ended, no bids'}</small></div></button>`).join('') || '<p class="muted">No other lots yet. List one.</p>';
  const box = $('[data-slot=queue]'); if (box._h !== h) { box.innerHTML = h; box._h = h; }
}

function renderNetwork() {
  const up = NET.filter((v) => v.up).length;
  const strip = NET.map((v) => `<button class="v-chip ${v.up ? 'on' : 'off'}" data-act="network"><i></i>${esc(v.name.replace('Validator ', 'V'))}<small>${v.up ? '#' + v.height : 'offline'}</small></button>`).join('');
  const vs = $('[data-slot=vstrip]'); if (vs._h !== strip) { vs.innerHTML = `<span class="muted">Consensus</span>${strip}`; vs._h = strip; }
  setV('netsummary', `${up} of 4 validators online. Blocks need 3 signatures; escrow releases need a FROST signature from 3. ${up >= 3 ? 'The arena keeps running.' : 'Below threshold: the chain is paused until a validator returns.'}`);
  const cards = NET.map((v) => `<div class="v-card ${v.up ? 'on' : 'off'}"><div class="v-top"><i></i><b>${esc(v.name)}</b><button class="btn-ghost sm" data-act="${v.up || v.process ? 'v-stop' : 'v-start'}" data-i="${v.index}">${v.up || v.process ? 'Stop' : 'Start'}</button></div>
    <div class="v-meta"><span>Height <b>${v.height ?? '–'}</b></span><span>Peers <b>${v.peers ?? '–'}</b></span><span>App hash <b>${v.appHash ? v.appHash.slice(0, 10) : '–'}</b></span></div>
    <div class="v-sigs">${(v.signers || []).map((s, i) => `<span class="${s ? 'y' : 'n'}" title="Validator ${i + 1} ${s ? 'signed' : 'missing'}">V${i + 1}</span>`).join('')}<small>signed last block</small></div>
    <div class="v-key">${v.frostParticipant ? `FROST share ${v.frostParticipant} of 4 · group key ${v.groupKey.slice(0, 14)}…` : '–'}</div></div>`).join('');
  const vc = $('[data-slot=vcards]'); if (vc._h !== cards) { vc.innerHTML = cards; vc._h = cards; }
  const rj = S ? S.rejections.slice().reverse().slice(0, 12).map((r) => `<li class="lg pay"><span class="lg-type">Block ${r.height}</span><span class="lg-note">${esc(r.reason)}<time>${clock(r.time)} · ${esc(nameOfPub(r.pubkey || ''))}</time></span><b></b></li>`).join('') : '';
  const rb = $('[data-slot=rejections]'); const rh = rj || '<li class="empty">Nothing rejected yet.</li>'; if (rb._h !== rh) { rb.innerHTML = rh; rb._h = rh; }
  $$('[data-seg=bots] button').forEach((b) => b.classList.toggle('on', b.dataset.v === ui.bots));
}

function renderWallet() {
  const n = ui.me, pk = mePub();
  const label = { topup: 'Added', hold: 'Locked', refund: 'Refunded', pay: 'Payout' };
  const lh = W[n].ledger.slice(0, 30).map((l) => `<li class="lg ${l.type}"><span class="lg-type">${label[l.type]}</span><span class="lg-note">${esc(l.note)}<time>${clock(l.ts)}</time></span><b>${l.type === 'hold' ? '−' : '+'}${fmt(l.amount)}</b></li>`).join('') || '<li class="empty">No activity yet.</li>';
  const lb = $('[data-slot=ledger]'); if (lb._h !== lh) { lb.innerHTML = lh; lb._h = lh; }
  const es = S ? Object.values(S.bids).filter((b) => b.bidder === pk).sort((x, y) => y.height - x.height).slice(0, 12) : [];
  const eh = es.map((b) => { const st = claimed.has(b.id) ? 'released' : b.status; return `<li class="lg ${st === 'leading' ? 'hold' : st === 'won' ? 'pay' : 'refund'}"><span class="lg-type">${{ leading: 'Leading', outbid: 'Refunding', lost: 'Refunding', void: 'Too late', won: 'Won', released: b.status === 'won' ? 'Paid' : 'Refunded' }[st]}</span><span class="lg-note">${esc(S.auctions[b.auction].title.slice(0, 30))}<time>block ${b.height} · ${proofsOf(b)} proofs · FROST 3-of-4</time></span><b>${fmt(b.amount)}</b></li>`; }).join('')
    + W[n].stranded.map((s) => `<li class="lg hold"><span class="lg-type">Stranded</span><span class="lg-note">Rejected bid · reclaim after<time>${clock(lockOf(s.locked[0])?.locktime || 0)}</time></span><b>${fmt(totalSats(s.locked))}</b></li>`).join('');
  const eb = $('[data-slot=escrows]'); const ehh = eh || '<li class="empty">No escrows.</li>'; if (eb._h !== ehh) { eb.innerHTML = ehh; eb._h = ehh; }
  setV('keys', `Nostr ${idPub(meId()).slice(0, 16)}… · wallet ${walletPub(meId()).slice(0, 18)}…`);
  $('[data-in=autotopup]').checked = ui.autotopup;
}

// outcome screens built from agreed chain state
function outcomeHTML(a, tab) {
  if (!a) return '';
  if (a.status !== 'closed') return `<div class="o-hero neutral"><h2>The auction is still live</h2><p>Outcome screens appear when validators close the lot at block time ≥ end.</p></div>`;
  const price = fmt(a.highAmount);
  if (!a.winner) return `<div class="o-hero neutral"><h2>No sale this time</h2><p>Nobody bid on this lot.</p></div>`;
  const w = S.bids[a.winner], wn = esc(nameOfBid(w));
  const losers = bidsOf(a).filter((b) => b.id !== a.winner);
  const facts = (rows) => `<div class="o-facts">${rows.map(([k, v]) => `<div><small>${k}</small><b>${v}</b></div>`).join('')}</div>`;
  if (tab === 'winner') {
    const isMe = w.bidder === mePub();
    return `<div class="o-hero win">${isMe ? '' : `<span class="o-eyebrow">Preview · what ${wn} sees</span>`}<div class="o-trophy">♛</div><h2>${isMe ? 'You won!' : wn + ' won!'}</h2><p>${esc(a.title)} · <b>${price} sats</b></p>
      ${facts([['Paid from escrow', price], ['Closed at block', a.closedHeight], ['Payout to seller', claimed.has(a.winner) ? 'Released' : 'Settling']])}</div>`;
  }
  if (tab === 'seller') {
    return `<div class="o-hero sell"><span class="o-eyebrow">Seller view · ${esc(a.sellerName || 'Seller')}${/^\.\/assets\/merch\//.test(a.image || '') ? ' · ' + PARODY : ''}</span><h2>Sold for ${price} sats</h2><p>to <b>${wn}</b> · ${a.bids.length} bids from ${new Set(bidsOf(a).map((b) => b.bidder)).size} bidders · ${a.mode === 'antisnipe' ? a.extensions + ' clock resets' : 'fixed time'}</p>
      ${facts([['Hammer price', price], ['Escrow release', 'FROST, 3 of 4'], ['Payout', claimed.has(a.winner) || role(a) !== 'seller' ? 'Released to wallet' : 'Settling…']])}</div>`;
  }
  const refunded = losers.filter((b) => claimed.has(b.id)).reduce((s, b) => s + b.amount, 0);
  const total = losers.reduce((s, b) => s + b.amount, 0);
  return `<div class="o-hero lose"><h2>Outbid this time</h2><p>${wn} won at <b>${price} sats</b>. ${losers.length} losing bids.</p>
    <div class="refund-card"><span class="rf-ico">↩</span><div><b>${fmt(total)} sats in losing escrows · ${fmt(refunded)} returned by this browser's users</b><small>Each refund is one FROST signature made by 3 of the 4 validators and pushed to the bidder's wallet the moment a bid is beaten. If validators vanish, bidders reclaim alone after locktime.</small></div></div></div>`;
}
function openOutcome(tab) {
  const a = currentLot();
  if (!tab) { const r = role(a); tab = r === 'winner' ? 'winner' : r === 'seller' ? 'seller' : r === 'loser' ? 'loser' : ui.otab || 'winner'; }
  ui.otab = tab;
  $$('[data-act=otab]').forEach((b) => b.classList.toggle('on', b.dataset.o === tab));
  $('[data-slot=outcome]').innerHTML = outcomeHTML(a, tab);
  $('[data-modal=outcome]').hidden = false;
}

function onNewState(prev) {
  const a = currentLot();
  if (prev && !firstState) {
    for (const r of S.rejections.slice(prev.rejections.length)) {
      if (r.kind === 1441 && r.pubkey === mePub()) toast(`Bid not accepted: ${esc(r.reason)}. Those sats return to your wallet automatically after the escrow locktime.`, 'danger');
    }
  }
  // closing moments
  for (const id of S.order) {
    const au = S.auctions[id];
    if (au.status === 'closed' && !seenClosed.has(id)) {
      seenClosed.add(id);
      if (firstState) continue;
      if (id === (a && a.id) || chainNow() - au.closedAt < 8) {
        ui.lot = id; ui.pinned = true;
        going(0); goingStage = 0;
        const stamp = $('.sold-stamp');
        $('i', stamp).textContent = id.slice(0, 4).toUpperCase();
        $('b', stamp).textContent = au.winner ? 'SOLD' : 'UNSOLD';
        $('em', stamp).textContent = au.winner ? `to ${nameOfBid(S.bids[au.winner])} · ${fmt(au.highAmount)} sats` : 'no bids';
        stamp.classList.add('show');
        const r = role(au);
        if (r === 'winner' || r === 'seller') confetti();
        setTimeout(() => { stamp.classList.remove('show'); if (r) openOutcome(); setTimeout(() => { ui.pinned = false; }, 9000); }, 2300);
      }
    }
  }
  // new bids: extension toast + feed animation
  for (const b of Object.values(S.bids)) {
    if (seenBids.has(b.id)) continue;
    seenBids.add(b.id);
    if (firstState) continue;
    if (b.auction === (a && a.id)) {
      if (b.extended) { toast(`Late bid! Clock back to <b>${S.auctions[b.auction].windowSec}s</b>`, 'info'); $$('[data-v=timer]').forEach((el) => pulse(el, 'extend')); }
      if (b.bidder === mePub()) pulse($('.c-price'), 'bump');
    }
  }
  firstState = false;
}

// ---------- timings (Network drawer) ----------
const timing = []; // last 20 of your bids: ms from tap to shown / accepted / in a block
let rtt = 0;       // smoothed round trip to the gateway, ms
function renderTimings() {
  const ms = (v) => (v == null ? '…' : v < 1000 ? Math.round(v) + ' ms' : (v / 1000).toFixed(1) + ' s');
  const h = timing.map((t) => `<li class="lg ${t.failed ? 'pay' : t.late ? 'refund' : 'hold'}"><span class="lg-type">${fmt(t.amount)}</span><span class="lg-note">${t.failed ? esc(short(t.failed, 40)) : t.late ? 'Too late · refunded' : 'Bid'}<time>shown ${ms(t.shown)} · accepted ${t.failed ? '–' : ms(t.accepted)} · in block ${t.failed ? '–' : ms(t.chain)}</time></span><b>${clock(t.at / 1000)}</b></li>`).join('')
    || '<li class="empty">Bid and the timings show here.</li>';
  const box = $('[data-slot=timings]'); if (box && box._h !== h) { box.innerHTML = h; box._h = h; }
  setV('pushmode', push.open ? `pushed the moment a block commits · round trip ${Math.round(rtt)} ms` : `polled every second · round trip ${Math.round(rtt)} ms`);
}

// ---------- push (ADR 0007) ----------
// The gateway says "new block" over Server-Sent Events; the page then reads
// the state at once. Polling stays as the fallback, slowed while push works.
const push = { open: false, h: 0, es: null };
function startPush() {
  if (typeof EventSource === 'undefined') return;
  const es = new EventSource(base + '/api/events');
  push.es = es;
  es.onopen = () => { push.open = true; renderTimings(); };
  es.onerror = () => { push.open = false; renderTimings(); }; // the browser retries by itself
  es.onmessage = (m) => {
    let d; try { d = JSON.parse(m.data); } catch { return; }
    if (d.type === 'settled') return onSettled(d);
    if (d.now) offsetMs = d.now - Date.now();
    if (d.h > push.h) { push.h = d.h; if (S) S.height = Math.max(S.height, d.h); pollState(); }
  };
}

// ADR 0009: the validators pushed new ecash (a refund or a payout) to a
// wallet key. If it is one of this browser's people, take it into Coco.
async function onSettled(d) {
  const n = people().find((x) => walletPub(ids[x]) === d.to);
  if (!n || claimed.has(d.bid) || busy.has('c:' + d.bid)) return;
  busy.add('c:' + d.bid);
  try {
    await api.receive(ids[n], d.proofs);
    claimed.add(d.bid); await refreshBal(n);
    const who = (d.cosigners || []).map((v) => v.replace('Validator ', 'V')).join(', ');
    const ms = d.ms ? ` · ${d.ms.total} ms` : '';
    const amt = (d.proofs || []).reduce((s, p) => s + p.amount, 0);
    const b = S?.bids[d.bid], au = S?.auctions[d.auction];
    if (d.move === 'payout') {
      ledger(n, 'pay', amt, `Payout for “${short(au?.title || '', 26)}” · pushed, FROST ${who}${ms}`);
      if (n === ui.me) { toast(`Payout <b>${fmt(amt)}</b> sats pushed to your wallet · ${who}${ms}`, 'good'); flyCoins($('.c-price'), 10); }
    } else {
      ledger(n, 'refund', amt, `Refund pushed · FROST ${who}${ms}`);
      if (n === ui.me) {
        const by = au?.highBid && S.bids[au.highBid] ? nameOfBid(S.bids[au.highBid]) : 'the winner';
        toast(b?.status === 'void' ? `Late bid · ${fmt(amt)} sats pushed back${ms}` : b?.status === 'outbid' ? `Outbid by <b>${esc(by)}</b> · ${fmt(amt)} sats pushed back${ms}` : `${fmt(amt)} sats returned${ms}`, 'danger', b?.status === 'outbid' && au?.status === 'open' ? ['Bid again', 'bid-next'] : null);
        flyCoins($('.c-price'));
      }
    }
    saveW(); renderWallet(); kick();
  } catch (e) { console.warn('pushed ecash', d.bid, e.message); } finally { busy.delete('c:' + d.bid); }
}

// ---------- polling ----------
let stateTag = '';
let polling = false;
// After an action, poll fast for a few seconds so the result shows the moment
// its block commits (~1 s) instead of up to a poll later. 304s cost no body.
let burstUntil = 0;
function burst(ms = 3000) {
  if (push.open) return; // blocks are pushed
  const first = burstUntil < Date.now();
  burstUntil = Date.now() + ms;
  if (first) (async function tick() { await pollState(); if (Date.now() < burstUntil) setTimeout(tick, 250); })();
}
async function pollState() {
  if (polling) return;
  polling = true;
  try {
    const prev = S;
    const q0 = performance.now();
    const r = await api.view(people().map((n) => idPub(ids[n])), stateTag);
    rtt = rtt ? rtt * 0.7 + (performance.now() - q0) * 0.3 : performance.now() - q0;
    if (!r) { renderFeeds(currentLot()); return; } // unchanged: the frame loop keeps the clocks moving
    S = r.state; stateTag = r.etag;
    if (NET.length) S.height = Math.max(S.height, ...NET.map((v) => v.height || 0));
    // the validator's wall clock, not the last block's time: with blocks on
    // demand the last block can be a minute old (ADR 0003 §1)
    offsetMs = S.now ? S.now + rtt / 2 - Date.now() : S.time * 1000 + 500 - Date.now();
    for (const tm of timing) if (tm.id && tm.chain == null && S.bids[tm.id]) { tm.chain = performance.now() - tm.t0; renderTimings(); }
    onNewState(prev);
    reconcilePending();
    const a = currentLot();
    document.body.classList.toggle('arena-loading', !a);
    renderMedia(a); renderFeeds(a); renderChat(a); renderQueue(a); renderWallet(); kick();
    if (!$('[data-modal=outcome]').hidden) $('[data-slot=outcome]').innerHTML = outcomeHTML(a, ui.otab);
  } catch (e) { /* gateway down */ } finally { polling = false; }
}
async function pollNet() { try { NET = await api.network(); if (S) S.height = Math.max(S.height, ...NET.map((v) => v.height || 0)); renderNetwork(); } catch {} }
async function pollChat() { try { CHAT = await api.chat(); renderChat(currentLot()); } catch {} }

// ---------- seeding ----------
async function seedIfEmpty() {
  if (!S) return;
  const open = Object.values(S.auctions).filter((a) => a.status === 'open');
  if (open.length) return;
  const pool = [...CATALOGUE].sort(() => Math.random() - 0.5).slice(0, 3);
  for (const [i, item] of pool.entries()) await api.createAuction(ids.Seller, randomLot(i % 2 ? 'antisnipe' : 'fixed', item)).catch(() => {});
  setTimeout(pollState, 1500);
}

// ---------- events ----------
document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const act = el.dataset.act; const a = currentLot();
  switch (act) {
    case 'user': if (el.dataset.u === 'You' && ui.me === 'You') { $('[data-modal=login]').hidden = false; break; } ui.me = el.dataset.u; save('me', ui.me); renderUsers(); renderWallet(); pollState(); toast(`Now acting as <b>${ui.me}</b>`, 'info'); break;
    case 'wallet': renderWallet(); $('[data-drawer=wallet]').hidden = false; break;
    case 'network': renderNetwork(); $('[data-drawer=network]').hidden = false; break;
    case 'new-lot': $('[data-drawer=newlot]').hidden = false; break;
    case 'quick-lot': {
      if (Date.now() - quickAt < 30000) { toast(`One quick lot every 30 s · next in ${Math.ceil((30000 - Date.now() + quickAt) / 1000)}s`, 'info'); break; }
      quickAt = Date.now();
      const lot = randomLot(el.dataset.mode);
      try {
        const r = await api.createAuction(meId(), lot);
        toast(`Listed <b>${esc(short(lot.title, 30))}</b> as ${esc(lot.name)} · ${lot.mode === 'antisnipe' ? `anti-snipe ${lot.windowSec}s` : 'fixed time'}`, 'good');
        $$('.drawer').forEach((x) => { x.hidden = true; });
        ui.lot = r.id; ui.pinned = true; burst();
      } catch (err) { quickAt = 0; toast(esc(String(err.message).replace(/^.*log='([^']+)'.*$/, '$1')), 'danger'); }
      break;
    }
    case 'login': $('[data-modal=login]').hidden = false; break;
    case 'login-ext': doLogin(() => loginExtension()); break;
    case 'login-bunker': doLogin(() => loginBunker($('[data-in=bunker]').value, authUrl)); break;
    case 'login-connect': {
      connectAbort?.abort(); connectAbort = new AbortController();
      doLogin(() => loginNostrConnect((uri) => { const l = $('[data-slot=connect-uri]'); l.hidden = false; $('a', l).href = uri; $('code', l).textContent = uri; }, connectAbort.signal));
      break;
    }
    case 'copy-uri': navigator.clipboard?.writeText($('[data-slot=connect-uri] code').textContent).then(() => toast('Copied', 'info')); break;
    case 'logout': {
      await logoutSigner(you); api.signers.delete(you.pubkey);
      delete pubToUser[you.pubkey]; delete ids.You; delete W.You; you = null; store.removeItem(LS + 'you');
      if (ui.me === 'You') { ui.me = 'Alice'; save('me', ui.me); }
      $$('.modal').forEach((d) => { d.hidden = true; }); renderUsers(); renderWallet(); pollState(); toast('Logged out · your wallet stays in this browser for next time', 'info');
      break;
    }
    case 'close-drawer': $$('.drawer').forEach((d) => { d.hidden = true; }); break;
    case 'close-modal': $$('.modal').forEach((d) => { d.hidden = true; }); break;
    case 'seller-sheet': if (a) { $('[data-slot=seller-full]').innerHTML = `<div class="sc-top"><img class="sc-av" src="${/^\.\/assets\/merch\//.test(a.image || '') ? esc(safeSrc(a.image)) : './assets/live-frame.jpg'}" alt=""><div><b>${esc(a.sellerName || 'Seller')}</b><small>npub hex ${esc(a.seller.slice(0, 24))}…</small></div></div><p class="sc-foot">Listing is a signed Nostr event (kind 1440). Payouts go only to the wallet key declared in it: ${esc(a.sellerWallet.slice(0, 20))}…</p>`; $('[data-modal=seller]').hidden = false; } break;
    case 'topup': el.classList.add('disabled'); try { await topup(ui.me, +el.dataset.amt); } catch (err) { toast(esc(err.message), 'danger'); } el.classList.remove('disabled'); renderWallet(); break;
    case 'bid-step': case 'bid-next': tapBid({ steps: +(el.dataset.steps || 0) }, act === 'bid-step' ? el : null); break;
    case 'bid-custom': {
      if (!a) break;
      const inp = $('[data-in=bid]'); const amt = parseInt(inp.value.replace(/\D/g, ''), 10) || 0;
      if (ui.mode === 'max') {
        if (amt < minNext(a)) { toast(`Max must be at least ${fmt(minNext(a))}`, 'danger'); break; }
        ui.max[a.id] = amt; save('max', ui.max); toast(`Max bid set to <b>${fmt(amt)}</b>. This browser bids for you one step at a time.`, 'good');
        if (role(a) !== 'winning') placeBid(ui.me, a, minNext(a), { auto: true });
      } else if (amt < minNext(a)) { toast(`Bid must be at least ${fmt(minNext(a))}`, 'danger'); pulse(inp.parentElement, 'shake'); }
      else tapBid({ amount: amt }, el);
      break;
    }
    case 'mode': ui.mode = el.dataset.mode; $$('[data-act=mode]').forEach((b) => b.classList.toggle('on', b === el)); break;
    case 'ctab': ui.ctab = el.dataset.tab; $$('[data-act=ctab]').forEach((b) => b.classList.toggle('on', b === el)); $$('.c-pane').forEach((p) => { p.hidden = p.dataset.pane !== ui.ctab; }); break;
    case 'img': ui.img = +el.dataset.i; ui.showLive = false; renderMedia(a); break;
    case 'show-live': ui.showLive = true; renderMedia(a); break;
    case 'pick-lot': ui.lot = el.dataset.id; ui.pinned = true; ui.img = 0; ui.showLive = true; pollState(); scrollTo({ top: 0, behavior: 'smooth' }); break;
    case 'outcome': openOutcome(); break;
    case 'otab': openOutcome(el.dataset.o); break;
    case 'v-stop': case 'v-start': {
      el.classList.add('disabled');
      try { await api.j(`/api/admin/validator/${el.dataset.i}/${act === 'v-stop' ? 'stop' : 'start'}`, { method: 'POST' }); toast(`Validator ${el.dataset.i} ${act === 'v-stop' ? 'stopped. 3 of 4 keep the arena running.' : 'restarting · it will replay blocks and catch up.'}`, 'info'); } catch (err) { toast(esc(err.message), 'danger'); }
      setTimeout(pollNet, 600); break;
    }
  }
  if (el.closest('[data-seg=bots]') && el.dataset.v) { ui.bots = el.dataset.v; save('bots', ui.bots); renderNetwork(); }
});
document.addEventListener('change', (e) => { if (e.target.matches('[data-in=autotopup]')) { ui.autotopup = e.target.checked; save('autotopup', ui.autotopup); } });
document.addEventListener('input', (e) => { if (e.target.matches('[data-in=bid]')) e.target._dirty = true; });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $$('.drawer,.modal').forEach((d) => { d.hidden = true; }); });
document.addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  if (f.matches('[data-act=comment-form]')) {
    const inp = $('[data-in=comment]', f); const t = inp.value.trim(); const a = currentLot();
    if (!t || !a) return; inp.value = '';
    try { await api.postChat(meId(), a.id, t); pollChat(); } catch (err) { toast(esc(err.message), 'danger'); }
  }
  if (f.matches('[data-act=lot-form]')) {
    const d = Object.fromEntries(new FormData(f));
    try {
      const lot = { title: d.title, description: d.description, image: d.image, category: '', startPrice: +d.startPrice, minIncrement: +d.minIncrement, durationSec: +d.durationSec, mode: d.mode };
      if (d.mode === 'antisnipe') lot.windowSec = +d.windowSec;
      const r = await api.createAuction(meId(), lot);
      toast(`Listed <b>${esc(d.title.slice(0, 30))}</b> · signed and accepted by ${esc(r.via)}`, 'good');
      $$('.drawer').forEach((x) => { x.hidden = true; });
      ui.lot = r.id; ui.pinned = true; burst();
    } catch (err) { toast(esc(String(err.message).replace(/^.*log='([^']+)'.*$/, '$1')), 'danger'); }
  }
});

// ---------- login (ADR 0010) ----------
let quickAt = 0, connectAbort = null;
const authUrl = (url) => toast(`Your signer asks you to approve: <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">open</a>`, 'info');
async function doLogin(fn) {
  const st = $('[data-slot=login-status]'); st.textContent = 'Connecting…';
  try {
    const login = await fn();
    connectAbort = null;
    adoptYou(login);
    ui.me = 'You'; save('me', ui.me);
    await refreshBal('You').catch(() => 0);
    $$('.modal').forEach((d) => { d.hidden = true; }); st.textContent = '';
    renderUsers(); renderWallet(); pollState();
    toast(`Logged in as <b>${esc(ids.You.name)}</b> · same fake sats, your own bids`, 'good');
    loadProfile(true);
  } catch (e) { st.textContent = e.message || 'Login failed'; }
}
async function loadProfile(force) {
  if (!you) return;
  if (!force && you.profile && Date.now() - (you.profile.fetched || 0) < 3600e3) return;
  try {
    const p = await fetchProfile(you.pubkey, you.relays || []);
    if (!p || !you) return;
    you.profile = { ...p, fetched: Date.now() }; save('you', you);
    if (p.name) ids.You.name = p.name;
    renderUsers(); kick();
  } catch {}
}

// swipe to bid (template interaction)
(function swipe() {
  const sw = $('[data-swipe]'); const knob = $('.swipe-knob', sw); const fill = $('.swipe-fill', sw);
  let sx = null; const max = () => sw.clientWidth - 54;
  const set = (dx) => { knob.style.transform = `translateX(${dx}px)`; fill.style.width = 48 + dx + 'px'; };
  knob.addEventListener('pointerdown', (e) => { sx = e.clientX; knob.setPointerCapture(e.pointerId); });
  knob.addEventListener('pointermove', (e) => { if (sx === null) return; set(Math.max(0, Math.min(max(), e.clientX - sx))); });
  knob.addEventListener('pointerup', (e) => {
    const dx = e.clientX - sx; sx = null;
    if (dx > max() * 0.82) { set(max()); tapBid({ steps: 0 }, sw); }
    setTimeout(() => set(0), 380);
  });
})();

// ---------- boot ----------
if (you) { adoptYou(you); loadProfile(false); } else if (ui.me === 'You') ui.me = 'Alice';
// Move any pre-Coco (v0.1) local proofs into each user's Coco wallet, then read balances.
for (const n of USERS) {
  if (W[n].proofs?.length) { try { await api.receive(ids[n], W[n].proofs); } catch (e) { console.warn('migrate', n, e.message); } }
  delete W[n].proofs;
}
saveW();
await Promise.all(people().map((n) => refreshBal(n).catch(() => 0)));
renderUsers();
['pointerdown', 'click', 'input', 'keydown'].forEach((t) => addEventListener(t, kick, { capture: true, passive: true }));
kick();
await pollNet();
await pollState();
await seedIfEmpty();
startPush();
(function fallback() { pollState(); setTimeout(fallback, push.open ? 5000 : 1000); })();
renderTimings();
setInterval(pollNet, 2000);
setInterval(pollChat, 2500);
setInterval(() => settleLoop().catch(() => {}), 1500);
setInterval(() => botLoop().catch(() => {}), 700);
setInterval(seedIfEmpty, 15000);
pollChat();
