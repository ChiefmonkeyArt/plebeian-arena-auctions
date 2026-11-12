// Nostr login (ADR 0010): NIP-07 browser extensions and NIP-46 remote
// signers (bunker:// or nostrconnect://). Only Nostr events are signed with
// the login key; the fake-sats wallet key stays in this browser.
// Profiles: the logged-in user's own relay list (kind 10002), then their
// kind 0, read with a small WebSocket client: at most 6 relays, 4 s each.
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { getPublicKey, verifyEvent } from 'nostr-tools/pure';

export const PROFILE_RELAYS = ['wss://relay.chiefmonkey.art', 'wss://nos.lol', 'wss://purplepag.es'];
export const CONNECT_RELAYS = ['wss://relay.chiefmonkey.art', 'wss://nos.lol'];
const HEX64 = /^[0-9a-f]{64}$/;
const wssOnly = (u) => { try { const x = new URL(u); return x.protocol === 'wss:' && !x.username && !x.password ? x.href.replace(/\/$/, '') : null; } catch { return null; } };

// ---------- signers ----------
const bunkers = new Map(); // pubkey -> BunkerSigner (this page session)

export async function loginExtension() {
  if (!globalThis.nostr?.getPublicKey) throw new Error('No Nostr extension found (NIP-07). Try a signer app instead.');
  const pubkey = await globalThis.nostr.getPublicKey();
  if (!HEX64.test(pubkey || '')) throw new Error('the extension returned no public key');
  let relays = [];
  try { relays = Object.keys((await globalThis.nostr.getRelays?.()) || {}); } catch {}
  return { signer: 'nip07', pubkey, relays: relays.map(wssOnly).filter(Boolean) };
}

// bunker://<remote-pubkey>?relay=wss://...&secret=...
export async function loginBunker(uri, onauth) {
  if (!/^bunker:\/\//.test(uri.trim())) throw new Error('paste a bunker:// link from your signer');
  const { parseBunkerInput, BunkerSigner } = await import('nostr-tools/nip46');
  const bp = await parseBunkerInput(uri.trim());
  if (!bp || !bp.relays.length) throw new Error('that bunker link has no relay');
  bp.relays = bp.relays.map(wssOnly).filter(Boolean);
  const sk = randomBytes(32);
  const signer = BunkerSigner.fromBunker(sk, bp, { onauth });
  await signer.connect();
  const pubkey = await signer.getPublicKey();
  bunkers.set(pubkey, signer);
  return { signer: 'nip46', pubkey, clientSk: bytesToHex(sk), bunker: bp, relays: bp.relays };
}

// nostrconnect://: the page shows a link / QR text, the signer app connects.
export async function loginNostrConnect(onUri, signal) {
  const { createNostrConnectURI, BunkerSigner } = await import('nostr-tools/nip46');
  const sk = randomBytes(32);
  const uri = createNostrConnectURI({ clientPubkey: getPublicKey(sk), relays: CONNECT_RELAYS, secret: bytesToHex(randomBytes(8)), name: 'Plebeian Auctions Arena', perms: ['sign_event:1440', 'sign_event:1441', 'sign_event:1442'] });
  onUri(uri);
  const signer = await BunkerSigner.fromURI(sk, uri, {}, signal);
  const pubkey = await signer.getPublicKey();
  bunkers.set(pubkey, signer);
  return { signer: 'nip46', pubkey, clientSk: bytesToHex(sk), bunker: signer.bp, relays: signer.bp.relays };
}

// A signing function for a saved login: extension now, or the bunker session
// (re-opened after a reload from the saved client key).
export function signerFor(you, onauth) {
  if (you.signer === 'nip07') return async (tmpl) => {
    if (!globalThis.nostr?.signEvent) throw new Error('your Nostr extension is not available');
    return globalThis.nostr.signEvent(tmpl);
  };
  return async (tmpl) => {
    let s = bunkers.get(you.pubkey);
    if (!s) {
      const { BunkerSigner } = await import('nostr-tools/nip46');
      s = BunkerSigner.fromBunker(hexToBytes(you.clientSk), you.bunker, { onauth });
      bunkers.set(you.pubkey, s);
    }
    return s.signEvent(tmpl);
  };
}

export async function logoutSigner(you) {
  const s = bunkers.get(you?.pubkey);
  bunkers.delete(you?.pubkey);
  try { await s?.close(); } catch {}
}

// ---------- profile ----------
// The newest event matching filter from one relay, or null after ms.
function query(url, filter, ms = 4000) {
  return new Promise((resolve) => {
    let ws, best = null, done = false;
    const finish = () => { if (done) return; done = true; clearTimeout(t); try { ws?.close(); } catch {} resolve(best); };
    const t = setTimeout(finish, ms);
    try { ws = new WebSocket(url); } catch { return finish(); }
    const sub = 'p' + bytesToHex(randomBytes(4));
    ws.onopen = () => ws.send(JSON.stringify(['REQ', sub, filter]));
    ws.onerror = finish;
    ws.onclose = finish;
    ws.onmessage = (m) => {
      let d; try { d = JSON.parse(m.data); } catch { return; }
      if (d[0] === 'EVENT' && d[1] === sub && d[2]) {
        const ev = d[2];
        if (filter.authors.includes(ev.pubkey) && filter.kinds.includes(ev.kind) && verifyEvent(ev) && (!best || ev.created_at > best.created_at)) best = ev;
      } else if ((d[0] === 'EOSE' || d[0] === 'CLOSED') && d[1] === sub) finish();
    };
  });
}
const newest = (evs) => evs.filter(Boolean).sort((a, b) => b.created_at - a.created_at)[0] || null;
const clean = (s, n) => String(s || '').replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e]/g, '').trim().slice(0, n);

export async function fetchProfile(pubkey, signerRelays = [], base = PROFILE_RELAYS) {
  const first = [...new Set([base[0], ...signerRelays, ...base.slice(1)].map(wssOnly).filter(Boolean))].slice(0, 6);
  const rl = newest(await Promise.all(first.map((u) => query(u, { kinds: [10002], authors: [pubkey], limit: 1 }))));
  const write = rl ? rl.tags.filter((t) => t[0] === 'r' && t[2] !== 'read').map((t) => wssOnly(t[1])).filter(Boolean) : [];
  const second = [...new Set([...write, ...first])].slice(0, 6);
  const k0 = newest(await Promise.all(second.map((u) => query(u, { kinds: [0], authors: [pubkey], limit: 1 }))));
  if (!k0) return null;
  let c; try { c = JSON.parse(k0.content); } catch { return null; }
  const pic = clean(c.picture, 500);
  return {
    name: clean(c.display_name || c.displayName || c.name, 40),
    picture: /^https:\/\/[^\s"'<>]+$/.test(pic) ? pic : '',
    at: k0.created_at,
  };
}
