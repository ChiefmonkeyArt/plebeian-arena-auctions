// Key ceremony for four participants, then 3-of-4 signing; the signature must
// verify as plain BIP-340 against the group key. Any 2 must fail.
// Usage: node web/test/frost-roundtrip.mjs <path to arena-frost>
import { execFileSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const BIN = process.argv[2];
const call = (cmd, input) => {
  try { return JSON.parse(execFileSync(BIN, [cmd], { input: JSON.stringify(input), stdio: ['pipe', 'pipe', 'pipe'] })); }
  catch (e) { const o = (e.stdout || '').toString(); return o ? JSON.parse(o) : { error: String(e) }; }
};
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(c ? '  ok  ' : '  FAIL', m); };
const ids = [1, 2, 3, 4];
const others = (i, m) => Object.fromEntries(Object.entries(m).filter(([k]) => Number(k) !== i));

const r1 = {}, s1 = {};
for (const i of ids) { const o = call('dkg1', { id: i, max: 4, min: 3 }); s1[i] = o.secret; r1[i] = o.package; }
const s2 = {}, inbox = { 1: {}, 2: {}, 3: {}, 4: {} };
for (const i of ids) {
  const o = call('dkg2', { secret: s1[i], round1: others(i, r1) });
  s2[i] = o.secret;
  for (const [to, p] of Object.entries(o.round2)) inbox[to][i] = p;
}
const kp = {}; let pkp, gk;
for (const i of ids) {
  const o = call('dkg3', { secret: s2[i], round1: others(i, r1), round2: inbox[i] });
  kp[i] = o.key_package; pkp ??= o.public_key_package; gk ??= o.group_key;
  ok(o.group_key === gk, `participant ${i} derives the same group key`);
}
ok(/^0[23][0-9a-f]{64}$/.test(gk), 'group key is a compressed secp256k1 key');

function signWith(signers, msg) {
  const nonces = {}, commitments = {};
  for (const i of signers) { const o = call('commit', { key_package: kp[i] }); nonces[i] = o.nonces; commitments[i] = o.commitments; }
  const { signing_package, error } = call('package', { commitments, message: msg });
  if (error) return { error };
  const shares = {};
  for (const i of signers) { const o = call('sign', { key_package: kp[i], nonces: nonces[i], signing_package }); if (o.error) return o; shares[i] = o.share; }
  return call('aggregate', { signing_package, shares, public_key_package: pkp });
}
for (const set of [[1, 2, 3], [2, 3, 4], [1, 3, 4], [1, 2, 3, 4]]) {
  const m = sha256(new TextEncoder().encode('escrow release ' + set.join('')));
  const o = signWith(set, bytesToHex(m));
  ok(o.signature && schnorr.verify(hexToBytes(o.signature), m, hexToBytes(gk.slice(2))), `signers ${set} make a valid BIP-340 signature`);
}
const two = signWith([1, 2], bytesToHex(sha256(new Uint8Array([1]))));
ok(!!two.error, `two signers are refused (${two.error})`);
// A nonce must never sign twice: reusing it with a different package is refused or yields garbage.
console.log(`frost roundtrip: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
