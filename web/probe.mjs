import { Wallet, P2PKBuilder, OutputData } from '@cashu/cashu-ts';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
const MINT='http://127.0.0.1:3338';
const w = new Wallet(MINT); await w.loadMint();
const q = await w.createMintQuoteBolt11(1000);
let st; for (let i=0;i<20;i++){ st = await w.checkMintQuoteBolt11(q.quote); if (st.state==='PAID') break; await new Promise(r=>setTimeout(r,300)); }
console.log('quote', st.state);
const proofs = await w.mintProofsBolt11(1000, q.quote);
console.log('minted', proofs.reduce((a,p)=>a+Number(p.amount),0), 'dleq?', !!proofs[0].dleq);
const vk = [1,2,3,4].map(()=>secp256k1.utils.randomSecretKey());
const vpub = vk.map(k=>'02'+bytesToHex(schnorr.getPublicKey(k)));
const bidderK = secp256k1.utils.randomSecretKey(); const bidderPub='02'+bytesToHex(schnorr.getPublicKey(bidderK));
const opts = new P2PKBuilder().addLockPubkey(vpub).requireLockSignatures(3).addRefundPubkey(bidderPub).lockUntil(Math.floor(Date.now()/1000)+3600).sigAll().toOptions();
const { keep, send } = await w.ops.send(300, proofs).asP2PK(opts).run();
console.log('locked', send.length, send[0].secret, 'dleq', JSON.stringify(send[0].dleq));
// refund: outputs to bidder, sign SIG_ALL with V1..V3
const ks = w.getKeyset();
const outs = OutputData.createRandomData(300, ks);
const msg = send.map(p=>p.secret).join('') + outs.map(o=>o.blindedMessage.B_).join('');
const h = sha256(new TextEncoder().encode(msg));
const sigs = vk.slice(0,3).map(k=>bytesToHex(schnorr.sign(h,k)));
const inputs = send.map((p,i)=>({id:p.id, amount:Number(p.amount), secret:p.secret, C:p.C, ...(i===0?{witness:JSON.stringify({signatures:sigs})}:{})}));
const outputs = outs.map(o=>({amount:Number(o.blindedMessage.amount), id:o.blindedMessage.id, B_:o.blindedMessage.B_}));
const r = await fetch(MINT+'/v1/swap',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({inputs,outputs})});
const j = await r.json(); console.log('swap', r.status, JSON.stringify(j).slice(0,200));
if (j.signatures){ const np = outs.map((o,i)=>o.toProof(j.signatures[i], ks)); console.log('refunded', np.reduce((a,p)=>a+Number(p.amount),0), 'plain secret', np[0].secret.slice(0,20)); }
