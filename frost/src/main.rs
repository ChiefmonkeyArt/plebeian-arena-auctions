//! arena-frost: one small, stateless FROST(secp256k1, Taproot) tool for the arena.
//!
//! Every command reads one JSON object on stdin and writes one JSON object on
//! stdout; secrets never go on the command line. The Go validators and gateway
//! call it. State (key shares, nonces) is kept by the caller, never here.
//!
//!   dkg1      {id, max, min}                         -> {secret, package}
//!   dkg2      {secret, round1}                       -> {secret, round2: {to: package}}
//!   dkg3      {secret, round1, round2}               -> {key_package, public_key_package, group_key}
//!   commit    {key_package}                          -> {nonces, commitments}
//!   package   {commitments: {id: c}, message}        -> {signing_package}
//!   sign      {key_package, nonces, signing_package} -> {share}
//!   aggregate {signing_package, shares, public_key_package} -> {signature, group_key}
//!
//! `message` is hex. Signatures are BIP-340 Schnorr over the message bytes, so
//! a Cashu mint verifies them like any single-key P2PK signature.

use frost_secp256k1_tr as frost;
use frost::keys::dkg;
use frost::Identifier;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};

type Res = Result<Value, String>;

fn field<T: serde::de::DeserializeOwned>(v: &Value, k: &str) -> Result<T, String> {
    serde_json::from_value(v.get(k).cloned().ok_or(format!("missing {k}"))?).map_err(|e| format!("bad {k}: {e}"))
}

fn ident(n: u16) -> Result<Identifier, String> {
    if !(1..=255).contains(&n) {
        return Err("participant id out of range".into());
    }
    Identifier::try_from(n).map_err(|e| e.to_string())
}

/// Maps keyed by participant number ("1".."4") on the wire.
fn by_id<T: serde::de::DeserializeOwned>(v: &Value, k: &str) -> Result<BTreeMap<Identifier, T>, String> {
    let m: BTreeMap<String, T> = field(v, k)?;
    m.into_iter()
        .map(|(id, t)| Ok((ident(id.parse().map_err(|_| format!("bad id {id}"))?)?, t)))
        .collect()
}

fn num_of(id: &Identifier, max: u16) -> Result<u16, String> {
    (1..=max).find(|n| Identifier::try_from(*n).ok().as_ref() == Some(id)).ok_or("unknown participant".into())
}

fn group_key(pk: &frost::keys::PublicKeyPackage) -> Result<String, String> {
    // 33-byte compressed SEC1 key; Cashu P2PK locks take this form, and BIP-340
    // verification uses its x coordinate.
    Ok(hex::encode(pk.verifying_key().serialize().map_err(|e| e.to_string())?))
}

fn run(cmd: &str, v: &Value) -> Res {
    let mut rng = rand::rngs::OsRng;
    let err = |e: frost::Error| e.to_string();
    match cmd {
        "dkg1" => {
            let id: u16 = field(v, "id")?;
            let (max, min): (u16, u16) = (field(v, "max")?, field(v, "min")?);
            if !(2..=max).contains(&min) || max > 16 {
                return Err("bad threshold".into());
            }
            let (secret, package) = dkg::part1(ident(id)?, max, min, &mut rng).map_err(err)?;
            Ok(json!({ "secret": secret, "package": package }))
        }
        "dkg2" => {
            let secret: dkg::round1::SecretPackage = field(v, "secret")?;
            let r1: BTreeMap<Identifier, dkg::round1::Package> = by_id(v, "round1")?;
            let max = r1.len() as u16 + 1;
            let (secret, out) = dkg::part2(secret, &r1).map_err(err)?;
            let mut round2 = serde_json::Map::new();
            for (id, p) in out {
                round2.insert(num_of(&id, max)?.to_string(), serde_json::to_value(p).map_err(|e| e.to_string())?);
            }
            Ok(json!({ "secret": secret, "round2": round2 }))
        }
        "dkg3" => {
            let secret: dkg::round2::SecretPackage = field(v, "secret")?;
            let r1: BTreeMap<Identifier, dkg::round1::Package> = by_id(v, "round1")?;
            let r2: BTreeMap<Identifier, dkg::round2::Package> = by_id(v, "round2")?;
            let (kp, pkp) = dkg::part3(&secret, &r1, &r2).map_err(err)?;
            Ok(json!({ "key_package": kp, "public_key_package": pkp, "group_key": group_key(&pkp)? }))
        }
        "commit" => {
            let kp: frost::keys::KeyPackage = field(v, "key_package")?;
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            Ok(json!({ "nonces": nonces, "commitments": commitments }))
        }
        "package" => {
            let c: BTreeMap<Identifier, frost::round1::SigningCommitments> = by_id(v, "commitments")?;
            let msg = hex::decode(field::<String>(v, "message")?).map_err(|_| "message must be hex")?;
            if msg.len() != 32 {
                return Err("message must be a 32-byte hash".into());
            }
            Ok(json!({ "signing_package": frost::SigningPackage::new(c, &msg) }))
        }
        "sign" => {
            let kp: frost::keys::KeyPackage = field(v, "key_package")?;
            let nonces: frost::round1::SigningNonces = field(v, "nonces")?;
            let sp: frost::SigningPackage = field(v, "signing_package")?;
            if sp.signing_commitments().len() < *kp.min_signers() as usize {
                return Err("too few signers in the package".into());
            }
            let share = frost::round2::sign(&sp, &nonces, &kp).map_err(err)?;
            Ok(json!({ "share": share }))
        }
        "aggregate" => {
            let sp: frost::SigningPackage = field(v, "signing_package")?;
            let shares: BTreeMap<Identifier, frost::round2::SignatureShare> = by_id(v, "shares")?;
            let pkp: frost::keys::PublicKeyPackage = field(v, "public_key_package")?;
            let sig = frost::aggregate(&sp, &shares, &pkp).map_err(err)?;
            pkp.verifying_key().verify(sp.message(), &sig).map_err(err)?;
            let raw = sig.serialize().map_err(err)?;
            // FROST serialises R as 33 bytes; BIP-340 wants x(R) || s (64 bytes).
            let bip340 = if raw.len() == 65 { raw[1..].to_vec() } else { raw };
            Ok(json!({ "signature": hex::encode(bip340), "group_key": group_key(&pkp)? }))
        }
        _ => Err(format!("unknown command {cmd}")),
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let mut input = String::new();
    let out = std::io::stdin()
        .take(1 << 20)
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str::<Value>(&input).map_err(|e| format!("bad json: {e}")))
        .and_then(|v| run(&cmd, &v));
    let code = match out {
        Ok(v) => {
            println!("{v}");
            0
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "arena-frost {cmd}: {e}");
            println!("{}", json!({ "error": e }));
            1
        }
    };
    std::process::exit(code);
}
