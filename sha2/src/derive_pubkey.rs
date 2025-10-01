// DH
#[cfg(feature = "use-curve25519")]
use curve25519_dalek::montgomery::MontgomeryPoint;

use arrayref::array_ref;
#[cfg(feature = "p256")]
use p256::{EncodedPoint, SecretKey};
#[cfg(feature = "p256")]
use p256::{elliptic_curve::sec1::ToEncodedPoint};

use crate::bindings::mwrapper::crypto::monitorkey;
use base64::{engine::general_purpose, Engine as _};
use core::cmp::min;
use core::str;
use crate::{Digest, Sha256};
use blake2::{Blake2s256, Digest as _}; 


#[cfg(feature = "use-curve25519")]
pub struct Monitored_Dh25519 {
    pub privkey: [u8; 32],
    pub pubkey: [u8; 32],
}

#[cfg(feature = "p256")]
pub struct Monitored_P256 {
    pub privkey: [u8; 32],
    pub pubkey: EncodedPoint,
}

impl Default for Monitored_Dh25519 {
    fn default() -> Self {
        Self {
            privkey: [0u8; 32],
            pubkey: [0u8; 32],
        }
    }
}

#[cfg(feature = "use-curve25519")]
impl Monitored_Dh25519 {
    /// Derives the public key from the private key using Curve25519 base point multiplication
    pub fn derive_pubkey(&mut self) {
        let point = MontgomeryPoint::mul_base_clamped(self.privkey);
        self.pubkey = point.to_bytes();

         // Call monitor
        //monitorkey::mon_exp_g_from_priv(&self.privkey);
    }
}

#[cfg(feature = "p256")]
impl Monitored_P256 {
    /// Derives the public key from the private key using P256
    pub fn derive_pubkey(&mut self) {
        let secret_key = SecretKey::from_bytes(&self.privkey.into()).unwrap();
        let public_key = secret_key.public_key();
        let encoded_pub = public_key.to_encoded_point(false);
        self.pubkey = encoded_pub;
    }
}

const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";

pub fn emit_proto_hash() {
    // suite string must match the ruleset exactly:
    let proto = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    let mut h = Blake2s256::new();
    h.update(proto.as_bytes());
    let digest32 = h.finalize(); // 32 bytes
    monitorkey::mon_hash_pair(proto, &digest32);
    // 2) h(< h(proto), IDENTIFIER >)
    monitorkey::mon_hpair_proto_identifier(&digest32, IDENTIFIER);
}

pub fn emit_mac1_pair(pk_r: &[u8]) {
    // label is raw bytes; rhs is raw pk_r bytes
    monitorkey::mon_hpair_pk_r(b"mac1----", pk_r);
}

pub fn emit_cookie_pair(pk_r: &[u8]) {
    monitorkey::mon_hpair_pk_r(b"cookie--", pk_r);
}

pub fn emit_mac1_expgltk_i(expgltk_i: &[u8]) {
    monitorkey::mon_hpair_expgltk_i(b"mac1----", expgltk_i);
}
pub fn emit_cookie_expgltk_i(expgltk_i: &[u8]) {
    monitorkey::mon_hpair_expgltk_i(b"cookie--", expgltk_i);
}

pub fn emit_after_generate(privkey: &[u8]) {
    // DO NOT: monitorkey::mon_rand();

    // // compute public = exp(g,priv) the same way Snow does:
    // let pubkey = MontgomeryPoint::mul_base_clamped(*arrayref::array_ref![privkey, 0, 32]).to_bytes();

    // // pair(exp('g', ltkI), expgltkI)
    // monitorkey::mon_exp_g_pair(privkey, &pubkey);

    // emit_mac1_expgltk_i(&pubkey);
    // emit_cookie_expgltk_i(&pubkey);
    emit_proto_hash();
    let pubkey = MontgomeryPoint::mul_base_clamped(*arrayref::array_ref![privkey, 0, 32]).to_bytes();
    monitorkey::mon_exp_g_pair(privkey, &pubkey);    // binds expgltkI
    emit_mac1_expgltk_i(&pubkey);                    // these now forward the real bytes
    emit_cookie_expgltk_i(&pubkey);
}

// Emit after DH (exp(peer_pk, my_priv))
pub fn emit_after_dh(peer_pk: &[u8], my_priv: &[u8]) {
    monitorkey::mon_dh_shared(peer_pk, my_priv);
}

pub fn emit_setup_static(ltk: &[u8]) {
    monitorkey::mon_setup_static(ltk);
}

pub fn emit_init_peer(ltk_i: &[u8], pk_r: &[u8]) {
    monitorkey::mon_init_peer(ltk_i, pk_r);
}

pub fn emit_hash_pair(proto: &str, digest32: &[u8]) {
    // Forward the real 32-byte digest as a slice; no allocation.
    monitorkey::mon_hash_pair(proto, digest32);
}

pub fn emit_precompute(ltk: &[u8]) {
    monitorkey::mon_precompute(ltk);
}
pub fn emit_ephemeral_rand(ephemeral_priv: &[u8]) {
   monitorkey::mon_rand(ephemeral_priv);
}

pub fn emit_ephemeral_exp_from_rand(ephemeral_priv: &[u8], _ephemeral_pub: &[u8]) {
    // Do NOT use mon_exp_g_pair here (it sends bytes as ret and will be rejected)
    monitorkey::mon_ephemeral_exp_from_rand_tag(ephemeral_priv);
}
