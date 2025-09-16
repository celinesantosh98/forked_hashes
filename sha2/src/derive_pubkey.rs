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
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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

// Emit after RNG-based key generation (rand + exp(g,ltk))
// pub fn emit_after_generate(privkey: &[u8]) {
//    // monitorkey::mon_rand();
//     monitorkey::mon_exp_g_from_priv(privkey);
// }
pub fn emit_after_generate(privkey: &[u8]) {
    // DO NOT: monitorkey::mon_rand();

    // compute public = exp(g,priv) the same way Snow does:
    let pubkey = MontgomeryPoint::mul_base_clamped(*arrayref::array_ref![privkey, 0, 32]).to_bytes();

    // pair(exp('g', ltkI), expgltkI)
    monitorkey::mon_exp_g_pair(privkey, &pubkey);
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

// pub fn emit_receive(channel: &str, msg: &[u8]) {
//     monitorkey::mon_receive(channel, msg);
// }

// pub fn emit_send(channel: &str, msg: &[u8]) {
//     monitorkey::mon_send(channel, msg);
// }

// pub fn emit_hash(proto: &str) {
//     monitorkey::mon_hash(proto);
// }
// pub fn emit_hash_pair(proto: &str, digest32: &[u8]) {
//     monitorkey::mon_hash_pair(proto, digest32);
// }
pub fn emit_hash_pair(proto: &str, _digest32: &[u8]) {
    // The monitor rules use a symbolic atom like: hNoise_<proto>
    let mut tag: Vec<u8> = Vec::with_capacity(1 + proto.len());
    tag.push(b'h');
    tag.extend_from_slice(proto.as_bytes());

    // Pass a byte slice (Vec<u8> -> &[u8])
    monitorkey::mon_hash_pair(proto, &tag);
}

pub fn emit_precompute(ltk: &[u8]) {
    monitorkey::mon_precompute(ltk);
}
pub fn emit_ephemeral_rand(ephemeral_priv: &[u8]) {
   monitorkey::mon_rand(ephemeral_priv);
}
// pub fn emit_ephemeral_rand(ephemeral_priv: &[u8]) {
//     // Send ⟨rand(), n⟩ with n = ephemeral_priv (raw bytes).
//     // Do NOT base64 here; the return must be a ground byte-string.
//     monitorkey::mon_rand(ephemeral_priv);
// }