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
pub fn emit_after_generate(privkey: &[u8]) {
    monitorkey::mon_rand();
    monitorkey::mon_exp_g_from_priv(privkey);
}

// Emit after DH (exp(peer_pk, my_priv))
pub fn emit_after_dh(peer_pk: &[u8], my_priv: &[u8]) {
    monitorkey::mon_dh_shared(peer_pk, my_priv);
}

pub fn emit_setup_static(ltk: &[u8]) {
    monitorkey::mon_setup_static(ltk);
}

// pub fn emit_init_peer(ltk_i: [u8;32], pk_r: [u8;32]) {
//     let args = base64::engine::general_purpose::STANDARD.encode(ltk_i) + "," +
//            &base64::engine::general_purpose::STANDARD.encode(pk_r);
//     // let args = format!("{},{}",
//     //     base64::engine::general_purpose::STANDARD.encode(ltk_i),
//     //     base64::engine::general_purpose::STANDARD.encode(pk_r));
//          monitorkey::mon_init_peer(&ltk_i[..], &pk_r[..]);
//     //eprintln!("[mon] init({},...) -> {}", args, ok);
// }

// pub fn emit_init_peer(ltk: &[u8], pk_r: &[u8]) {
//     monitorkey::mon_init_peer(ltk, pk_r);
// }

//  if ok != 1 { eprintln!("monitor rejected init"); }
//}

// pub fn emit_init_peer(ltk_i: &[u8; 32], pk_r: &[u8]) {
//     // pass raw bytes; the wrapper will serialize/base64 + add comma
//     monitorkey::mon_init_peer(&ltk_i[..], pk_r);
// }

pub fn emit_init_peer(ltk_i: &[u8], pk_r: &[u8]) {
    // pass raw bytes; wrapper does the base64 + formatting
    monitorkey::mon_init_peer(ltk_i, pk_r);
}