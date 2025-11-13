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
use sha2::{Digest, Sha256};
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

        monitorkey::mon_exp_g_pair(&self.privkey, &self.pubkey);

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

// const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";  //TODO

// pub fn emit_proto_hash() {
//     // suite string must match the ruleset exactly:
//     let proto = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
//     let mut h = Blake2s256::new();
//     h.update(proto.as_bytes());
//     let digest32 = h.finalize(); // 32 bytes
//     monitorkey::mon_hash_pair(proto, &digest32);
//     // 2) h(< h(proto), IDENTIFIER >)
//     monitorkey::mon_hpair_proto_identifier(&digest32, IDENTIFIER);
// }

// pub fn emit_mac1_pair(pk_r: &[u8]) {
//     // label is raw bytes; rhs is raw pk_r bytes
//     monitorkey::mon_hpair_pk_r(b"mac1----", pk_r);
// }

// pub fn emit_cookie_pair(pk_r: &[u8]) {
//     monitorkey::mon_hpair_pk_r(b"cookie--", pk_r);
// }

// pub fn emit_mac1_expgltk_i(expgltk_i: &[u8]) {
//     monitorkey::mon_hpair_expgltk_i(b"mac1----", expgltk_i);
// }
// pub fn emit_cookie_expgltk_i(expgltk_i: &[u8]) {
//     monitorkey::mon_hpair_expgltk_i(b"cookie--", expgltk_i);
// }

// #[cfg(feature = "use-curve25519")]
// pub fn emit_after_generate(privkey: &[u8]) {
//     emit_proto_hash();
//     let pubkey = MontgomeryPoint::mul_base_clamped(*arrayref::array_ref![privkey, 0, 32]).to_bytes();
//     monitorkey::mon_exp_g_pair(privkey, &pubkey);    // binds expgltkI
//     emit_mac1_expgltk_i(&pubkey);                    // these now forward the real bytes
//     emit_cookie_expgltk_i(&pubkey);
// }

// // Emit after DH (exp(peer_pk, my_priv))
// pub fn emit_after_dh(peer_pk: &[u8], my_priv: &[u8]) {
//     monitorkey::mon_dh_shared(peer_pk, my_priv);
// }

pub fn emit_setup_static(ltk: &[u8]) {
    monitorkey::mon_setup_static(ltk);
}

pub fn emit_init_peer(ltk_i: &[u8], pk_r: &[u8]) {
    monitorkey::mon_init_peer(ltk_i, pk_r);
}

// pub fn emit_hash_pair(proto: &str, digest32: &[u8]) {
//     // Forward the real 32-byte digest as a slice; no allocation.
//     monitorkey::mon_hash_pair(proto, digest32);
// }

// pub fn emit_precompute(ltk: &[u8]) {
//     monitorkey::mon_precompute(ltk);
// }
// pub fn emit_ephemeral_rand(ephemeral_priv: &[u8]) {
//    monitorkey::mon_rand(ephemeral_priv);
// }

// pub fn emit_ephemeral_exp_from_rand(ephemeral_priv: &[u8], _ephemeral_pub: &[u8]) {
//     monitorkey::mon_ephemeral_exp_from_rand_tag(ephemeral_priv);
// }

// pub fn emit_exppkRr(pk_r: &[u8], r: &[u8]) {
//     // Must be the same `r` you passed to emit_ephemeral_rand/emit_ephemeral_exp_from_rand
//     monitorkey::mon_exppk_r(pk_r, r);
// }

// pub fn emit_hmac_cii_expgr() {
//     use blake2::{Blake2s256, Digest as _};
//     const PROTO: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

//     let mut h = Blake2s256::new();
//     h.update(PROTO.as_bytes());
//     let hproto = h.finalize(); // 32 bytes
//     monitorkey::mon_hmac_cii_expgr(&hproto);
// }

// pub fn emit_hmac_ciiexpgr_type1() {
//     monitorkey::mon_hmac_ciiexpgr_type1();
// }

// pub fn emit_hmac_hmachmacciiexpgr0x01_exppkRr() {
//     // hmac('hmachmacciiexpgr0x01','exppkRr') -> 'hmachmachmacciiexpgr0x01exppkRr'
//     monitorkey::mon_hmac_hmachmacciiexpgr0x01_exppkrr();
// }

// /// h(⟨ 'hpairh{proto}{IDENTIFIER}', pkR ⟩) -> 'hpairhipkR'
// pub fn emit_hpairhipk_r(pk_r: &[u8]) {
//     monitorkey::mon_hpairhipk_r(pk_r);
// }

// pub fn emit_hmac_hmachmachmacciiexpgr0x01_exppkRr_0x01() {
//     monitorkey::mon_hmac_hmachmachmacciiexpgr0x01_exppkrr0x01();
// }

// pub fn emit_hmac_hmachmachmachmacciiexpgr0x01_exppkRr0x01_with_sisr(sisr: &[u8]) {
//     monitorkey::mon_hmac_hmachmachmachmacciiexpgr0x01_exppkrr0x01_bytes(sisr); 
// }

// // NOTE the extra underscore before `_0x02`
// pub fn emit_hmac_hmachmachmachmacciiexpgr0x01_exppkRr_pair_0x02() {
//     monitorkey::mon_hmac_hmachmachmachmacciiexpgr0x01_exppkrr_pair0x02();
// }

// pub fn emit_h_of_pair_hpairhipkR_and_expgr() {
//     monitorkey::mon_h_of_pair_hpairhipk_r_and_expgr();
// }

// /// hmac('...0x01exppkRr0x01sisr', 0x01) -> '...0x01sisr0x01'
// pub fn emit_hmac_hmachmachmachmacciiexpgr0x01_exppkRr0x01sisr_with_0x01() {
//     monitorkey::mon_hmac_hmachmachmachmacciiexpgr0x01_exppkrr0x01sisr0x01();
// }

// // NEW: hmac('...0x01sisr', <'...0x01sisr0x01', 0x02>)
// pub fn emit_hmac_hmachmachmachmacciiexpgr0x01_exppkRr0x01sisr_pair_0x02() {
//     monitorkey::mon_hmac_hmachmachmachmacciiexpgr0x01_exppkrr0x01sisr_pair0x02();
// }

// // NEW: aead('..._pair0x02', 0^96, <expgltkI>)
// pub fn emit_aead_hmachmachmachmacciiexpgr0x01_exppkRr_pair0x02_zero_nonce_expgltk_i(
//     expgltk_i: &[u8]
// ) {
//     monitorkey::mon_aead_pair0x02_zero_nonce_expgltk_i(expgltk_i);
// }

// pub fn emit_h_of_pair_hpairhpairhipkRexpgr_and_prev_aead() {
//     monitorkey::mon_h_of_pair_hpairhpairhipk_rexpgr_and_prev_aead();
// }

// pub fn emit_aead_sisr_pair0x02_zero_nonce_ts_ad_h3(ts: &[u8]) {
//     monitorkey::mon_aead_sisr_pair0x02_zero_nonce_ts_with_h3_ad(ts);
// }

// pub fn emit_hpair_hi0_ats(ts: &[u8]) {
//     monitorkey::mon_hpair_hi0_ats(ts);
// }

// // h(⟨⟨sidI,pekI⟩,⟨astat,ats⟩⟩) -> "hpairsidIpekIastatats"
// pub fn emit_hpair_sidI_pekI_astat_ats(
//     sid_i: &[u8],   // 4
//     pek_i: &[u8],   // 32 (ephemeral pub)
//     astat: &[u8],   // 48 (encrypted static + tag)
//     ts: &[u8],      // the same ts you used when building ats elsewhere
// ) {
//     monitorkey::mon_hpair_sidi_peki_astat_ats(
//         sid_i,
//         pek_i,
//         astat,
//         ts,
//     );
// }