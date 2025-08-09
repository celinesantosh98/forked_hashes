// DH
#[cfg(feature = "use-curve25519")]
use curve25519_dalek::montgomery::MontgomeryPoint;

use arrayref::array_ref;
#[cfg(feature = "p256")]
use p256::{EncodedPoint, SecretKey};
#[cfg(feature = "p256")]
use p256::{elliptic_curve::sec1::ToEncodedPoint};

use crate::bindings::mwrapper::crypto::monitorkey;

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
        monitorkey::monitor_ephemeral(&self.pubkey);
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
