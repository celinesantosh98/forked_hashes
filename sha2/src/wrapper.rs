use digest::{Update, OutputSizeUser, FixedOutput, Output};
use generic_array::{GenericArray, typenum::U32};
use digest::{Reset, FixedOutputReset, Digest, HashMarker,};

wit_bindgen::generate!({
    world: "noise-demo",
    generate_all
 });

pub struct Sha256Impl {
    inner: mwrapper::crypto::crypto::Buffer,
}

impl Sha256Impl {
    pub fn new() -> Self {
        Self {
            inner: mwrapper::crypto::crypto::Buffer::new(),
        }
    }
}

impl Default for Sha256Impl {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha256Impl {
    fn update(&mut self, input: &[u8]) {        
        self.inner.update(input); 
    }
}

impl OutputSizeUser for Sha256Impl {
    type OutputSize = U32;
}


impl FixedOutput for Sha256Impl {
    fn finalize_into(self, out: &mut Output<Self>) {
        let hash = self.inner.finalize(); // calls wasm buffer.finalize()
        out.copy_from_slice(&hash);
    }
}


impl Reset for Sha256Impl {
    fn reset(&mut self) {
        self.inner.reset(); 
    }
}


impl FixedOutputReset for Sha256Impl {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let hash = self.inner.finalize_reset(); 
        out.copy_from_slice(&hash);
    }
}

impl HashMarker for Sha256Impl {}
