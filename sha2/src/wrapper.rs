

//use crate::bindings::mwrapper::crypto::crypto::Buffer;

use digest::{Update, OutputSizeUser, FixedOutput, Output};
use generic_array::{GenericArray, typenum::U32};
use digest::{Reset, FixedOutputReset};

pub struct Sha256Impl {
    inner: Buffer,
}

impl Sha256Impl {
    pub fn new() -> Self {
        Self {
            inner: Buffer::new(),
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

// --- WIT Guest Resource Exports ---

// impl GuestHasher for Sha256Impl {
//     fn new() -> Self {
//         Sha256Impl::new()
//     }

//     fn update(&self, input: Vec<u8>) {
//         self.inner.update(&input);
//     }

//     fn finalize(&self) -> Vec<u8> {
//         self.inner.finalize().into()
//     }

//     fn reset(&self) {
//         self.inner.reset();
//     }

//     fn finalize_reset(&self) -> Vec<u8> {
//         self.inner.finalize_reset().into()
//     }
// }

// pub struct Host;

// impl Guest for Host {
//     type Hasher = Sha256Impl;
//     fn hash_hello() {
//         let mut buffer = Buffer::new();
//         buffer.update(b"trigger");
//     }
// }

// bindings::export!(Host with_types_in bindings);




// use digest::core_api::{ CtVariableCoreWrapper};
// use digest::{
//     core_api::{BlockSizeUser, OutputSizeUser},
//     HashMarker, Update, FixedOutput, Reset, Output, FixedOutputReset
// };
// use digest::core_api::BufferKindUser;
// use digest::generic_array::typenum::{Unsigned, U128, U32, U64};
// use crate::core_api::Sha256VarCore;
// use core::fmt;
// use digest::block_buffer::BlockBuffer;

// pub struct CoreMWrapperSha256 {
//     core: CtVariableCoreWrapper<Sha256VarCore, U32>,
//     buffer: BlockBuffer<
//     <CtVariableCoreWrapper<Sha256VarCore, U32> as BlockSizeUser>::BlockSize,
//     <CtVariableCoreWrapper<Sha256VarCore, U32> as BufferKindUser>::BufferKind
// >
// }
// use digest::core_api::{UpdateCore, FixedOutputCore};
// impl Default for CoreMWrapperSha256 {
//     fn default() -> Self {
//         Self {
//             core: Default::default(),
//             buffer: Default::default(),
//         }
//     }
// }

// impl HashMarker for CoreMWrapperSha256 {}

// impl BlockSizeUser for CoreMWrapperSha256 {
//     type BlockSize = <CtVariableCoreWrapper<Sha256VarCore, U32> as BlockSizeUser>::BlockSize;
// }

// impl OutputSizeUser for CoreMWrapperSha256 {
//     type OutputSize = <CtVariableCoreWrapper<Sha256VarCore, U32> as OutputSizeUser>::OutputSize;
// }

// impl Update for CoreMWrapperSha256 {
//     fn update(&mut self, input: &[u8]) {
//         println!("Crypto intercepted");
        
//         let Self { core, buffer } = self;
//         buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
//     }
// }

// impl FixedOutput for CoreMWrapperSha256 {
//     fn finalize_into(mut self, out: &mut Output<Self>) {
       
//         let Self { core, buffer } = &mut self;
//         core.finalize_fixed_core(buffer, out);
       
//     }
// }

// impl Reset for CoreMWrapperSha256 {
//     fn reset(&mut self) {
//         self.core.reset();
//         self.buffer.reset();
//     }
// }

// impl fmt::Debug for CoreMWrapperSha256 {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "CoreMWrapperSha256 {{ ... }}")
//     }
// }

// impl FixedOutputReset for CoreMWrapperSha256 {
//     fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
//         // self.core.finalize_fixed_core(&mut self.buffer, out);
//         // self.core.reset();
//         // self.buffer.reset();
//         let Self { core, buffer } = self;
//         core.finalize_fixed_core(buffer, out);
//         core.reset();
//         buffer.reset();
//     }
// }