use core::fmt::Debug;
use digest::{CustomizedInit, ExtendableOutputReset};

pub(crate) fn cshake_reset_test<D, F>(input: &[u8], output: &[u8], new: F) -> Option<&'static str>
where
    D: ExtendableOutputReset + Debug + Clone,
    F: Fn() -> D,
{
    let mut hasher = new();
    let mut buf = [0u8; 1024];
    let buf = &mut buf[..output.len()];
    // Test that it works when accepting the message all at once
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if buf != output {
        return Some("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test if reset works correctly
    hasher2.reset();
    hasher2.update(input);
    hasher2.finalize_xof_reset_into(buf);
    if buf != output {
        return Some("whole message after reset");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test that it works when accepting the message in chunks
    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = new();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
            hasher2.update(chunk);
        }
        hasher.finalize_xof_into(buf);
        if buf != output {
            return Some("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);

        hasher2.finalize_xof_reset_into(buf);
        if buf != output {
            return Some("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    None
}

macro_rules! new_cshake_test {
    ($name:ident, $test_name:expr, $hasher:ty, $test_func:ident $(,)?) => {
        #[test]
        fn $name() {
            use digest::dev::blobby::Blob3Iterator;
            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [customization, input, output] = row.unwrap();
                if let Some(desc) =
                    $test_func(input, output, || <$hasher>::new_customized(customization))
                {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         input:\t{:?}\n\
                         output:\t{:?}\n",
                        i, desc, input, output,
                    );
                }
            }
        }
    };
}

new_cshake_test!(
    cshake128_reset,
    "cshake128",
    sha3::CShake128,
    cshake_reset_test
);
new_cshake_test!(
    cshake256_reset,
    "cshake256",
    sha3::CShake256,
    cshake_reset_test
);
