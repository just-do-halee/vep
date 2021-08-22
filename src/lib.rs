// Licensed under either of Apache License, Version 2.0 or MIT license at your option.

//! ```ignore
//!
//! use sha2::Sha256;
//! impl vep::Digester for Sha256 {
//!     fn digest(&mut self, bytes: &[u8]) -> Vec<u8> {
//!         self.update(bytes);
//!         self.finalize_reset().to_vec()
//!     }
//! }
//!
//!
//! let src = b"hello vep!"; // <- 10 bytes
//! let expanded = Vep(Sha256::new()).expand(src); // -> 10 * 32 bytes == 320 bytes
//!
//! ```

#![deny(unsafe_code)]
#![no_std]
extern crate alloc;

#[cfg(feature = "default")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
extern crate std;

pub trait Digester {
    fn digest(&mut self, bytes: &[u8]) -> Vec<u8>;
}
pub struct Vep<D: Digester>(pub D);

impl<D: Digester> Vep<D> {
    pub fn expand<T: AsRef<[u8]>>(mut self, bytes: T) -> Vec<u8> {
        let bytes = bytes.as_ref();
        let rev_i = bytes.len() - 1;
        let mut salt;
        let mut buf = Vec::from(bytes);
        let mut final_output = Vec::new();
        for (i, &byte) in bytes.iter().enumerate() {
            salt = bytes[rev_i - i];
            for _ in 0..byte {
                buf.push(salt);
                buf = self.0.digest(buf.as_slice());
            }
            final_output.extend(buf.iter());
        }
        final_output
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::eprintln;

    use super::*;

    // ---------------  blake3  ---------------
    use blake3::Hasher;
    impl Digester for Hasher {
        fn digest(&mut self, bytes: &[u8]) -> Vec<u8> {
            self.reset();
            self.update(bytes);
            self.finalize().as_bytes().to_vec()
        }
    }
    // ---------------  sha3_512  ---------------
    use sha3::{Digest, Sha3_512};
    impl Digester for Sha3_512 {
        fn digest(&mut self, bytes: &[u8]) -> Vec<u8> {
            self.update(bytes);
            self.finalize_reset().to_vec()
        }
    }

    // ---------------  sha2_384  ---------------
    use sha2::Sha384 as Sha2_384;
    impl Digester for Sha2_384 {
        fn digest(&mut self, bytes: &[u8]) -> Vec<u8> {
            self.update(bytes);
            self.finalize_reset().to_vec()
        }
    }

    #[test]
    fn it_works() {
        let src = b"hello world!";
        let src_len = src.len(); // 12 bytes
        eprintln!("\n'hello world!' = {} ({})\n", hex::encode(src), src_len);

        let blake3_expanded = Vep(Hasher::new()).expand(src); // output = 32 bytes == 256 bits
        let b_len = blake3_expanded.len();
        assert_eq!(src_len * 32, b_len); // == 384 bytes == 3072 bits

        let sha2_expanded = Vep(Sha2_384::new()).expand(src); // output = 48 bytes == 384 bits
        let s2_len = sha2_expanded.len();
        assert_eq!(src_len * 48, s2_len); // == 576 bytes == 4608 bits

        let sha3_expanded = Vep(Sha3_512::new()).expand(src); // output = 64 bytes == 512 bits
        let s3_len = sha3_expanded.len();
        assert_eq!(src_len * 64, s3_len); // == 768 bytes == 6144 bits

        eprintln!(
            "vep(blake3_256) = {} ({})\n",
            hex::encode(blake3_expanded),
            b_len
        );
        eprintln!(
            "vep(sha2_384) = {} ({})\n",
            hex::encode(sha2_expanded),
            s2_len
        );
        eprintln!(
            "vep(sha3_512) = {} ({})\n",
            hex::encode(sha3_expanded),
            s3_len
        );
    }
}
