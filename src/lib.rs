// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

//! # **`vep`**
//!
//! Variable-length Expansion Pass function.
//! ( i.e. short password to long hashed password )<br>
//! (supported no-std)
//! <a href="https://i.ibb.co/kGnwXXf/vep.png">check algorithm</a>
//! ## How to
//! ```rust
//!
//! use vep::Vep;
//! use sha2::{Sha256, Digest}; // can be any hasher(dyn Digest from `digest` crate)
//!
//! let src = b"hello vep!"; // <- 10 bytes
//! let expanded = Vep(Sha256::new()).expand(src); // -> 10 * 32 bytes == 320 bytes
//!
//!
//! ```

#![deny(unsafe_code)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::vec::Vec;

pub mod parts {
    pub use digest::generic_array::{ArrayLength, GenericArray};
    pub use digest::Digest;
    pub use typenum as BytesSize;
}

pub trait Digester {
    type OutputSize: parts::ArrayLength<u8>;
    fn digest(&mut self, bytes: &[u8]) -> parts::GenericArray<u8, Self::OutputSize>;
}

impl<D: parts::Digest> Digester for D {
    type OutputSize = D::OutputSize;
    #[inline]
    fn digest(&mut self, bytes: &[u8]) -> parts::GenericArray<u8, Self::OutputSize> {
        self.update(bytes);
        self.finalize_reset()
    }
}

pub struct Vep<D: Digester>(pub D);

impl<D: Digester> Vep<D> {
    pub fn expand(mut self, bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let bytes = bytes.as_ref();
        let rev_i = bytes.len() - 1;
        let mut salt;
        let mut buf = Vec::from(bytes);
        let mut temp;
        let mut final_output = Vec::new();
        for (i, &byte) in bytes.iter().enumerate() {
            salt = bytes[rev_i - i];
            let times = byte;
            buf.push(salt);
            temp = self.0.digest(buf.as_slice());
            for _ in 0..times {
                temp = self.0.digest(temp.as_slice());
            }
            buf = temp.to_vec();
            final_output.extend(buf.iter());
        }
        final_output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------  blake3  ---------------
    use blake3::traits::digest::Digest;
    use blake3::Hasher;
    // ---------------  sha3_512  ---------------
    use sha3::Sha3_512;
    // ---------------  sha2_384  ---------------
    use sha2::Sha384 as Sha2_384;

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
