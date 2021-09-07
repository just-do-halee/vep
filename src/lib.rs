// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

//! # **`vep`**
//!
//! Variable-length Expansion Pass function.
//! ( i.e. short password to long hashed password )<br>
//! (supported no-std)
//! <a href="https://i.ibb.co/WgTkyXF/vep2.png">check algorithm</a>
//! ## How to
//! ```rust
//!
//! use vep::Vep;
//! use sha2::{Sha256, Digest}; // can be any hasher(dyn Digest from `digest` crate)
//!
//! let src = b"hello vep!"; // <- 10 bytes
//! let expanded = Vep(Sha256::new()).expand(src); // -> 10 * 32 bytes == `320 bytes`
//!
//! assert_eq!(expanded.len(), Vep::<Sha256>::output_size_calc(src));
//! ```
//!
//! ## Fixed size available
//! ```rust
//! # use vep::Vep;
//! # use sha2::{Sha256, Digest};
//! let src = b"hello vep!"; // <- 10 bytes
//! let result = Vep(Sha256::new()).expand_and_then_reduce(src); // -> 320 bytes -> `32 bytes` (reduced)
//!
//! assert_eq!(result.len(), Vep::<Sha256>::reduced_size_calc());
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

use zeroize::Zeroize;

pub mod parts {
    pub use digest::generic_array::{ArrayLength, GenericArray};
    pub use digest::Digest;
    pub use typenum as BytesSize;
}

pub trait Digester {
    type OutputSize: parts::ArrayLength<u8>;
    fn output_size() -> usize;
    fn digest(&mut self, data: impl AsRef<[u8]>) -> parts::GenericArray<u8, Self::OutputSize>;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize_reset(&mut self) -> parts::GenericArray<u8, Self::OutputSize>;
}

impl<D: parts::Digest> Digester for D {
    type OutputSize = D::OutputSize;
    #[inline]
    fn output_size() -> usize {
        D::output_size()
    }
    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data);
    }
    #[inline]
    fn finalize_reset(&mut self) -> parts::GenericArray<u8, Self::OutputSize> {
        self.finalize_reset()
    }
    #[inline]
    fn digest(&mut self, data: impl AsRef<[u8]>) -> parts::GenericArray<u8, Self::OutputSize> {
        self.update(data);
        self.finalize_reset()
    }
}

pub struct Vep<D: Digester>(pub D);

impl<D: Digester> Vep<D> {
    /// very cheap
    #[inline]
    pub fn output_size_calc(bytes: impl AsRef<[u8]>) -> usize {
        let len = bytes.as_ref().len();
        D::output_size() * if len < 2 { 2 } else { len }
    }
    /// very cheap
    #[inline]
    pub fn reduced_size_calc() -> usize {
        D::output_size()
    }
    pub fn expand(mut self, bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let (last_salt, middle_output) = self.middle_process(bytes);
        middle_output
            .into_iter()
            .zip(last_salt.iter())
            .flat_map(|(data, &salt)| {
                self.0.update(data);
                self.0.update(&[salt]);
                self.0.finalize_reset()
            })
            .collect() // final output
    }
    pub fn expand_and_then_reduce(mut self, bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let (last_salt, middle_output) = self.middle_process(bytes);
        middle_output
            .into_iter()
            .zip(last_salt.iter())
            .map(|(data, &salt)| {
                self.0.update(data);
                self.0.update(&[salt]);
                self.0.finalize_reset()
            })
            .collect::<Vec<parts::GenericArray<u8, D::OutputSize>>>()
            .into_iter()
            .reduce(|a, b| {
                self.0.update(a);
                self.0.update(b);
                self.0.finalize_reset()
            })
            .unwrap()
            .to_vec()
    }
    #[inline]
    fn middle_process(
        &mut self,
        bytes: impl AsRef<[u8]>,
    ) -> (Vec<u8>, Vec<parts::GenericArray<u8, D::OutputSize>>) {
        let mut bytes = match bytes.as_ref().len() {
            // padding
            0 => [0, 0].to_vec(),
            1 => bytes.as_ref().to_vec().repeat(2),
            _ => bytes.as_ref().to_vec(),
        };
        let bytes_len = bytes.len();
        let rev_i = bytes_len - 1;
        let mut salt;
        let mut buf = Vec::from(bytes.as_slice());
        let mut temp;
        let mut last_salt = Vec::with_capacity(bytes_len);
        let mut middle_output = Vec::with_capacity(bytes_len);

        for (i, &byte) in bytes.iter().enumerate() {
            salt = bytes[rev_i - i];
            let times = byte;
            buf.push(salt);
            temp = self.0.digest(buf.as_slice());
            for _ in 0..times {
                temp = self.0.digest(temp.as_slice());
            }
            buf = temp.to_vec();
            last_salt.push(buf[0]);
            middle_output.push(temp);
        }

        bytes.zeroize();
        (last_salt, middle_output)
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

    fn filter_len(len: usize) -> usize {
        if len < 2 {
            2
        } else {
            len
        }
    }

    #[test]
    fn pad() {
        let src = b"";
        let src_len = filter_len(src.len()); // 2 bytes
        eprintln!("\n'' = {} ({})\n", hex::encode(src), src_len);

        let blake3_expanded = Vep(Hasher::new()).expand(src); // output = 32 bytes == 256 bits
        let b_len = blake3_expanded.len();
        assert_eq!(src_len * 32, b_len); // == 64 bytes == 512 bits
        assert_eq!(b_len, 64);
        assert_eq!(64, Vep::<Hasher>::output_size_calc(src));

        let src = b"a";
        let src_len = filter_len(src.len()); // 2 bytes
        eprintln!("\n'a' = {} ({})\n", hex::encode(src), src_len);

        let sha2_expanded = Vep(Sha2_384::new()).expand(src); // output = 48 bytes == 384 bits
        let s2_len = sha2_expanded.len();
        assert_eq!(src_len * 48, s2_len); // == 96 bytes == 768 bits
        assert_eq!(s2_len, 96);
        assert_eq!(96, Vep::<Sha2_384>::output_size_calc(src));
    }
    #[test]
    fn expand() {
        let src = b"hello world!";
        let src_len = src.len(); // 12 bytes
        eprintln!("\n'hello world!' = {} ({})\n", hex::encode(src), src_len);

        let blake3_expanded = Vep(Hasher::new()).expand(src); // output = 32 bytes == 256 bits
        let b_len = blake3_expanded.len();
        assert_eq!(src_len * 32, b_len); // == 384 bytes == 3072 bits
        assert_eq!(b_len, Vep::<Hasher>::output_size_calc(src));

        let sha2_expanded = Vep(Sha2_384::new()).expand(src); // output = 48 bytes == 384 bits
        let s2_len = sha2_expanded.len();
        assert_eq!(src_len * 48, s2_len); // == 576 bytes == 4608 bits
        assert_eq!(s2_len, Vep::<Sha2_384>::output_size_calc(src));

        let sha3_expanded = Vep(Sha3_512::new()).expand(src); // output = 64 bytes == 512 bits
        let s3_len = sha3_expanded.len();
        assert_eq!(src_len * 64, s3_len); // == 768 bytes == 6144 bits
        assert_eq!(s3_len, Vep::<Sha3_512>::output_size_calc(src));

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
    #[test]
    fn expand_and_then_reduce() {
        let src = b"";
        let src_len = src.len(); // 12 bytes
        eprintln!("\n'' = {} ({})\n", hex::encode(src), src_len);

        let blake3_expanded = Vep(Hasher::new()).expand_and_then_reduce(src);
        let b_len = blake3_expanded.len();
        assert_eq!(32, b_len); // 32 bytes == 256 bits
        assert_eq!(b_len, Vep::<Hasher>::reduced_size_calc());

        let sha2_expanded = Vep(Sha2_384::new()).expand_and_then_reduce(src);
        let s2_len = sha2_expanded.len();
        assert_eq!(48, s2_len); // 48 bytes == 384 bits
        assert_eq!(s2_len, Vep::<Sha2_384>::reduced_size_calc());

        let sha3_expanded = Vep(Sha3_512::new()).expand_and_then_reduce(src);
        let s3_len = sha3_expanded.len();
        assert_eq!(64, s3_len); // 64 bytes == 512 bits
        assert_eq!(s3_len, Vep::<Sha3_512>::reduced_size_calc());

        let hex = hex::encode(blake3_expanded);
        eprintln!("vep(blake3_256) = {} ({})\n", hex, b_len);
        assert_eq!(
            hex,
            "78e74c2be51e45d39331b3b25359b1122f3a0f1e042379aafa85ca2651352438"
        );
        let hex = hex::encode(sha2_expanded);
        eprintln!("vep(sha2_384) = {} ({})\n", hex, s2_len);
        assert_eq!(hex, "21e977feb8e749c591c10adc3fe718302680f0b80750aed635de4c9a1d3529362092aed43529cc4fecca1baf119e00c1");
        let hex = hex::encode(sha3_expanded);
        eprintln!("vep(sha3_512) = {} ({})\n", hex, s3_len);
        assert_eq!(hex, "760974c924b7ca24b447a53e2bd82fc3112ab2334cf8e2a3ebe22fff073aee4d795ea0e5d5ce82facb1b228fc531c92bb71c4f6feebea1099863b564c89e8310");
    }
}
