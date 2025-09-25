#![allow(
    dead_code,
    non_snake_case,
    clippy::suspicious_arithmetic_impl,
    unused_variables,
    clippy::upper_case_acronyms
)]
use std::fmt::Debug;

pub mod Integrity {
    pub mod BLAKE;
    mod Merkle_Damgard;
    pub mod SHA;
    pub mod Sponge;
}

pub mod Confidentiality {
    pub mod AES;
    mod RSA;
    pub mod XOR;
}

pub mod Authenticity {
    use thiserror::Error;

    pub mod Ed25519;

    #[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
    pub enum AuthenticationError {
        #[error("Signature was not a valid signature")]
        BadSignature,
        #[error("Public key was not a valid Public key")]
        BadPublicKey,
        #[error("Signature did not match the given message and Public key")]
        SignatureNotMatchMessage,
    }
}

pub mod Block_Cipher;
mod Feistel_network;
mod Lattices {
    mod Lattice;
}

#[inline]
pub(crate) fn zip_with<const N: usize, T, U, V: Debug, F: Fn(T, U) -> V>(
    arr1: [T; N],
    arr2: [U; N],
    f: F,
) -> [V; N] {
    arr1.into_iter()
        .zip(arr2)
        .map(|(a, b)| f(a, b))
        .collect::<Vec<V>>()
        .try_into()
        .unwrap()
}
