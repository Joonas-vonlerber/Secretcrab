#![allow(
    dead_code,
    non_snake_case,
    clippy::suspicious_arithmetic_impl,
    unused_imports,
    unused_variables,
    clippy::upper_case_acronyms
)]
#![feature(array_chunks, iter_map_windows)]

pub mod Integrity {
    pub mod BLAKE;
    pub mod SHA;
    pub mod Sponge;
    mod Merkle_Damgard;
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

pub mod Block_cypher;
mod Feistel_network;