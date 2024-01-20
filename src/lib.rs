#![allow(
    dead_code,
    non_snake_case,
    clippy::suspicious_arithmetic_impl,
    unused_imports,
    unused_variables,
    clippy::upper_case_acronyms
)]
#![feature(array_chunks, const_option)]

pub mod Integrity {
    pub mod BLAKE;
    pub mod SHA;
    pub mod Sponge;
}

pub mod Confidentiality {
    pub mod AES;
    pub mod RSA;
    pub mod XOR;
}

pub mod Authenticity {
    pub mod Ed25519;
}

pub mod Block_cypher;
