#![allow(dead_code, non_snake_case)]
#![feature(slice_as_chunks, iter_collect_into, const_result, const_option)]
#![allow(clippy::redundant_clone)]

pub mod Integrity {
    pub mod Keccak;
    pub mod SHA;
}

pub mod Confidentiality {
    pub mod AES;
    pub mod RSA;
    pub mod XOR;
}

pub mod Authenticity {
    pub mod Ed25519;
}
