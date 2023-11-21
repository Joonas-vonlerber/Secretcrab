#![allow(dead_code, non_snake_case)]
#![feature(slice_as_chunks, iter_collect_into, const_result, const_option)]

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
