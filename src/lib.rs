#![allow(dead_code, non_snake_case)]
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
