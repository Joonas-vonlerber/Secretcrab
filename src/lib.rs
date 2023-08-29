#![allow(dead_code, non_snake_case)]
#![feature(slice_as_chunks, iter_collect_into)]
#![allow(unused_imports)]

pub mod Integrity {
    pub mod Keccak;
    pub mod SHA;
}

pub mod Confidentiality {
    pub mod AES;
    pub mod RSA;
}
