use crate::Integrity::Sponge::Keccak::keccak;

pub fn sha_3_244(input: &[u8]) -> [u8; 28] {
    keccak::<28>(input, 144, 0x06)
}

pub fn sha_3_256(input: &[u8]) -> [u8; 32] {
    keccak::<32>(input, 136, 0x06)
}

pub fn sha_3_384(input: &[u8]) -> [u8; 48] {
    keccak::<48>(input, 104, 0x06)
}

pub fn sha_3_512(input: &[u8]) -> [u8; 64] {
    keccak::<64>(input, 72, 0x06)
}

pub fn shake_128<const OUTPUT_LEN: usize>(input: &[u8]) -> [u8; OUTPUT_LEN] {
    keccak::<OUTPUT_LEN>(input, 168, 0x1F)
}

pub fn shake_256<const OUTPUT_LEN: usize>(input: &[u8]) -> [u8; OUTPUT_LEN] {
    keccak::<OUTPUT_LEN>(input, 136, 0x1F)
}
