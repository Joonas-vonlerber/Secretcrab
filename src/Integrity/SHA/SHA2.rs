use crate::Integrity::Merkle_Damgard::merkle_damgard;
use super::*;


fn sha256_comp_fun(state: &mut [u32; 8], chunk: [u8; 64]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h]: [u32; 8] = *state;

    let mut words: [u32; 64] = [0; 64];
    chunk.chunks(4).enumerate().for_each(|(i, x)| {
        words[i] = u32::from_be_bytes(x.try_into().unwrap());
    });
    for i in 16usize..64 {
        let w15 = words[i - 15];
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let w2 = words[i - 2];
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        words[i] = (words[i - 16])
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }

    for (i, w) in words.into_iter().enumerate() {
        let S1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g); //(e and f) xor ((not e) and g)
        let temp1 = h
            .wrapping_add(S1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(words[i]);
        let S0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c); //(a and b) xor (a and c) xor (b and c)
        let temp2 = S0.wrapping_add(maj);

        (a, b, c, d, e, f, g, h) = (
            temp1.wrapping_add(temp2),
            a,
            b,
            c,
            d.wrapping_add(temp1),
            e,
            f,
            g,
        );
    }
    for (s,x) in state.iter_mut().zip([a,b,c,d,e,f,g,h]) {
        *s = s.wrapping_add(x);
    }
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let IV = [
        0x6a09e667u32,
        0xbb67ae85u32,
        0x3c6ef372u32,
        0xa54ff53au32,
        0x510e527fu32,
        0x9b05688cu32,
        0x1f83d9abu32,
        0x5be0cd19u32,
    ];
    merkle_damgard::<[u32; 8], _, _, _, 32, 64>(
        sha_padding::<64>,
        sha256_comp_fun,
        sha_finalize_32::<8, 32>,
        IV,
        input,
    )
}

pub fn sha224(input: &[u8]) -> [u8; 28] {
    let IV = [
        0xc1059ed8u32,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4,
    ];
    merkle_damgard::<[u32; 8], _, _, _, 28, 64>(
        sha_padding::<64>,
        sha256_comp_fun,
        sha_finalize_32::<8, 28>,
        IV,
        input,
    )
}

fn sha512_comp_fun(state: &mut [u64; 8], chunk: [u8; 128]) {
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    let mut words: [u64; 80] = [0; 80];
    chunk
        .chunks(8)
        .zip(words.iter_mut())
        .for_each(|(c, w)| *w = u64::from_be_bytes(c.try_into().unwrap()));
    for i in 16..80 {
        let w15 = words[i - 15];
        let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
        let w2 = words[i - 2];
        let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
        words[i] = words[i - 16]
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }
    for i in 0usize..80 {
        let S1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(S1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(words[i]);
        let S0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = S0.wrapping_add(maj);
        (a, b, c, d, e, f, g, h) = (
            temp1.wrapping_add(temp2),
            a,
            b,
            c,
            d.wrapping_add(temp1),
            e,
            f,
            g,
        );
    }
    for (s,x) in state.iter_mut().zip([a,b,c,d,e,f,g,h]) {
        *s = s.wrapping_add(x);
    }
}


pub fn sha512(input: &[u8]) -> [u8; 64] {
    let IV = [
        0x6a09e667f3bcc908u64,
        0xbb67ae8584caa73bu64,
        0x3c6ef372fe94f82bu64,
        0xa54ff53a5f1d36f1u64,
        0x510e527fade682d1u64,
        0x9b05688c2b3e6c1fu64,
        0x1f83d9abfb41bd6bu64,
        0x5be0cd19137e2179u64,
    ];
    merkle_damgard::<[u64; 8], _, _, _, 64, 128>(
        sha_padding::<128>,
        sha512_comp_fun,
        sha_finalize_64::<8, 64>,
        IV,
        input,
    )
}

pub fn sha384(input: &[u8]) -> [u8; 48] {
    let IV = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];
    merkle_damgard::<[u64; 8], _, _, _, 48, 128>(
        sha_padding::<128>,
        sha512_comp_fun,
        sha_finalize_64::<8, 48>,
        IV,
        input,
    )
}

fn sha512_IV_generating_function(input: &[u8]) -> [u8; 64] {
    let IV = [
        0x6a09e667f3bcc908u64 ^ 0xa5a5a5a5a5a5a5a5,
        0xbb67ae8584caa73bu64 ^ 0xa5a5a5a5a5a5a5a5,
        0x3c6ef372fe94f82bu64 ^ 0xa5a5a5a5a5a5a5a5,
        0xa54ff53a5f1d36f1u64 ^ 0xa5a5a5a5a5a5a5a5,
        0x510e527fade682d1u64 ^ 0xa5a5a5a5a5a5a5a5,
        0x9b05688c2b3e6c1fu64 ^ 0xa5a5a5a5a5a5a5a5,
        0x1f83d9abfb41bd6bu64 ^ 0xa5a5a5a5a5a5a5a5,
        0x5be0cd19137e2179u64 ^ 0xa5a5a5a5a5a5a5a5,
    ];
    merkle_damgard::<[u64; 8], _, _, _, 64, 128>(
        sha_padding,
        sha512_comp_fun,
        sha_finalize_64::<8, 64>,
        IV,
        input,
    )
}


fn sha512_to_t<const T_BYTES: usize>(input: &[u8]) -> [u8; T_BYTES] {
    assert!(T_BYTES * 8 < 512, "t cannot be >= 512");
    let length = T_BYTES * 8;
    let IV: [u64; 8] = sha512_IV_generating_function(format!("SHA-512/{}", length).as_bytes())
        .chunks(8)
        .map(|x| u64::from_be_bytes((*x).try_into().unwrap()))
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();
    merkle_damgard::<[u64; 8], _, _, _, T_BYTES, 128>(
        sha_padding,
        sha512_comp_fun,
        sha_finalize_64::<8, T_BYTES>,
        IV,
        input,
    )
}

pub fn sha512_to_224(input: &[u8]) -> [u8; 28] {
    sha512_to_t::<28>(input)
}

pub fn sha512_to_256(input: &[u8]) -> [u8; 32] {
    sha512_to_t::<32>(input)
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];