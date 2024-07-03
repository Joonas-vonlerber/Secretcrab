use super::sha_padding;
use crate::Integrity::Merkle_Damgard::merkle_damgard;

fn sha_1_constants(i: usize, b: u32, c: u32, d: u32) -> (u32, u32) {
    match i {
        0..=19 => (((b & c) | ((!b) & d)), 0x5A827999u32), // (b and c) or ((not b) and d)
        20..=39 => ((b ^ c ^ d), 0x6ED9EBA1u32),           // b xor c xor d
        40..=59 => (((b & c) | (b & d) | (c & d)), 0x8F1BBCDCu32), // (b and c) or (b and d) or (c and d)
        60..=79 => ((b ^ c ^ d), 0xCA62C1D6u32),                   // b xor c xor d
        _ => unreachable!("By specification"),
    }
}

fn sha1_comp_fun(state: &mut [u32; 5], chunk: [u8; 64]) {
    let [mut a, mut b, mut c, mut d, mut e]: [u32; 5] = *state;
    let mut words: [u32; 80] = [0; 80];
    chunk.chunks(4).enumerate().for_each(|(i, x)| {
        words[i] = u32::from_be_bytes(x.try_into().unwrap());
    });
    for i in 16usize..80 {
        words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
    }
    for (i, w) in words.into_iter().enumerate() {
        let (f, k) = sha_1_constants(i, b, c, d);
        (a, b, c, d, e) = (
            a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w),
            a,
            b.rotate_left(30),
            c,
            d,
        );
    }
    for (s, x) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(x);
    }
}

fn sha1_finalize(state: [u32; 5]) -> [u8; 20] {
    state
        .map(|x| x.to_be_bytes())
        .concat()
        .try_into()
        .expect("5*32 should be 160/8")
}

pub fn sha1(input: &[u8]) -> [u8; 20] {
    let IV: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    merkle_damgard::<[u32; 5], _, _, _, 20, 64>(
        sha_padding::<64>,
        sha1_comp_fun,
        sha1_finalize,
        IV,
        input,
    )
}
