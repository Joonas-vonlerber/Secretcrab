use crate::Integrity::Sponge::Keccak::*;
#[derive(Debug, PartialEq)]
enum BlockSize {
    Bits512,
    Bits1024,
}
impl BlockSize {
    fn get_size_bytes(&self) -> usize {
        match self {
            BlockSize::Bits512 => 64,
            BlockSize::Bits1024 => 128,
        }
    }
}

fn pad_input(input: &[u8], block_size: BlockSize) -> Vec<u8> {
    let block_size_bytes = block_size.get_size_bytes();
    let lenght = input.len();
    let u128_length: [u8; 16] = u128::try_from(lenght * 8).unwrap().to_be_bytes();
    let u64_length: [u8; 8] = u64::try_from(lenght * 8).unwrap().to_be_bytes();
    let length_bytes = match block_size {
        BlockSize::Bits512 => u64_length.as_slice(),
        BlockSize::Bits1024 => u128_length.as_slice(),
    };
    let size_of_len_bytes = match block_size {
        BlockSize::Bits512 => std::mem::size_of::<u64>(),
        BlockSize::Bits1024 => std::mem::size_of::<u128>(),
    };
    let padding_needed = match lenght % block_size_bytes {
        x if x > block_size_bytes - size_of_len_bytes - 1 => {
            2 * block_size_bytes - x - size_of_len_bytes - 1
        }
        x => block_size_bytes - size_of_len_bytes - x - 1,
    };
    let padding_bits = [0x00u8].repeat(padding_needed);
    let message = [
        input,
        [0x80u8].as_slice(),
        padding_bits.as_slice(),
        length_bytes,
    ]
    .concat();
    assert_eq!(message.len() % block_size_bytes, 0);
    message
}

fn sha_1_constants(i: usize, b: u32, c: u32, d: u32) -> (u32, u32) {
    match i {
        0..=19 => (((b & c) | ((!b) & d)), 0x5A827999u32), // (b and c) or ((not b) and d)
        20..=39 => ((b ^ c ^ d), 0x6ED9EBA1u32),           // b xor c xor d
        40..=59 => (((b & c) | (b & d) | (c & d)), 0x8F1BBCDCu32), // (b and c) or (b and d) or (c and d)
        60..=79 => ((b ^ c ^ d), 0xCA62C1D6u32),                   // b xor c xor d
        _ => unreachable!("shouldn't go that high"),
    }
}

pub fn sha_1(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301u32;
    let mut h1: u32 = 0xEFCDAB89u32;
    let mut h2: u32 = 0x98BADCFEu32;
    let mut h3: u32 = 0x10325476u32;
    let mut h4: u32 = 0xC3D2E1F0u32;
    let mut a: u32;
    let mut b: u32;
    let mut c: u32;
    let mut d: u32;
    let mut e: u32;
    let message = pad_input(input, BlockSize::Bits512);
    for chunk in message.chunks(64) {
        // chunks are always size of 64
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        let mut words: Vec<u32> = chunk
            .chunks(4)
            .map(|word| u32::from_be_bytes(word.try_into().unwrap())) // will not fail because chunk_size == 4
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve_exact(64);
        (16..80).for_each(|i| {
            words.push((words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1))
        });
        assert_eq!(words.len(), 80);
        for (i, w) in words.iter().enumerate() {
            let (f, k) = sha_1_constants(i, b, c, d);
            (a, b, c, d, e) = (
                a.rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(*w),
                a,
                b.rotate_left(30),
                c,
                d,
            );
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap()
}

pub fn sha_256(input: &[u8]) -> [u8; 32] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        0x6a09e667u32,
        0xbb67ae85u32,
        0x3c6ef372u32,
        0xa54ff53au32,
        0x510e527fu32,
        0x9b05688cu32,
        0x1f83d9abu32,
        0x5be0cd19u32,
    );
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h);

    let message = pad_input(input, BlockSize::Bits512);
    for chunk_512 in message.chunks(64) {
        let mut words: Vec<u32> = chunk_512
            .chunks(4)
            .map(|word| u32::from_be_bytes(word.try_into().unwrap())) // will not fail because chunk_size == 4
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve_exact(48);
        (16..64usize).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            words.push(
                (words[i - 16])
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            )
        });
        assert_eq!(words.len(), 64);

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        for i in 0..64 {
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

            // h = g;
            // g = f;
            // f = e;
            // e = d.wrapping_add(temp1);
            // d = c;
            // c = b;
            // b = a;
            // a = temp1.wrapping_add(temp2);
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }
    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
        h7.to_be_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap()
}

//just so much unneccecary boilerplate
pub fn sha_244(input: &[u8]) -> [u8; 28] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        0xc1059ed8u32,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4,
    );
    let mut a: u32;
    let mut b: u32;
    let mut c: u32;
    let mut d: u32;
    let mut e: u32;
    let mut f: u32;
    let mut g: u32;
    let mut h: u32;

    let message = pad_input(input, BlockSize::Bits512);

    for chunk_512 in message.chunks(64) {
        let mut words: Vec<u32> = chunk_512
            .chunks(4)
            .map(|word| u32::from_be_bytes(word.try_into().unwrap())) // will not fail because chunk_size == 4
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve_exact(48);
        (16..64usize).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            words.push(
                (words[i - 16])
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            )
        });
        assert_eq!(words.len(), 64);

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        for i in 0..64 {
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
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }
    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap()
}

pub fn sha_512(input: &[u8]) -> [u8; 64] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        0x6a09e667f3bcc908u64,
        0xbb67ae8584caa73bu64,
        0x3c6ef372fe94f82bu64,
        0xa54ff53a5f1d36f1u64,
        0x510e527fade682d1u64,
        0x9b05688c2b3e6c1fu64,
        0x1f83d9abfb41bd6bu64,
        0x5be0cd19137e2179u64,
    );
    let mut a: u64;
    let mut b: u64;
    let mut c: u64;
    let mut d: u64;
    let mut e: u64;
    let mut f: u64;
    let mut g: u64;
    let mut h: u64;

    let message = pad_input(input, BlockSize::Bits1024);
    for chunk in message.chunks(128) {
        let mut words: Vec<u64> = chunk
            .chunks(8)
            .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve(64);
        (16..80).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            words.push(
                words[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            );
        });
        (a, b, c, d, e, f, g, h) = (h0, h1, h2, h3, h4, h5, h6, h7);
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
        (h0, h1, h2, h3, h4, h5, h6, h7) = (
            h0.wrapping_add(a),
            h1.wrapping_add(b),
            h2.wrapping_add(c),
            h3.wrapping_add(d),
            h4.wrapping_add(e),
            h5.wrapping_add(f),
            h6.wrapping_add(g),
            h7.wrapping_add(h),
        );
    }
    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
        h7.to_be_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap()
}

// fuck this boilerplait for just two fucking changes
pub fn sha_384(input: &[u8]) -> [u8; 48] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    );
    let mut a: u64;
    let mut b: u64;
    let mut c: u64;
    let mut d: u64;
    let mut e: u64;
    let mut f: u64;
    let mut g: u64;
    let mut h: u64;

    let message = pad_input(input, BlockSize::Bits1024);
    for chunk in message.chunks(128) {
        let mut words: Vec<u64> = chunk
            .chunks(8)
            .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve(64);
        (16..80).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            words.push(
                words[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            );
        });

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

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
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }
    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap()
}

//boilerplait go brr
fn sha_512_IV_generating_function(input: &[u8]) -> [u8; 64] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        0x6a09e667f3bcc908u64 ^ 0xa5a5a5a5a5a5a5a5,
        0xbb67ae8584caa73bu64 ^ 0xa5a5a5a5a5a5a5a5,
        0x3c6ef372fe94f82bu64 ^ 0xa5a5a5a5a5a5a5a5,
        0xa54ff53a5f1d36f1u64 ^ 0xa5a5a5a5a5a5a5a5,
        0x510e527fade682d1u64 ^ 0xa5a5a5a5a5a5a5a5,
        0x9b05688c2b3e6c1fu64 ^ 0xa5a5a5a5a5a5a5a5,
        0x1f83d9abfb41bd6bu64 ^ 0xa5a5a5a5a5a5a5a5,
        0x5be0cd19137e2179u64 ^ 0xa5a5a5a5a5a5a5a5,
    );
    let mut a: u64;
    let mut b: u64;
    let mut c: u64;
    let mut d: u64;
    let mut e: u64;
    let mut f: u64;
    let mut g: u64;
    let mut h: u64;

    let message = pad_input(input, BlockSize::Bits1024);
    for chunk in message.chunks(128) {
        let mut words: Vec<u64> = chunk
            .chunks(8)
            .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve(64);
        (16..80).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            words.push(
                words[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            );
        });
        (a, b, c, d, e, f, g, h) = (h0, h1, h2, h3, h4, h5, h6, h7);
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
        (h0, h1, h2, h3, h4, h5, h6, h7) = (
            h0.wrapping_add(a),
            h1.wrapping_add(b),
            h2.wrapping_add(c),
            h3.wrapping_add(d),
            h4.wrapping_add(e),
            h5.wrapping_add(f),
            h6.wrapping_add(g),
            h7.wrapping_add(h),
        );
    }
    [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
        h7.to_be_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap()
}

pub fn sha_512_to_244(input: &[u8]) -> [u8; 28] {
    let [mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7]: [u64; 8] = unsafe {
        sha_512_IV_generating_function(b"SHA-512/224")
            .as_chunks_unchecked::<8>()
            .iter()
            .map(|x| u64::from_be_bytes(*x))
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap()
    }; // SAFETY: 64 is divisible by 8
    let mut a: u64;
    let mut b: u64;
    let mut c: u64;
    let mut d: u64;
    let mut e: u64;
    let mut f: u64;
    let mut g: u64;
    let mut h: u64;

    let message = pad_input(input, BlockSize::Bits1024);
    for chunk in message.chunks(128) {
        let mut words: Vec<u64> = chunk
            .chunks(8)
            .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve(64);
        (16..80).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            words.push(
                words[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            );
        });
        (a, b, c, d, e, f, g, h) = (h0, h1, h2, h3, h4, h5, h6, h7);
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
        (h0, h1, h2, h3, h4, h5, h6, h7) = (
            h0.wrapping_add(a),
            h1.wrapping_add(b),
            h2.wrapping_add(c),
            h3.wrapping_add(d),
            h4.wrapping_add(e),
            h5.wrapping_add(f),
            h6.wrapping_add(g),
            h7.wrapping_add(h),
        );
    }
    let mut hh = [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
        h7.to_be_bytes(),
    ]
    .concat();
    hh.truncate(28);
    hh.try_into().unwrap()
}

pub fn sha_512_to_256(input: &[u8]) -> [u8; 32] {
    let [mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7]: [u64; 8] = unsafe {
        sha_512_IV_generating_function(b"SHA-512/256")
            .as_chunks_unchecked::<8>()
            .iter()
            .map(|x| u64::from_be_bytes(*x))
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap()
    }; // SAFETY: 64 is divisible by 8
    let mut a: u64;
    let mut b: u64;
    let mut c: u64;
    let mut d: u64;
    let mut e: u64;
    let mut f: u64;
    let mut g: u64;
    let mut h: u64;

    let message = pad_input(input, BlockSize::Bits1024);
    for chunk in message.chunks(128) {
        let mut words: Vec<u64> = chunk
            .chunks(8)
            .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words.len(), 16);
        words.reserve(64);
        (16..80).for_each(|i| {
            let w15 = words[i - 15];
            let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let w2 = words[i - 2];
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            words.push(
                words[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(words[i - 7])
                    .wrapping_add(s1),
            );
        });
        (a, b, c, d, e, f, g, h) = (h0, h1, h2, h3, h4, h5, h6, h7);
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
        (h0, h1, h2, h3, h4, h5, h6, h7) = (
            h0.wrapping_add(a),
            h1.wrapping_add(b),
            h2.wrapping_add(c),
            h3.wrapping_add(d),
            h4.wrapping_add(e),
            h5.wrapping_add(f),
            h6.wrapping_add(g),
            h7.wrapping_add(h),
        );
    }
    let mut hh = [
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
        h7.to_be_bytes(),
    ]
    .concat();
    hh.truncate(32);
    hh.try_into().unwrap()
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

/*
-
-
-                   TESTING
-
-
-
- */
#[cfg(test)]
mod SHA_tests {
    use super::*;
    use const_hex::encode;
    use std::env;
    #[test]
    fn sha1_test() {
        env::set_var("RUST_BACKTRACE", "1");
        let lol_hash = encode(sha_1(b"lol"));
        assert_eq!(
            lol_hash,
            "403926033d001b5279df37cbbe5287b7c7c267fa".to_owned()
        );
        let lazy_dog = encode(sha_1(b"The quick brown fox jumps over the lazy dog").as_slice());
        assert_eq!(
            lazy_dog,
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_owned()
        );
        let lazy_cog = encode(sha_1(b"The quick brown fox jumps over the lazy cog").as_slice());
        assert_eq!(
            lazy_cog,
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3".to_owned()
        );
    }
    #[test]
    fn sha_256_test() {
        let Hello_hash = encode(sha_256(b"Hello").as_slice());
        assert_eq!(
            Hello_hash,
            "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969".to_owned()
        );
        let lazy_dog = encode(sha_256(b"The quick brown fox jumps over the lazy dog").as_slice());
        assert_eq!(
            lazy_dog,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_owned()
        );
        let lazy_cog = encode(sha_256(b"The quick brown fox jumps over the lazy cog").as_slice());
        assert_eq!(
            lazy_cog,
            "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be".to_owned()
        );
    }
    #[test]
    fn sha_512_test() {
        let hello_hash = encode(sha_512(b"Hello").as_slice());
        assert_eq!(hello_hash, "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315".to_owned());
        let lazy_dog = encode(sha_512(b"The quick brown fox jumps over the lazy dog").as_slice());
        assert_eq!(
            lazy_dog,
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6".to_owned()
        );
        let lazy_cog = encode(sha_512(b"The quick brown fox jumps over the lazy cog").as_slice());
        assert_eq!(
            lazy_cog,
            "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045".to_owned()
        );
    }
    #[test]
    fn sha_512_to_t_test() {
        let hello_hash_244 = encode(sha_512_to_244(b"Hello").as_slice());
        assert_eq!(
            hello_hash_244,
            "0d075258abfd1f8b81fc0a5207a1aa5cc82eb287720b1f849b862235".to_owned()
        );
        let hello_hash_256 = encode(sha_512_to_256(b"Hello").as_slice());
        assert_eq!(
            hello_hash_256,
            "7e75b18b88d2cb8be95b05ec611e54e2460408a2dcf858f945686446c9d07aac".to_owned()
        );
    }

    #[test]
    fn sha_3_224_test() {
        let hello_hash_224 = encode(sha_3_244(b"Hello"));
        assert_eq!(
            hello_hash_224,
            "4cf679344af02c2b89e4a902f939f4608bcac0fbf81511da13d7d9b9".to_owned()
        );
    }

    #[test]
    fn sha_3_256_test() {
        let hello_hash_256 = encode(sha_3_256(b"Hello"));
        assert_eq!(
            hello_hash_256,
            "8ca66ee6b2fe4bb928a8e3cd2f508de4119c0895f22e011117e22cf9b13de7ef"
        )
    }

    #[test]
    fn sha_3_384_test() {
        let hello_hash_384 = encode(sha_3_384(b"Hello"));
        assert_eq!(
        hello_hash_384,
        "df7e26e3d067579481501057c43aea61035c8ffdf12d9ae427ef4038ad7c13266a11c0a3896adef37ad1bc85a2b5bdac"
    )
    }

    #[test]
    fn sha_3_512_test() {
        let hello_hash_512 = encode(sha_3_512(b"Hello"));
        assert_eq!(
        hello_hash_512,
        "0b8a44ac991e2b263e8623cfbeefc1cffe8c1c0de57b3e2bf1673b4f35e660e89abd18afb7ac93cf215eba36dd1af67698d6c9ca3fdaaf734ffc4bd5a8e34627"
    )
    }
}
