const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const INITIALIZATION_VECTOR_2B: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const INITIALIZATION_VECTOR_2S: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

#[inline]
fn mix_2b(work_vector: &mut [u64], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    work_vector[a] = work_vector[a].wrapping_add(work_vector[b]).wrapping_add(x);
    work_vector[d] = (work_vector[d] ^ work_vector[a]).rotate_right(32);

    work_vector[c] = work_vector[c].wrapping_add(work_vector[d]);
    work_vector[b] = (work_vector[b] ^ work_vector[c]).rotate_right(24);

    work_vector[a] = work_vector[a].wrapping_add(work_vector[b]).wrapping_add(y);
    work_vector[d] = (work_vector[d] ^ work_vector[a]).rotate_right(16);

    work_vector[c] = work_vector[c].wrapping_add(work_vector[d]);
    work_vector[b] = (work_vector[b] ^ work_vector[c]).rotate_right(63);
}

fn compress_2b(state: &mut [u64; 8], chunk: &[u8; 128], offset: u128, is_last: bool) {
    // Init work and message vectors
    let mut work_vector: Vec<u64> = [*state, INITIALIZATION_VECTOR_2B].concat();
    let message_chunk: [u64; 16] = chunk
        .chunks(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();
    work_vector[12] ^= offset as u64;
    work_vector[13] ^= (offset >> 64) as u64;

    // invert if last
    if is_last {
        work_vector[14] = !work_vector[14]
    }

    let mut round_sigma: [usize; 16];
    // Throw them into the cryptographic blender
    for i in 0..12 {
        round_sigma = SIGMA[i % 10];
        mix_2b(
            &mut work_vector,
            0,
            4,
            8,
            12,
            message_chunk[round_sigma[0]],
            message_chunk[round_sigma[1]],
        );
        mix_2b(
            &mut work_vector,
            1,
            5,
            9,
            13,
            message_chunk[round_sigma[2]],
            message_chunk[round_sigma[3]],
        );
        mix_2b(
            &mut work_vector,
            2,
            6,
            10,
            14,
            message_chunk[round_sigma[4]],
            message_chunk[round_sigma[5]],
        );
        mix_2b(
            &mut work_vector,
            3,
            7,
            11,
            15,
            message_chunk[round_sigma[6]],
            message_chunk[round_sigma[7]],
        );
        mix_2b(
            &mut work_vector,
            0,
            5,
            10,
            15,
            message_chunk[round_sigma[8]],
            message_chunk[round_sigma[9]],
        );
        mix_2b(
            &mut work_vector,
            1,
            6,
            11,
            12,
            message_chunk[round_sigma[10]],
            message_chunk[round_sigma[11]],
        );
        mix_2b(
            &mut work_vector,
            2,
            7,
            8,
            13,
            message_chunk[round_sigma[12]],
            message_chunk[round_sigma[13]],
        );
        mix_2b(
            &mut work_vector,
            3,
            4,
            9,
            14,
            message_chunk[round_sigma[14]],
            message_chunk[round_sigma[15]],
        );
    }

    // Xor them in
    for i in 0..8 {
        state[i] = state[i] ^ work_vector[i] ^ work_vector[i + 8];
    }
}

/// The BLAKE2B hash function. HASH_LEN is the digest length in bytes and is between 1 and 64.<br>Key is optional and if there is one, it should be less then 64 bytes.
///
/// ## Panics
/// if `HASH_LEN == 0` or `HASH_LEN > 64`<br>
/// if `key.unwrap_or(vec![]).len() > 64`
pub fn blake2b<const HASH_LEN: usize>(input: &[u8], key: Option<Vec<u8>>) -> [u8; HASH_LEN] {
    assert!(HASH_LEN <= 64 && 0 < HASH_LEN);
    // Take the key
    let key: Vec<u8> = key.unwrap_or(Vec::new());
    assert!(key.len() <= 64);
    // Init the state
    let mut state: [u64; 8] = INITIALIZATION_VECTOR_2B;
    state[0] ^= 0x01010000 ^ ((key.len() as u64) << 8) ^ HASH_LEN as u64;

    let mut bytes_compressed: u128 = 0;
    let mut bytes_remaning: u128 = input.len() as u128;

    // bake the key in to the message if there is one
    let mut M = input.to_vec();
    if !key.is_empty() {
        M = [pad_with_zeros(&key, 128), M].concat();
        bytes_remaning += 128;
    }

    // start compressing
    let mut chunks = M.chunks(128);
    let mut chunk: [u8; 128];
    while bytes_remaning > 128 {
        chunk = chunks
            .next()
            .expect("There was no next element")
            .try_into()
            .unwrap();
        bytes_compressed += 128;
        bytes_remaning -= 128;
        compress_2b(&mut state, &chunk, bytes_compressed, false);
    }

    // compress the last chunk
    chunk = pad_with_zeros(chunks.next().unwrap_or(&[]), 128)
        .try_into()
        .expect("Padding did not work");
    bytes_compressed += bytes_remaning;
    compress_2b(&mut state, &chunk, bytes_compressed, true);

    // Return the first HASH_LEN bytes of the state
    state
        .into_iter()
        .flat_map(|word| word.to_le_bytes())
        .take(HASH_LEN)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

fn pad_with_zeros(input: &[u8], size: u32) -> Vec<u8> {
    match size as usize > input.len() {
        true => [input, &[0x00].repeat(size as usize - input.len())].concat(),
        false => input.to_vec(),
    }
}

// BOILERPLATE!!!!!

#[inline]
fn mix_2s(work_vector: &mut [u32], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    work_vector[a] = work_vector[a].wrapping_add(work_vector[b]).wrapping_add(x);
    work_vector[d] = (work_vector[d] ^ work_vector[a]).rotate_right(16);

    work_vector[c] = work_vector[c].wrapping_add(work_vector[d]);
    work_vector[b] = (work_vector[b] ^ work_vector[c]).rotate_right(12);

    work_vector[a] = work_vector[a].wrapping_add(work_vector[b]).wrapping_add(y);
    work_vector[d] = (work_vector[d] ^ work_vector[a]).rotate_right(8);

    work_vector[c] = work_vector[c].wrapping_add(work_vector[d]);
    work_vector[b] = (work_vector[b] ^ work_vector[c]).rotate_right(7);
}

fn compress_2s(state: &mut [u32; 8], chunk: &[u8; 64], offset: u64, is_last: bool) {
    // Init work and message vectors
    let mut work_vector: Vec<u32> = [*state, INITIALIZATION_VECTOR_2S].concat();
    let message_chunk: [u32; 16] = chunk
        .chunks(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();
    work_vector[12] ^= offset as u32;
    work_vector[13] ^= (offset >> 32) as u32;

    // invert if last
    if is_last {
        work_vector[14] = !work_vector[14]
    }

    let mut round_sigma: [usize; 16];
    // Throw them into the cryptographic blender
    for i in 0..10 {
        round_sigma = SIGMA[i % 10];
        mix_2s(
            &mut work_vector,
            0,
            4,
            8,
            12,
            message_chunk[round_sigma[0]],
            message_chunk[round_sigma[1]],
        );
        mix_2s(
            &mut work_vector,
            1,
            5,
            9,
            13,
            message_chunk[round_sigma[2]],
            message_chunk[round_sigma[3]],
        );
        mix_2s(
            &mut work_vector,
            2,
            6,
            10,
            14,
            message_chunk[round_sigma[4]],
            message_chunk[round_sigma[5]],
        );
        mix_2s(
            &mut work_vector,
            3,
            7,
            11,
            15,
            message_chunk[round_sigma[6]],
            message_chunk[round_sigma[7]],
        );
        mix_2s(
            &mut work_vector,
            0,
            5,
            10,
            15,
            message_chunk[round_sigma[8]],
            message_chunk[round_sigma[9]],
        );
        mix_2s(
            &mut work_vector,
            1,
            6,
            11,
            12,
            message_chunk[round_sigma[10]],
            message_chunk[round_sigma[11]],
        );
        mix_2s(
            &mut work_vector,
            2,
            7,
            8,
            13,
            message_chunk[round_sigma[12]],
            message_chunk[round_sigma[13]],
        );
        mix_2s(
            &mut work_vector,
            3,
            4,
            9,
            14,
            message_chunk[round_sigma[14]],
            message_chunk[round_sigma[15]],
        );
    }

    // Xor them in
    for i in 0..8 {
        state[i] = state[i] ^ work_vector[i] ^ work_vector[i + 8];
    }
}

/// The BLAKE2S hash function. HASH_LEN is the digest length in bytes and is between 1 and 32.<br>Key is optional and if there is one, it should be less then 32 bytes.
///
/// ## Panics
/// if `HASH_LEN == 0` or `HASH_LEN > 32`<br>
/// if `key.unwrap_or(vec![]).len() > 32`
pub fn blake2s<const HASH_LEN: usize>(input: &[u8], key: Option<Vec<u8>>) -> [u8; HASH_LEN] {
    assert!(HASH_LEN <= 32 && 0 < HASH_LEN);
    // Take the key
    let key: Vec<u8> = key.unwrap_or(Vec::new());
    assert!(key.len() <= 32);
    // Init the state
    let mut state: [u32; 8] = INITIALIZATION_VECTOR_2S;
    state[0] ^= 0x01010000 ^ ((key.len() as u32) << 8) ^ HASH_LEN as u32;

    let mut bytes_compressed: u64 = 0;
    let mut bytes_remaning: u64 = input.len() as u64;

    // bake the key in to the message if there is one
    let mut M = input.to_vec();
    if !key.is_empty() {
        M = [pad_with_zeros(&key, 64), M].concat();
        bytes_remaning += 64;
    }

    // start compressing
    let mut chunks = M.chunks(64);
    let mut chunk: [u8; 64];
    while bytes_remaning > 64 {
        chunk = chunks
            .next()
            .expect("There was no next element")
            .try_into()
            .unwrap();
        bytes_compressed += 64;
        bytes_remaning -= 64;
        compress_2s(&mut state, &chunk, bytes_compressed, false);
    }

    // compress the last chunk
    chunk = pad_with_zeros(chunks.next().unwrap_or(&[]), 64)
        .try_into()
        .expect("Padding did not work");
    bytes_compressed += bytes_remaning;
    compress_2s(&mut state, &chunk, bytes_compressed, true);

    // Return the first HASH_LEN bytes of the state
    state
        .into_iter()
        .flat_map(|word| word.to_le_bytes())
        .take(HASH_LEN)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

pub fn blake2_244(input: &[u8]) -> [u8; 28] {
    blake2s::<28>(input, None)
}

pub fn blake2_256(input: &[u8]) -> [u8; 32] {
    blake2s::<32>(input, None)
}

pub fn blake2_384(input: &[u8]) -> [u8; 48] {
    blake2b::<48>(input, None)
}

pub fn blake2_512(input: &[u8]) -> [u8; 64] {
    blake2b::<64>(input, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use const_hex::const_decode_to_array;
    #[test]
    fn blake2b_512_test() {
        let message1 = b"";
        let expected1: [u8; 64] = const_decode_to_array(b"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce").unwrap();
        assert_eq!(blake2b::<64>(message1, None), expected1);

        let message2 = b"The quick brown fox jumps over the lazy dog";
        let expected2: [u8; 64] = const_decode_to_array(b"a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918").unwrap();
        assert_eq!(blake2b::<64>(message2, None), expected2);

        let message3 = b"";
        let key3 = Some(b"yaas".to_vec());
        let expected3: [u8; 64] = const_decode_to_array(b"3559e2a509bf0974915150b6206fa1232f062127aa668ea6b13983f0a7562d0c51e49ab4b8e8cd50c57f0f379814edc23ac4f11422ca23cf9aab33f890bf010d").unwrap();
        assert_eq!(blake2b(message3, key3), expected3);

        let message4 = b"The quick brown fox jumps over the lazy dog";
        let key4 = Some([0xff].repeat(64));
        let expected4: [u8; 64] = const_decode_to_array(b"efdaa05992a1bf786afd51599fe236625c6a0be8061938084bef8903126511c6be8d759b207669c9892d28f5753c82d57921c2d7d05ab46f08e82ad63e38e314").unwrap();
        assert_eq!(blake2b(message4, key4), expected4);
    }

    #[test]
    fn blake2s_256_test() {
        let message1 = b"";
        let expected1: [u8; 32] = const_decode_to_array(
            b"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        )
        .unwrap();

        assert_eq!(blake2s::<32>(message1, None), expected1);

        let message2 = b"Hello, world!";
        let expected2: [u8; 32] = const_decode_to_array(
            b"30d8777f0e178582ec8cd2fcdc18af57c828ee2f89e978df52c8e7af078bd5cf",
        )
        .unwrap();
        assert_eq!(blake2s::<32>(message2, None), expected2);

        let message3 = b"";
        let key3 = Some(b"yaas".to_vec());
        let expected3: [u8; 32] = const_decode_to_array(
            b"9cfcab13a204d1c31dbec19fc91e7f908917b1e0a739c4d4c6a90cba5f5f0289",
        )
        .unwrap();
        assert_eq!(blake2s(message3, key3), expected3);

        let message4 = b"Hello, world!";
        let key4 = Some([0xff].repeat(32));
        let expected4: [u8; 32] = const_decode_to_array(
            b"0c439e22dbacb9b6c7ba7a038eb74fa2ebe2ec90a79e5f1a7b3554e4f5a2d6a0",
        )
        .unwrap();
        assert_eq!(blake2s(message4, key4), expected4);
    }
}
