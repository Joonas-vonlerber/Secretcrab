use ndarray::prelude::*;

use crate::Block_cypher::{BlockCypher, Padding, CBC, ECB};
type AESState = Array2<u8>;

#[derive(Debug, PartialEq)]
enum AESKeySize {
    Key128,
    Key192,
    Key256,
}

impl AESKeySize {
    fn key_size_in_32_words(&self) -> usize {
        match self {
            Self::Key128 => 4,
            Self::Key192 => 6,
            Self::Key256 => 8,
        }
    }
    fn rounds_keys_needed(&self) -> usize {
        match self {
            Self::Key128 => 11,
            Self::Key192 => 13,
            Self::Key256 => 15,
        }
    }
}

pub(crate) fn sub_byte(byte: u8) -> u8 {
    AES_S_BOX[byte as usize]
}

fn inverse_sub_byte(byte: u8) -> u8 {
    AES_REVERSE_S_BOX[byte as usize]
}

fn sub_word(word: u32) -> u32 {
    u32::from_be_bytes(word.to_be_bytes().map(sub_byte))
}

fn rotate_word(word: u32) -> u32 {
    word.rotate_left(8)
}

fn key_schedule(original_key: &[u32], round_keys_needed: usize) -> Vec<u32> {
    let mut expanded_keys: Vec<u32> = Vec::new();
    expanded_keys.reserve_exact(4 * round_keys_needed);
    let lenght = original_key.len();
    for round in 0..(4 * round_keys_needed) {
        expanded_keys.push(match round {
            i if i < lenght => original_key[i],
            i if i % lenght == 0 => {
                expanded_keys[i - lenght]
                    ^ sub_word(rotate_word(expanded_keys[i - 1]))
                    ^ ROUND_CONSTANTS[i / lenght]
            }
            i if (lenght > 6) && (i % lenght == 4) => {
                expanded_keys[i - lenght] ^ sub_word(expanded_keys[i - 1])
            }
            i => expanded_keys[i - lenght] ^ expanded_keys[i - 1],
        })
    }
    expanded_keys
    // .chunks(4)
    // .map(|key| {
    //     Array2::from_shape_vec(
    //         (4, 4).f(),
    //         key.iter().flat_map(|word| word.to_be_bytes()).collect(),
    //     )
    //     .unwrap()
    // })
    // .collect::<Vec<_>>()
}

fn words_to_state(words: &[u32]) -> AESState {
    assert_eq!(words.len(), 4);
    Array2::from_shape_vec(
        (4, 4).f(),
        words.iter().flat_map(|word| word.to_be_bytes()).collect(),
    )
    .unwrap()
}

fn add_round_key(state: &mut AESState, key: &AESState) {
    assert_eq!(state.shape(), key.shape());
    *state ^= key;
}

fn sub_bytes(state: &mut AESState) {
    state.map_inplace(|byte| *byte = sub_byte(*byte))
}

fn inverse_sub_bytes(state: &mut AESState) {
    state.map_inplace(|byte| *byte = inverse_sub_byte(*byte))
}

fn bytearray_rotate_left(mut array: ArrayViewMut1<u8>, mid: usize) {
    assert_eq!(array.len(), 4);
    assert!(mid <= 3);
    let mut temp;
    for _ in 0..mid {
        temp = array[0];
        array[0] = array[1];
        array[1] = array[2];
        array[2] = array[3];
        array[3] = temp;
    }
}

fn bytearray_rotate_right(mut array: ArrayViewMut1<u8>, mid: usize) {
    assert_eq!(array.len(), 4);
    assert!(mid <= 4);
    let mut temp: u8;
    for _ in 0..mid {
        temp = array[3];
        array[3] = array[2];
        array[2] = array[1];
        array[1] = array[0];
        array[0] = temp;
    }
}

fn shift_rows(state: &mut AESState) {
    for (rot, row) in state.rows_mut().into_iter().enumerate() {
        bytearray_rotate_left(row, rot);
    }
}

fn inverse_shift_rows(state: &mut AESState) {
    for (rot, row) in state.rows_mut().into_iter().enumerate() {
        bytearray_rotate_right(row, rot)
    }
}
fn mul_char_2(lhs: u8, rhs: u8, bits: usize, modulo: u8) -> u8 {
    let mut a: u8 = lhs;
    let mut b: u8 = rhs;
    let mut p: u8 = 0;
    let mut carry: bool;
    for _ in 0..bits {
        if b & 1 == 1 {
            p ^= a;
        }
        b >>= 1;
        carry = a >> (bits - 1) == 1;
        a <<= 1;
        if carry {
            a ^= modulo
        }
    }
    p
}

fn GF_mul(lhs: u8, rhs: u8) -> u8 {
    mul_char_2(lhs, rhs, 8, 0x1b)
}

fn mix_columns(state: &mut AESState) {
    let mut temp_vec: Vec<u8>;
    for mut column in state.columns_mut() {
        temp_vec = column.to_vec();
        column[0] = GF_mul(2, temp_vec[0]) ^ GF_mul(3, temp_vec[1]) ^ temp_vec[2] ^ temp_vec[3];
        column[1] = temp_vec[0] ^ GF_mul(2, temp_vec[1]) ^ GF_mul(3, temp_vec[2]) ^ temp_vec[3];
        column[2] = temp_vec[0] ^ temp_vec[1] ^ GF_mul(2, temp_vec[2]) ^ GF_mul(3, temp_vec[3]);
        column[3] = GF_mul(3, temp_vec[0]) ^ temp_vec[1] ^ temp_vec[2] ^ GF_mul(2, temp_vec[3]);
    }
}

fn inverse_mix_colums(state: &mut AESState) {
    let mut temp_vec: Vec<u8>;
    for mut column in state.columns_mut() {
        temp_vec = column.to_vec();
        column[0] = GF_mul(0x0e, temp_vec[0])
            ^ GF_mul(0x0b, temp_vec[1])
            ^ GF_mul(0x0d, temp_vec[2])
            ^ GF_mul(9, temp_vec[3]);
        column[1] = GF_mul(9, temp_vec[0])
            ^ GF_mul(0x0e, temp_vec[1])
            ^ GF_mul(0x0b, temp_vec[2])
            ^ GF_mul(0x0d, temp_vec[3]);
        column[2] = GF_mul(0x0d, temp_vec[0])
            ^ GF_mul(9, temp_vec[1])
            ^ GF_mul(0x0e, temp_vec[2])
            ^ GF_mul(0x0b, temp_vec[3]);
        column[3] = GF_mul(0x0b, temp_vec[0])
            ^ GF_mul(0x0d, temp_vec[1])
            ^ GF_mul(9, temp_vec[2])
            ^ GF_mul(0x0e, temp_vec[3]);
    }
}

fn encryption(state: &mut AESState, key: &[u32], key_lenght: &AESKeySize) {
    let round_keys: Vec<AESState> = key_schedule(key, key_lenght.rounds_keys_needed())
        .chunks(4)
        .map(words_to_state)
        .collect();
    add_round_key(state, round_keys.first().unwrap());
    for round_key in round_keys[1..(round_keys.len() - 1)].iter() {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys.last().unwrap());
}

fn decryption(state: &mut AESState, key: &[u32], key_lenght: &AESKeySize) {
    let round_keys: Vec<AESState> = key_schedule(key, key_lenght.rounds_keys_needed())
        .chunks(4)
        .map(words_to_state)
        .rev()
        .collect();
    add_round_key(state, round_keys.first().unwrap());
    for round_key in round_keys[1..(round_keys.len() - 1)].iter() {
        inverse_shift_rows(state);
        inverse_sub_bytes(state);
        add_round_key(state, round_key);
        inverse_mix_colums(state);
    }
    inverse_shift_rows(state);
    inverse_sub_bytes(state);
    add_round_key(state, round_keys.last().unwrap());
}

fn pad_ANSIX923_message(input: &[u8]) -> Vec<u8> {
    let bytes_needed = 16 - (input.len() % 16);
    let num_byte = bytes_needed as u8;
    [input, &[0x00].repeat(bytes_needed - 1), &[num_byte]].concat()
}

fn unpad_ANSIX923_message(input: &[u8]) -> Vec<u8> {
    let len_padded_bytes = input.last().unwrap();
    let mut unpadded = input.to_vec();
    unpadded.truncate(unpadded.len() - *len_padded_bytes as usize);
    unpadded
}

fn bytes_to_block(input: &[u8]) -> Vec<AESState> {
    assert_eq!(input.len() % 16, 0);
    input
        .chunks_exact(16)
        .map(|bytes| Array2::from_shape_vec((4, 4).f(), bytes.to_vec()).unwrap())
        .collect()
}

fn block_to_array(block: [u8; 16]) -> AESState {
    Array2::from_shape_vec((4, 4).f(), block.to_vec()).expect("Block should have been 16 bytes")
}

struct AES;

impl BlockCypher<16, 16> for AES {
    fn encrypt_block(key: &[u8; 16], plain_text_block: &[u8; 16]) -> [u8; 16] {
        let mut block = block_to_array(*plain_text_block);
        let key_u32: Vec<u32> = key
            .array_chunks::<4>()
            .map(|word| u32::from_be_bytes(*word)) // LE or BE??
            .collect();
        encryption(&mut block, &key_u32[..], &AESKeySize::Key128);
        block.into_raw_vec().try_into().unwrap()
    }
    fn decrypt_block(key: &[u8; 16], cypher_text_block: &[u8; 16]) -> [u8; 16] {
        let mut block = block_to_array(*cypher_text_block);
        let key_u32: Vec<u32> = key
            .array_chunks::<4>()
            .map(|word| u32::from_be_bytes(*word)) // LE or BE??
            .collect();
        decryption(&mut block, &key_u32, &AESKeySize::Key128);
        block.into_raw_vec().try_into().unwrap()
    }
}
/// PKCS#5 padding
///
/// ## Panics
/// if:
/// - data.len() > AMOUNT
/// - AMOUNT < 256
/// - AMOUNT = 0
fn pad_PKCS5<const AMOUNT: usize>(data: &[u8]) -> [u8; AMOUNT] {
    assert!(data.len() <= AMOUNT);
    assert!(AMOUNT < 256);
    assert_ne!(AMOUNT, 0);
    let bytes_needed: usize = AMOUNT - data.len();
    [data, [bytes_needed as u8].repeat(bytes_needed).as_slice()]
        .concat()
        .try_into()
        .expect("Padding is broken")
}

fn unpad_PKCS5<const AMOUNT: usize>(data: [u8; AMOUNT]) -> Result<Vec<u8>, [u8; AMOUNT]> {
    assert_ne!(AMOUNT, 0);
    let mut output = data.to_vec();
    let added_bytes = data.last().expect("Cannot unpad empty data");
    if data
        .iter()
        .rev()
        .take(*added_bytes as usize)
        .all(|x| *x == *added_bytes)
    {
        output.truncate(AMOUNT - *added_bytes as usize);
        Ok(output)
    } else {
        Err(data)
    }
}

impl Padding<16> for AES {
    fn pad(data: &[u8]) -> impl Iterator<Item = [u8; 16]> {
        let block_iterator = data.array_chunks::<16>();
        let remainder = block_iterator.remainder();
        block_iterator
            .copied()
            .chain(std::iter::once(pad_PKCS5::<16>(remainder)))
    }
    /// ## Panics
    /// if data.len() = 0
    fn unpad(data: &[[u8; 16]]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(data.len() * 16);
        let (last, xs) = data.split_last().expect("data was empty");
        let unpacked = unpad_PKCS5(*last);
        buf.extend(xs.iter().flatten());
        match unpacked {
            Ok(val) => buf.extend(val),
            Err(val) => buf.extend(val),
        };
        buf
    }
}
// LOOKUP TABLES AHEAD

const AES_S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_REVERSE_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const ROUND_CONSTANTS: [u32; 11] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1B000000, 0x36000000,
];

/*
-
-
-
-                   TESTING
-
-
-
-
*/

#[test]
fn key_schedule_test() {
    let expanded_keys = key_schedule(&[0, 0, 0, 0], 11);
    let test_vec: Vec<u32> = vec![
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x62636363, 0x62636363, 0x62636363,
        0x62636363, 0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa, 0x90973450, 0x696ccffa,
        0xf2f45733, 0x0b0fac99, 0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b, 0x7f2e2b88,
        0xf8443e09, 0x8dda7cbb, 0xf34b9290, 0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7,
        0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b, 0x0ef90333, 0x3ba96138, 0x97060a04,
        0x511dfa9f, 0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941, 0xb4ef5bcb, 0x3e92e211,
        0x23e951cf, 0x6f8f188e,
    ];
    assert_eq!(expanded_keys.len(), test_vec.len());
    assert_eq!(expanded_keys, test_vec);
}

#[test]
fn shift_rows_test() {
    let mut test_array = Array2::from_shape_vec(
        (4, 4).f(),
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    )
    .unwrap();
    shift_rows(&mut test_array);
    let result = Array2::from_shape_vec(
        (4, 4).f(),
        vec![0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11],
    )
    .unwrap();
    assert_eq!(test_array, result);
}

#[test]
fn mix_columns_test() {
    let mut test_array = Array2::from_shape_vec(
        (4, 4).f(),
        vec![
            0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
            0xc6, 0xc6,
        ],
    )
    .unwrap();
    mix_columns(&mut test_array);
    let result = Array2::from_shape_vec(
        (4, 4).f(),
        vec![
            0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
            0xc6, 0xc6,
        ],
    )
    .unwrap();
    assert_eq!(test_array, result);
}

#[test]
fn encryption_decryption_test() {
    let mut test_vector: AESState =
        words_to_state(&[0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff]);
    let resulting_vec = test_vector.clone();
    let key = &[0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
    encryption(&mut test_vector, key, &AESKeySize::Key128);
    decryption(&mut test_vector, key, &AESKeySize::Key128);
    // let resulting_vec = words_to_state(&[0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a]);
    assert_eq!(test_vector, resulting_vec);
}

#[test]
fn padding_test() {
    let message: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let padded_message = pad_ANSIX923_message(&message);
    assert_eq!(
        padded_message,
        vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 8
        ]
    );
    let depadded_message = unpad_ANSIX923_message(&padded_message);
    assert_eq!(message.to_vec(), depadded_message);
}

#[test]
fn PKCS5_padding_test() {
    let message: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let padded_message: [u8; 10] = pad_PKCS5(&message);
    assert_eq!(
        padded_message,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x02, 0x02]
    );
    let depadded_message: Vec<u8> = unpad_PKCS5(padded_message).expect("could not be depadded");
    assert_eq!(depadded_message, message)
}

#[test]
fn ecb_encryption_decryption_test() {
    let message = b"Yass queen SLAYYYYYY";
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let encrypted_should_message = vec![
        0x59, 0xab, 0xbb, 0x97, 0xca, 0xf7, 0x2b, 0x2f, 0x12, 0xda, 0x61, 0xc2, 0xbe, 0x9f, 0xe2,
        0xc2, 0x8a, 0x93, 0xfc, 0x60, 0x78, 0x7c, 0x56, 0x5d, 0x72, 0xf6, 0x36, 0x34, 0x14, 0x04,
        0x81, 0xb8,
    ];
    let encrypted_message = AES::ecb_encrypt(&key, message);
    assert_eq!(
        encrypted_message
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<u8>>(),
        encrypted_should_message
    );
    let decrypted_message = AES::ecb_decrypt(&key, &encrypted_message);
    assert_eq!(decrypted_message, message.to_vec());
}

#[test]
fn cbc_encrypt_decrypt_test() {
    let message = b"Yass queen SLAYYYYYY";
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let encypted_should_message: Vec<u8> = vec![
        0x59, 0xab, 0xbb, 0x97, 0xca, 0xf7, 0x2b, 0x2f, 0x12, 0xda, 0x61, 0xc2, 0xbe, 0x9f, 0xe2,
        0xc2, 0x7e, 0x7c, 0x36, 0x32, 0x53, 0x01, 0x04, 0x13, 0x4f, 0xa2, 0x9b, 0x2d, 0xc9, 0x44,
        0x14, 0x58,
    ];
    let encrypted_message = AES::cbc_encrypt(&key, message, [0x00; 16]);
    assert_eq!(
        encrypted_message
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        encypted_should_message
    );
    let decrypted_message = AES::cbc_decrypt(&key, &encrypted_message, [0x00; 16]);
    assert_eq!(decrypted_message, message.to_vec());
}
