pub fn keccak<const OUTPUT_LEN: usize>(
    input: &[u8],
    rate: usize,
    delimited_suffix: u8,
) -> [u8; OUTPUT_LEN] {
    sponge::<_, _, OUTPUT_LEN>(keccak_f_1600, keccak_padding, rate, input, delimited_suffix)
}

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
use std::ops::{Index, IndexMut};

use ndarray::prelude::*;

// only works for 1600 block size and there is very few reasons to be using anything else :DD
fn sponge<F1, F2, const OUTPUT_LEN: usize>(
    perm_fun: F1,
    pad_fun: F2,
    rate: usize,
    input: &[u8],
    delimited_suffix: u8,
) -> [u8; OUTPUT_LEN]
where
    F1: Fn(&mut Vec<u8>),
    F2: Fn(&[u8], usize, u8) -> Vec<u8>,
{
    let padded_message: Vec<u8> = pad_fun(input, rate, delimited_suffix);
    assert_eq!(padded_message.len() % rate, 0);

    let zero_block: Vec<u8> = [0x00].repeat(200 - rate);
    let mut state: Vec<u8> = [0x00; 200].to_vec();
    // Absorbion phase
    for P in padded_message.chunks(rate) {
        state = state
            .iter()
            .zip([P, zero_block.as_slice()].concat().iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();
        perm_fun(&mut state);
    }
    // Squeeze phase
    if rate >= OUTPUT_LEN {
        let hash: [u8; OUTPUT_LEN] = state
            .into_iter()
            .take(OUTPUT_LEN)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        return hash;
    };

    let mut output: Vec<u8> = Vec::new();
    state
        .clone()
        .into_iter()
        .take(OUTPUT_LEN)
        .collect_into(&mut output);

    while output.len() < OUTPUT_LEN {
        state
            .clone()
            .into_iter()
            .take(OUTPUT_LEN)
            .collect_into(&mut output);
    }
    output
        .into_iter()
        .take(OUTPUT_LEN)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn keccak_f_1600(state: &mut Vec<u8>) {
    let mut array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        state
            .chunks(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for i in ROUND_CONSTANTS.iter() {
        round_1600(&mut array, *i);
    }
    *state = array
        .into_raw_vec()
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
}

fn round_1600(state: &mut Array2<u64>, round_constant: u64) {
    theta_step(state);
    rho_step(state);
    let aux_state = pi_step(state);
    xi_step(state, &aux_state);
    iota_step(state, round_constant);
}

fn theta_step(state: &mut Array2<u64>) {
    let C: Vec<u64> = state
        .rows()
        .into_iter()
        .map(|row| row.fold(0u64, |x, acc| acc ^ x))
        .collect();

    let D: Vec<u64> = (0..5)
        .map(|x| C[(x + 4) % 5] ^ (C[(x + 1) % 5]).rotate_left(1))
        .collect();
    for ((x, _), A) in state.indexed_iter_mut() {
        *A ^= D[x];
    }
}

fn rho_step(state: &mut Array2<u64>) {
    let rotation_offsets: Array2<u32> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61,
            56, 14,
        ],
    )
    .unwrap();
    azip!((a in state, &r in &rotation_offsets) *a = a.rotate_left(r));
}

fn pi_step(state: &Array2<u64>) -> Array2<u64> {
    let mut B: Array2<u64> = Array2::zeros((5, 5));
    for ((x, y), A) in state.indexed_iter() {
        *B.index_mut(Ix2(y, (2 * x + 3 * y) % 5)) = *A;
    }
    B
}

fn xi_step(state: &mut Array2<u64>, aux_state: &Array2<u64>) {
    for ((x, y), A) in state.indexed_iter_mut() {
        *A = aux_state.index(Ix2(x, y))
            ^ (!(aux_state.index(Ix2((x + 1) % 5, y))) & aux_state.index(Ix2((x + 2) % 5, y)))
    }
}

fn iota_step(state: &mut Array2<u64>, round_constant: u64) {
    *state.index_mut(Ix2(0, 0)) ^= round_constant;
}

fn keccak_padding(input: &[u8], rate: usize, delimited_suffix: u8) -> Vec<u8> {
    let padding_needed = rate - (input.len() % rate);
    let padding_bytes: Vec<u8> = match padding_needed {
        0 => [
            [delimited_suffix].as_slice(),
            [0x00].repeat(rate - 2).as_slice(),
            [0x80].as_slice(),
        ]
        .concat(),
        1 => vec![0x86],
        2 => vec![0x06, 0x80],
        x => [
            [delimited_suffix].as_slice(),
            [0x00].repeat(x - 2).as_slice(),
            [0x80].as_slice(),
        ]
        .concat(),
    };
    [input, padding_bytes.as_slice()].concat()
}

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
fn theta_test() {
    let mut test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();
    theta_step(&mut test_array);
    let should_be_resuling_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            26, 9, 13, 29, 47, 31, 14, 8, 22, 34, 16, 3, 3, 19, 37, 21, 24, 30, 12, 56, 14, 29, 25,
            9, 51,
        ],
    )
    .unwrap();
    assert_eq!(test_array, should_be_resuling_array);

    let mut snd_test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5),
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();
    theta_step(&mut snd_test_array);
    let should_be_snd_resulting_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5),
        vec![
            18, 19, 16, 17, 22, 29, 30, 31, 16, 17, 17, 16, 23, 22, 21, 49, 46, 47, 44, 45, 19, 18,
            17, 16, 31,
        ],
    )
    .unwrap();
    assert_eq!(snd_test_array, should_be_snd_resulting_array);
}
#[test]
fn rho_test() {
    let mut test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();
    rho_step(&mut test_array);
    let should_be_resuling_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0,
            2,
            9223372036854775808,
            805306368,
            536870912,
            343597383680,
            105553116266496,
            448,
            288230376151711744,
            9437184,
            80,
            11264,
            105553116266496,
            436207616,
            7696581394432,
            32985348833280,
            562949953421312,
            557056,
            37748736,
            4864,
            5242880,
            84,
            13835058055282163714,
            1657324662872342528,
            393216,
        ],
    )
    .unwrap();
    assert_eq!(test_array, should_be_resuling_array);

    let mut snd_test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5),
        vec![
            1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();
    rho_step(&mut snd_test_array);
    let should_be_snd_resulting_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5),
        vec![
            1,
            68719476736,
            16,
            6597069766656,
            1048576,
            10,
            105553116266496,
            7168,
            281474976710656,
            36,
            9223372036854775810,
            704,
            105553116266496,
            425984,
            13835058055282163713,
            4026531840,
            576460752303423488,
            570425344,
            37748736,
            1369094286720630784,
            2684354560,
            22020096,
            12094627905536,
            5888,
            393216,
        ],
    )
    .unwrap();
    assert_eq!(snd_test_array, should_be_snd_resulting_array);
}
#[test]
fn pi_test() {
    let test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();
    let aux_state = pi_step(&test_array);
    let resulting_array = Array2::from_shape_vec(
        (5, 5),
        vec![
            0, 3, 1, 4, 2, 6, 9, 7, 5, 8, 12, 10, 13, 11, 14, 18, 16, 19, 17, 15, 24, 22, 20, 23,
            21,
        ],
    )
    .unwrap();
    assert_eq!(aux_state, resulting_array);
}

#[test]
fn xi_test() {
    let mut test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();
    let aux_state: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24,
        ],
    )
    .unwrap();

    xi_step(&mut test_array, &aux_state);
    let resulting_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5),
        vec![
            2, 4, 14, 14, 22, 0, 14, 10, 18, 20, 6, 6, 14, 16, 30, 3, 12, 13, 30, 19, 5, 11, 15, 3,
            25,
        ],
    )
    .unwrap();
    assert_eq!(test_array, resulting_array);
}
#[test]
fn iota_test() {
    let mut test_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            15332, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24,
        ],
    )
    .unwrap();
    iota_step(&mut test_array, 2147516555);
    let resulting_array: Array2<u64> = Array2::from_shape_vec(
        (5, 5).f(),
        vec![
            2147531631, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24,
        ],
    )
    .unwrap();
    assert_eq!(test_array, resulting_array);
}
#[test]
fn keccak_f_1600_test() {
    let mut test_array: Vec<u8> = (0..25u64).flat_map(|word| word.to_le_bytes()).collect();
    keccak_f_1600(&mut test_array);
    let should_array: Vec<u8> = vec![
        21, 129, 237, 82, 82, 176, 116, 131, 0, 148, 86, 182, 118, 166, 247, 29, 125, 121, 81, 138,
        75, 25, 101, 247, 69, 5, 118, 209, 67, 123, 71, 32, 106, 96, 246, 243, 164, 139, 95, 209,
        147, 212, 141, 124, 79, 20, 215, 161, 63, 253, 56, 81, 150, 147, 209, 48, 190, 227, 27,
        149, 114, 148, 126, 72, 90, 122, 218, 203, 88, 168, 243, 12, 136, 127, 177, 155, 56, 78,
        229, 47, 143, 38, 159, 13, 222, 56, 115, 11, 127, 109, 37, 139, 245, 223, 239, 85, 106, 62,
        44, 235, 148, 62, 53, 200, 17, 31, 144, 140, 148, 246, 42, 46, 166, 157, 48, 202, 12, 222,
        115, 232, 226, 49, 77, 148, 108, 194, 175, 247, 215, 21, 196, 140, 128, 234, 245, 160, 207,
        216, 62, 126, 67, 49, 245, 83, 33, 210, 164, 67, 59, 31, 127, 119, 133, 233, 153, 180, 60,
        166, 12, 253, 48, 35, 209, 197, 192, 85, 192, 212, 223, 167, 224, 166, 138, 229, 47, 167,
        163, 72, 153, 124, 147, 245, 26, 66, 136, 8, 52, 113, 48, 16, 22, 94, 51, 74, 126, 41, 58,
        244, 83, 209,
    ];
    assert_eq!(should_array.len(), 200);
    assert_eq!(test_array, should_array);
}
