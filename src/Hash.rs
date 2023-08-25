pub mod SHA;

pub mod Keccak {

    pub fn keccak<const OUTPUT_LEN: usize>(input: &[u8], rate: usize) -> [u8; OUTPUT_LEN] {
        sponge::<_, _, OUTPUT_LEN>(keccak_f_1600, padding_sha3, rate, input)
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
    ) -> [u8; OUTPUT_LEN]
    where
        F1: Fn(&Array2<u64>) -> Array2<u64>,
        F2: Fn(&[u8], usize) -> Vec<u8>,
    {
        let padded_message: Vec<u8> = pad_fun(input, rate);
        assert_eq!(padded_message.len() % rate, 0);

        let mut block: Vec<u64>;
        let mut array_block: Array2<u64>;
        let zero_block: Vec<u8> = [0x00].repeat(200 - rate);

        let mut S: Array2<u64> = Array2::zeros((5, 5));

        // Absorbion phase
        for P in padded_message.chunks(rate) {
            block = [P, zero_block.as_slice()]
                .concat()
                .chunks(8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                .collect();
            array_block = Array2::from_shape_vec((5, 5).f(), block).unwrap();
            azip!((a in &mut array_block, &b in &S) *a ^= b); // zip them with the xor :D
            S = perm_fun(&array_block);
        }
        // Squeeze phase
        if rate >= OUTPUT_LEN {
            let hash: [u8; OUTPUT_LEN] = S
                .into_raw_vec()
                .iter() //lets hope this does like 0,0 -> 1,0 -> 2,0 ..
                .flat_map(|i| i.to_be_bytes())
                .take(OUTPUT_LEN)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            return hash;
        };

        let mut output: Vec<u8> = Vec::new();
        S.clone()
            .into_raw_vec()
            .iter()
            .flat_map(|i| i.to_be_bytes())
            .take(OUTPUT_LEN)
            .collect_into(&mut output);

        while output.len() < OUTPUT_LEN {
            S.clone()
                .into_raw_vec()
                .iter()
                .flat_map(|i| i.to_be_bytes())
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

    pub fn keccak_f_1600(state: &Array2<u64>) -> Array2<u64> {
        let mut state = state.clone();
        for i in ROUND_CONSTANTS.iter() {
            // println!("{}\n\n\n", state);
            state = round_1600(&state, *i);
        }
        state
    }

    pub fn round_1600(state: &Array2<u64>, round_constant: u64) -> Array2<u64> {
        let mut state: Array2<u64> = state.clone();

        theta_step(&mut state);
        rho_step(&mut state);
        let aux_state = pi_step(&state);
        // println!("{}\n\n\n", aux_state);
        xi_step(&mut state, &aux_state);
        iota_step(&mut state, round_constant);

        state
    }

    pub fn theta_step(state: &mut Array2<u64>) {
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

    pub fn rho_step(state: &mut Array2<u64>) {
        let rotation_offsets: Array2<u32> = Array2::from_shape_vec(
            (5, 5).f(),
            vec![
                0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2,
                61, 56, 14,
            ],
        )
        .unwrap();
        azip!((a in state, &r in &rotation_offsets) *a = a.rotate_left(r));
    }

    pub fn pi_step(state: &Array2<u64>) -> Array2<u64> {
        let mut B: Array2<u64> = Array2::zeros((5, 5));
        for ((x, y), A) in state.indexed_iter() {
            *B.index_mut(Ix2(y, (2 * x + 3 * y) % 5)) = *A;
        }
        B
    }

    pub fn xi_step(state: &mut Array2<u64>, aux_state: &Array2<u64>) {
        for ((x, y), A) in state.indexed_iter_mut() {
            *A = aux_state.index(Ix2(x, y))
                ^ (!(aux_state.index(Ix2((x + 1) % 5, y))) & aux_state.index(Ix2((x + 2) % 5, y)))
        }
    }

    pub fn iota_step(state: &mut Array2<u64>, round_constant: u64) {
        *state.index_mut(Ix2(0, 0)) ^= round_constant;
    }

    fn padding_sha3(input: &[u8], rate: usize) -> Vec<u8> {
        let padding_needed = rate - (input.len() % rate);
        let padding_bytes: Vec<u8> = match padding_needed {
            0 => [
                [0x06u8].as_slice(),
                [0x00].repeat(rate - 2).as_slice(),
                [0x80].as_slice(),
            ]
            .concat(),
            1 => vec![0x86],
            2 => vec![0x06, 0x80],
            x => [
                [0x06].as_slice(),
                [0x00].repeat(x - 2).as_slice(),
                [0x80].as_slice(),
            ]
            .concat(),
        };
        [input, padding_bytes.as_slice()].concat()
    }
}

#[cfg(test)]
mod keccak_tests {
    use crate::Hash::Keccak::*;
    use ndarray::prelude::*;

    #[test]
    fn theta_test() {
        let mut test_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5).f(),
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ],
        )
        .unwrap();
        theta_step(&mut test_array);
        let should_be_resuling_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5).f(),
            vec![
                26, 9, 13, 29, 47, 31, 14, 8, 22, 34, 16, 3, 3, 19, 37, 21, 24, 30, 12, 56, 14, 29,
                25, 9, 51,
            ],
        )
        .unwrap();
        assert_eq!(test_array, should_be_resuling_array);

        let mut snd_test_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5),
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ],
        )
        .unwrap();
        theta_step(&mut snd_test_array);
        let should_be_snd_resulting_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5),
            vec![
                18, 19, 16, 17, 22, 29, 30, 31, 16, 17, 17, 16, 23, 22, 21, 49, 46, 47, 44, 45, 19,
                18, 17, 16, 31,
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
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
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
                1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
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
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ],
        )
        .unwrap();
        let aux_state = pi_step(&test_array);
        let resulting_array = Array2::from_shape_vec(
            (5, 5),
            vec![
                0, 3, 1, 4, 2, 6, 9, 7, 5, 8, 12, 10, 13, 11, 14, 18, 16, 19, 17, 15, 24, 22, 20,
                23, 21,
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
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ],
        )
        .unwrap();
        let aux_state: Array2<u64> = Array2::from_shape_vec(
            (5, 5).f(),
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ],
        )
        .unwrap();

        xi_step(&mut test_array, &aux_state);
        let resulting_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5),
            vec![
                2, 4, 14, 14, 22, 0, 14, 10, 18, 20, 6, 6, 14, 16, 30, 3, 12, 13, 30, 19, 5, 11,
                15, 3, 25,
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
                15332, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24,
            ],
        )
        .unwrap();
        iota_step(&mut test_array, 2147516555);
        let resulting_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5).f(),
            vec![
                2147531631, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                21, 22, 23, 24,
            ],
        )
        .unwrap();
        assert_eq!(test_array, resulting_array);
    }
    #[test]
    fn keccak_f_1600_test() {
        let test_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5).f(),
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24,
            ],
        )
        .unwrap();
        let result_array = keccak_f_1600(&test_array);
        let should_array: Array2<u64> = Array2::from_shape_vec(
            (5, 5),
            vec![
                9472389783892099349,
                11661812091723830419,
                825065683101361807,
                17847697619892908514,
                15330347418010067760,
                2159377575142921216,
                3517755057770134847,
                6192414258352188799,
                11598434253200954839,
                12047099911907354591,
                17826682512249813373,
                5223775837645169598,
                14426505790672879210,
                6049795840392747215,
                4763389569697138851,
                2325963263767348549,
                933274647126506074,
                3326742392640380689,
                8610635351954084385,
                6779624089296570504,
                15086930817298358378,
                3451250694486589320,
                16749975585634164134,
                18234131770974529925,
                15083668107635345971,
            ],
        )
        .unwrap();
        assert_eq!(result_array, should_array);
    }
}
