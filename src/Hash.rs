pub mod SHA;

pub mod Keccak {

    pub fn keccak<const OUTPUT_LEN: usize>(input: &[u8], rate: usize) -> [u8; OUTPUT_LEN] {
        sponge::<_, _, OUTPUT_LEN>(keccak_f_1600, padding_sha3, rate, input)
    }

    const ROTATION_OFFSETS: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];
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
                .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
                .collect();
            array_block = Array2::from_shape_vec((5, 5), block).unwrap();
            azip!((a in &mut array_block, &b in &S) *a ^= b); // zip them with the xor :D
            S = perm_fun(&array_block);
        }
        // Squeeze phase
        if rate >= OUTPUT_LEN {
            let hash: [u8; OUTPUT_LEN] = S
                .iter() //lets hope this does like 0,0 -> 1,0 -> 2,0 ..
                .flat_map(|i| i.to_be_bytes())
                .take(OUTPUT_LEN)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            return hash;
        };

        let mut output: Vec<u8> = Vec::new();
        S.iter()
            .flat_map(|i| i.to_be_bytes())
            .take(OUTPUT_LEN)
            .collect_into(&mut output);

        while output.len() < OUTPUT_LEN {
            S.iter()
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

    fn keccak_f_1600(state: &Array2<u64>) -> Array2<u64> {
        let mut state = state.clone();
        for i in ROUND_CONSTANTS.iter() {
            state = round_1600(&state, *i);
        }
        state
    }

    fn round_1600(state: &Array2<u64>, round_constant: u64) -> Array2<u64> {
        let mut state: Array2<u64> = state.clone();
        //Theta phase
        let C: Vec<u64> = (0..5)
            .map(|x| {
                state.index(Ix2(x, 0))
                    ^ state.index(Ix2(x, 1))
                    ^ state.index(Ix2(x, 3))
                    ^ state.index(Ix2(x, 4))
            })
            .collect();

        let D: Vec<u64> = (0..5)
            .map(|x| C[(x + 4) % 5] ^ (C[(x + 1) % 5]).rotate_left(1))
            .collect();

        for ((x, _), A) in state.indexed_iter_mut() {
            *A ^= D[x];
        }

        // rho and pi phases
        let mut B: Array2<u64> = Array2::zeros((5, 5));
        for ((x, y), &A) in state.indexed_iter() {
            *B.index_mut(Ix2(y, (2 * x + 3 * y) % 5)) = A.rotate_left(ROTATION_OFFSETS[x][y]);
        }

        // xi phase
        for ((x, y), A) in state.indexed_iter_mut() {
            *A = B.index(Ix2(x, y)) ^ (!B.index(Ix2((x + 1) % 5, y)) & B.index(Ix2((x + 2) % 5, y)))
        }

        //iota phase
        *state.index_mut(Ix2(0, 0)) ^= round_constant;

        state
    }

    fn padding_sha3(input: &[u8], rate: usize) -> Vec<u8> {
        let modulo = input.len() % rate;
        let first_pad_byte: u8 = 0b01100000;
        let padding_bytes: Vec<u8> = match modulo {
            0 => [
                [first_pad_byte].as_slice(),
                [0x00].repeat(rate - 2).as_slice(),
                [1u8].as_slice(),
            ]
            .concat(),
            x if x == rate - 1 => vec![first_pad_byte & 1],
            x if x == rate - 2 => vec![first_pad_byte, 1],
            x => [
                [first_pad_byte].as_slice(),
                [0x00].repeat(rate - x - 2).as_slice(),
                [1u8].as_slice(),
            ]
            .concat(),
        };
        [input, padding_bytes.as_slice()].concat()
    }
}
