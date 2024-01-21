use std::fmt::Debug;

pub mod Keccak;
mod Photon;

pub(crate) fn zip_with<const N: usize, T, U, V: Debug, F: Fn(T, U) -> V>(
    arr1: [T; N],
    arr2: [U; N],
    f: F,
) -> [V; N] {
    arr1.into_iter()
        .zip(arr2)
        .map(|(a, b)| f(a, b))
        .collect::<Vec<V>>()
        .try_into()
        .unwrap()
}

fn extended_sponge<F1, F2, const OUTPUT_LEN: usize, const STATE_SIZE: usize>(
    perm_fun: F1,
    pad_fun: F2,
    absorb_rate: usize,
    squeeze_rate: usize,
    initialization_state: [u8; STATE_SIZE],
    input: &[u8],
) -> [u8; OUTPUT_LEN]
where
    F1: Fn(&mut [u8; STATE_SIZE]),
    F2: Fn(&[u8], usize) -> Vec<u8>,
{
    let padded_message: Vec<u8> = pad_fun(input, absorb_rate);
    assert_eq!(padded_message.len() % absorb_rate, 0);

    let zero_block: Vec<u8> = [0x00].repeat(STATE_SIZE - absorb_rate);
    let mut state: [u8; STATE_SIZE] = initialization_state;

    // Absorbion phase
    for P in padded_message.chunks(absorb_rate) {
        let block: [u8; STATE_SIZE] = [P, &zero_block]
            .concat()
            .try_into()
            .expect("Padding function did not pad correctly");
        state = zip_with(state, block, |a, b| a ^ b);
        perm_fun(&mut state);
    }

    // Squeeze phase
    if squeeze_rate >= OUTPUT_LEN {
        return state[0..OUTPUT_LEN].try_into().unwrap();
    };

    let mut output: Vec<u8> = Vec::new();
    output.extend(&state[0..squeeze_rate]);

    while output.len() < OUTPUT_LEN {
        perm_fun(&mut state);
        output.extend(&state[0..squeeze_rate])
    }
    output[0..OUTPUT_LEN].try_into().unwrap()
}

fn sponge<F1, F2, const OUTPUT_LEN: usize, const STATE_SIZE: usize>(
    perm_fun: F1,
    pad_fun: F2,
    rate: usize,
    input: &[u8],
) -> [u8; OUTPUT_LEN]
where
    F1: Fn(&mut [u8; STATE_SIZE]),
    F2: Fn(&[u8], usize) -> Vec<u8>,
{
    extended_sponge::<_, _, OUTPUT_LEN, STATE_SIZE>(
        perm_fun,
        pad_fun,
        rate,
        rate,
        [0x00; STATE_SIZE],
        input,
    )
}

struct Duplex<F1, F2, const STATE_SIZE: usize>
where
    F1: Fn(&mut [u8; STATE_SIZE]),
    F2: Fn(&[u8], usize) -> Vec<u8>,
{
    permutation_function: F1,
    padding_function: F2,
    state: [u8; STATE_SIZE],
    rate: usize,
}

impl<F1, F2, const STATE_SIZE: usize> Duplex<F1, F2, STATE_SIZE>
where
    F1: Fn(&mut [u8; STATE_SIZE]),
    F2: Fn(&[u8], usize) -> Vec<u8>,
{
    fn new(perm_fun: F1, pad_fun: F2, rate: usize) -> Duplex<F1, F2, STATE_SIZE> {
        Duplex {
            permutation_function: perm_fun,
            padding_function: pad_fun,
            state: [0x00; STATE_SIZE],
            rate,
        }
    }

    fn duplex<const OUTPUT_LEN: usize>(&mut self, input: &[u8]) -> [u8; OUTPUT_LEN] {
        assert!(OUTPUT_LEN <= self.rate);
        // Pad message and make it into one block
        let padded = (self.padding_function)(input, self.rate);
        let block: [u8; STATE_SIZE] = [padded, [0x00].repeat(STATE_SIZE - self.rate)]
            .concat()
            .try_into()
            .expect("Padding function did not pad correctly");
        // Zip it with the state

        self.state = zip_with(self.state, block, |a, b| a ^ b);
        // Permutate the state
        (self.permutation_function)(&mut self.state);
        // First OUTPUT_LEN bytes
        self.state[0..OUTPUT_LEN].try_into().unwrap()
    }
}

// I should attempt to implement the spongewrap construction

// struct SpongeWrap<F1, F2, const STATE_SIZE: usize, const BLOCK_SIZE: usize>
// where
//     F1: Fn(&mut [u8; STATE_SIZE]),
//     F2: Fn(&[u8], usize) -> Vec<u8>,
// {
//     duplex: Duplex<F1, F2, STATE_SIZE>,
// }

// impl<F1, F2, const STATE_SIZE: usize, const BLOCK_SIZE: usize>
//     SpongeWrap<F1, F2, STATE_SIZE, BLOCK_SIZE>
// where
//     F1: Fn(&mut [u8; STATE_SIZE]),
//     F2: Fn(&[u8], usize) -> Vec<u8>,
// {
//     fn new(perm_fun: F1, pad_fun: F2, rate: usize, key: &[u8]) -> Self {
//         let mut duplex = Duplex::<_, _, STATE_SIZE>::new(perm_fun, pad_fun, rate);

//         // Break the key into blocks and seperate out the last block
//         let (mut key_blocks, key_block_len, last_key_block) = Self::divide_into_blocks(key);

//         // Duplex them in
//         let mut key_block: Vec<u8>;
//         for _ in 0..key_block_len {
//             key_block = concat_with(
//                 key_blocks.next().expect("There was no next key chunk"),
//                 0x01,
//             );
//             duplex.duplex::<0>(&key_block);
//         }
//         key_block = [last_key_block, [0x00].to_vec()].concat();
//         duplex.duplex::<0>(&key_block);

//         SpongeWrap { duplex }
//     }

//     fn wrap<const TAG_LEN: usize>(
//         &mut self,
//         header: &[u8],
//         plain_text: &[u8],
//     ) -> (Vec<u8>, [u8; TAG_LEN]) {
//         // Break the header into blocks
//         let (mut header_blocks, header_block_len, last_header_block) =
//             Self::divide_into_blocks(header);
//         // Break the plain_text into blocks
//         let (plain_text_blocks_not_peek, plain_text_block_len, last_plain_text_block) =
//             Self::divide_into_blocks(plain_text);
//         let mut plain_text_blocks = plain_text_blocks_not_peek.peekable();

//         // Duplex the header in
//         let mut header_block: Vec<u8> = Vec::with_capacity(BLOCK_SIZE + 1);

//         for _ in 0..header_block_len {
//             header_block.clear();
//             header_block.extend(
//                 header_blocks
//                     .next()
//                     .expect("next header block was not available")
//                     .iter()
//                     .chain([0x00].iter()),
//             );
//             self.duplex.duplex::<0>(&header_block);
//         }

//         // Duplex the plain_text in

//         let mut tag: [u8; BLOCK_SIZE] = self
//             .duplex
//             .duplex(&[&last_header_block[..], &[0x01][..]].concat());
//         let mut cypher: [u8; BLOCK_SIZE] = xor_array(
//             **plain_text_blocks
//                 .peek()
//                 .expect("no first plaintext element"),
//             tag,
//         );

//         let mut cypher_text: Vec<u8> = Vec::with_capacity(plain_text.len());
//         cypher_text.extend_from_slice(&cypher);

//         for _ in 0..plain_text_block_len {
//             tag = self.duplex.duplex(&concat_with(
//                 plain_text_blocks
//                     .next()
//                     .expect("no next plane_text block was found"),
//                 0x01,
//             ));
//             // cypher = xor_array(plain_text_blocks.peek().expect(msg), array2) // There is a bug right here, it doesn't account for the last block size, since it might not be exactly BLOCK_SIZE
//             // It is a hard construction to do and implement, might attempt it later
//         }

//         // Make the tag
//         todo!()
//     }

//     fn unwrap<const TAG_LEN: usize>(
//         &mut self,
//         header: &[u8],
//         cypher_text: &[u8],
//         tag: [u8; TAG_LEN],
//     ) -> Option<Vec<u8>> {
//         todo!()
//     }

//     fn divide_into_blocks(input: &[u8]) -> (ArrayChunks<u8, BLOCK_SIZE>, usize, Vec<u8>) {
//         let input_blocks = input.array_chunks::<BLOCK_SIZE>();
//         let (input_len, last_input_block) = match input.len().div_rem(&BLOCK_SIZE) {
//             (n, 0) => (
//                 n.saturating_sub(1),
//                 input_blocks.clone().last().map(|x| &x[..]).unwrap_or(&[]),
//             ),
//             (n, _) => (n, input_blocks.remainder()),
//         };
//         (input_blocks, input_len, last_input_block.to_vec())
//     }
// }

// fn concat_with(slice: &[u8], byte: u8) -> Vec<u8> {
//     [slice, &[byte][..]].concat()
// }
