pub mod Keccak;

pub(crate) fn sponge<F1, F2, const OUTPUT_LEN: usize, const STATE_SIZE: usize>(
    perm_fun: F1,
    pad_fun: F2,
    rate: usize,
    input: &[u8],
) -> [u8; OUTPUT_LEN]
where
    F1: Fn(&mut [u8; STATE_SIZE]),
    F2: Fn(&[u8], usize) -> Vec<u8>,
{
    let padded_message: Vec<u8> = pad_fun(input, rate);
    assert_eq!(padded_message.len() % rate, 0);

    let zero_block: Vec<u8> = [0x00].repeat(STATE_SIZE - rate);
    let mut state: [u8; STATE_SIZE] = [0x00; STATE_SIZE];

    // Absorbion phase
    for P in padded_message.chunks(rate) {
        let block: [u8; STATE_SIZE] = [P, &zero_block]
            .concat()
            .try_into()
            .expect("Padding function did not pad correctly");
        state = state.zip(block).map(|(x, y)| x ^ y);
        perm_fun(&mut state);
    }
    // Squeeze phase
    if rate >= OUTPUT_LEN {
        return state[0..OUTPUT_LEN].try_into().unwrap();
    };

    let mut output: Vec<u8> = Vec::new();
    output.extend(&state[0..rate]);

    while output.len() < OUTPUT_LEN {
        perm_fun(&mut state);
        output.extend(&state[0..rate])
    }
    output[0..OUTPUT_LEN].try_into().unwrap()
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
        let block = [padded, [0x00].repeat(STATE_SIZE - self.rate)].concat();
        // Zip it with the state
        self.state = self
            .state
            .zip(
                block
                    .try_into()
                    .expect("Padding function did not pad correctly"),
            )
            .map(|(x, y)| x ^ y);
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

// fn xor_array<const N: usize>(array1: [u8; N], array2: [u8; N]) -> [u8; N] {
//     array1.zip(array2).map(|(a, b)| a ^ b)
// }

// fn concat_with(slice: &[u8], byte: u8) -> Vec<u8> {
//     [slice, &[byte][..]].concat()
// }
