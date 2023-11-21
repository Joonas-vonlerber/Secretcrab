pub mod Keccak;

pub(crate) fn sponge<F1, F2, const OUTPUT_LEN: usize, const STATE_SIZE: usize>(
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

    let zero_block: Vec<u8> = [0x00].repeat(STATE_SIZE - rate);
    let mut state: Vec<u8> = [0x00; STATE_SIZE].to_vec();
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
