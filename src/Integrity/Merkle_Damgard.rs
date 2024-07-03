
pub(crate) fn merkle_damgard<STATE, C, P, F, const N: usize, const BLOCK_SIZE_BYTES: usize>(
    pad: P,
    compression: C,
    finalize: F,
    IV: STATE,
    input: &[u8],
) -> [u8; N]
where
    C: Fn(&mut STATE, [u8; BLOCK_SIZE_BYTES]),
    P: Fn(&[u8]) -> Box<dyn Iterator<Item = [u8; BLOCK_SIZE_BYTES]> + '_>,
    F: Fn(STATE) -> [u8; N],
{
    let padded = pad(input);
    let mut state = IV;
    for block in padded {
        compression(&mut state, block);
    }
    finalize(state)
}
