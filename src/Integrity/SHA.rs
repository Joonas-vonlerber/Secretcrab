pub mod SHA1;
pub mod SHA2;
pub mod SHA3;
#[cfg(test)]
mod tests;

use std::iter::once;

fn sha_padding<const BLOCK_SIZE_BYTES: usize>(
    input: &[u8],
) -> Box<dyn Iterator<Item = [u8; BLOCK_SIZE_BYTES]> + '_> {
    let lenght = input.len();
    let u128_length: [u8; 16] = u128::try_from(lenght * 8).unwrap().to_be_bytes();
    let u64_length: [u8; 8] = u64::try_from(lenght * 8).unwrap().to_be_bytes();
    let length_bytes = match BLOCK_SIZE_BYTES {
        64 => u64_length.as_slice(),
        128 => u128_length.as_slice(),
        _ => unreachable!(),
    };
    let size_of_len_bytes = match BLOCK_SIZE_BYTES {
        64 => std::mem::size_of::<u64>(),
        128 => std::mem::size_of::<u128>(),
        _ => unreachable!(),
    };
    let padding_needed = match lenght % BLOCK_SIZE_BYTES {
        x if x > BLOCK_SIZE_BYTES - size_of_len_bytes - 1 => {
            2 * BLOCK_SIZE_BYTES - x - size_of_len_bytes - 1
        }
        x => BLOCK_SIZE_BYTES - size_of_len_bytes - x - 1,
    };
    let iterator = input.chunks_exact(BLOCK_SIZE_BYTES);
    let last_chunk = iterator.remainder();
    let padding_bits = [0x00u8].repeat(padding_needed);
    let pad_chunk: [u8; BLOCK_SIZE_BYTES] =
        [last_chunk, &[0x80u8][..], &padding_bits[..], length_bytes]
            .concat()
            .try_into()
            .expect("By math :DD");
    Box::new(
        iterator
            .map(|chunk| chunk.try_into().expect("chunk size in BLOCK_SIZE_BYTES"))
            .chain(once(pad_chunk)),
    )
}

fn sha_finalize_32<const N: usize, const T: usize>(state: [u32; N]) -> [u8; T] {
    assert!(N * 32 >= 8 * T);
    state
        .into_iter()
        .flat_map(|x| x.to_be_bytes())
        .take(T)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("take T u8")
}

fn sha_finalize_64<const N: usize, const T: usize>(state: [u64; N]) -> [u8; T] {
    assert!(N * 64 >= 8 * T);
    state
        .into_iter()
        .flat_map(|x| x.to_be_bytes())
        .take(T)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("take T u8")
}
