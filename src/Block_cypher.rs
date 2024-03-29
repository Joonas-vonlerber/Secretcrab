use std::ops::BitXor;

use crate::Integrity::Sponge::zip_with;
use std::iter::successors;

pub trait BlockCypher<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize> {
    fn encrypt_block(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text_block: &[u8; BLOCK_SIZE_BYTES],
    ) -> [u8; BLOCK_SIZE_BYTES];
    fn decrypt_block(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text_block: &[u8; BLOCK_SIZE_BYTES],
    ) -> [u8; BLOCK_SIZE_BYTES];
}

pub trait Padding<const BLOCK_SIZE_BYTES: usize> {
    fn pad(data: &[u8]) -> impl Iterator<Item = [u8; BLOCK_SIZE_BYTES]>;
    fn unpad(data: &[[u8; BLOCK_SIZE_BYTES]]) -> Vec<u8>;
}

fn bytes_needed_to_fit(data_len: usize, block_size: usize) -> usize {
    block_size - (data_len % block_size)
}
pub trait Counter<const BLOCK_SIZE_BYTES: usize> {
    type Counter;
    fn init_counter(init_value: [u8; BLOCK_SIZE_BYTES]) -> Self::Counter;
    fn increment(counter: &Self::Counter) -> Self::Counter;
    fn to_block(counter: &Self::Counter) -> [u8; BLOCK_SIZE_BYTES];
    fn generate_stream(
        init_value: [u8; BLOCK_SIZE_BYTES],
    ) -> impl Iterator<Item = [u8; BLOCK_SIZE_BYTES]> {
        successors(
            Some(Self::init_counter(init_value)),
            |last: &Self::Counter| Some(Self::increment(last)),
        )
        .map(|x: Self::Counter| Self::to_block(&x))
    }
}

pub trait ECB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn ecb_encrypt(key: &[u8; KEY_SIZE_BYTES], plain_text: &[u8]) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let mut cypher_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            (plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES))
                .div_ceil(BLOCK_SIZE_BYTES),
        );
        cypher_text.extend(Self::pad(plain_text).map(|block| Self::encrypt_block(key, &block)));
        cypher_text
    }
    fn ecb_decrypt(key: &[u8; KEY_SIZE_BYTES], cypher_text: &[[u8; BLOCK_SIZE_BYTES]]) -> Vec<u8> {
        let mut plain_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(cypher_text.len());
        plain_text.extend(
            cypher_text
                .iter()
                .map(|block| Self::decrypt_block(key, block)),
        );
        Self::unpad(&plain_text)
    }
}

impl<T, const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
    ECB<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> for T
where
    T: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
}

pub trait CBC<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn cbc_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let padded_text = Self::pad(plain_text);
        let mut cypher_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            (plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES))
                .div_ceil(BLOCK_SIZE_BYTES),
        );
        let mut iv: [u8; BLOCK_SIZE_BYTES] = iv;
        let mut cypher_block: [u8; BLOCK_SIZE_BYTES];
        for block in padded_text {
            cypher_block = Self::encrypt_block(key, &zip_with(block, iv, BitXor::bitxor));
            cypher_text.push(cypher_block);
            iv = cypher_block;
        }
        cypher_text
    }
    fn cbc_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text: &[[u8; BLOCK_SIZE_BYTES]],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut plain_text: Vec<[u8; BLOCK_SIZE_BYTES]> =
            Vec::with_capacity(cypher_text.len() * BLOCK_SIZE_BYTES);
        let with_iv = [&[iv], cypher_text].concat();
        let iterator = with_iv.windows(2).map(|blocks| {
            zip_with(
                Self::decrypt_block(key, &blocks[1]),
                blocks[0],
                BitXor::bitxor,
            )
        });
        plain_text.extend(iterator);
        Self::unpad(&plain_text)
    }
}

impl<T, const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
    CBC<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> for T
where
    T: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
}

pub trait PCBC<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn pcbc_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let padded_text = Self::pad(plain_text);
        let mut cypher_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            (plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES))
                .div_ceil(BLOCK_SIZE_BYTES),
        );
        let mut iv = iv;
        let mut cypher_block: [u8; BLOCK_SIZE_BYTES];
        for block in padded_text {
            cypher_block = Self::encrypt_block(key, &zip_with(block, iv, BitXor::bitxor));
            iv = zip_with(cypher_block, block, BitXor::bitxor);
            cypher_text.push(cypher_block);
        }
        cypher_text
    }
    fn pcbc_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text: &[[u8; BLOCK_SIZE_BYTES]],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut plain_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(cypher_text.len());
        let mut iv = iv;
        let mut plain_block: [u8; BLOCK_SIZE_BYTES];
        for block in cypher_text {
            plain_block = zip_with(Self::decrypt_block(key, block), iv, BitXor::bitxor);
            iv = zip_with(plain_block, *block, BitXor::bitxor);
            plain_text.push(plain_block);
        }
        Self::unpad(&plain_text)
    }
}

impl<T, const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
    PCBC<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> for T
where
    T: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
}

pub trait CFB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES>,
{
    fn cfb_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut cypher_text: Vec<u8> = Vec::with_capacity(plain_text.len());
        let block_iterator = plain_text.array_chunks::<BLOCK_SIZE_BYTES>();
        let remainder = block_iterator.remainder();
        let mut key_block: [u8; BLOCK_SIZE_BYTES] = iv;
        let mut cypher_block: [u8; BLOCK_SIZE_BYTES] = [0x00; BLOCK_SIZE_BYTES];
        cypher_text.extend(block_iterator.flat_map(|block| {
            cypher_block = zip_with(Self::encrypt_block(key, &key_block), *block, BitXor::bitxor);
            key_block = cypher_block;
            cypher_block
        }));
        cypher_text.extend(
            remainder
                .iter()
                .zip(Self::encrypt_block(key, &key_block))
                .map(|(a, b)| a ^ b),
        );
        cypher_text
    }
    fn cfb_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut plain_text: Vec<u8> = Vec::with_capacity(cypher_text.len());
        let block_iterator = cypher_text.array_chunks::<BLOCK_SIZE_BYTES>();
        let remainder = block_iterator.remainder();
        plain_text.extend(
            std::iter::once(&iv)
                .chain(block_iterator.clone())
                .map_windows(|[prev, &curr]| {
                    zip_with(Self::encrypt_block(key, prev), curr, BitXor::bitxor)
                })
                .flatten(),
        );
        if let Some(last) = block_iterator.last() {
            plain_text.extend(
                Self::encrypt_block(key, last)
                    .into_iter()
                    .zip(remainder.iter())
                    .map(|(a, b)| a ^ b),
            );
        }
        plain_text
    }
}

impl<T, const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
    CFB<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> for T
where
    T: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES>,
{
}

pub trait OFB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES>,
{
    fn ofb_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut cypher_text: Vec<u8> = Vec::with_capacity(plain_text.len());
        let crypted_iv = Self::encrypt_block(key, &iv);
        let key_stream = successors(Some(crypted_iv), |a| Some(Self::encrypt_block(key, a)));
        let chunks = plain_text.chunks(BLOCK_SIZE_BYTES);
        cypher_text.extend(key_stream.zip(chunks).flat_map(|(key_stream, block)| {
            key_stream.into_iter().zip(block.iter()).map(|(a, b)| a ^ b)
        }));
        cypher_text
    }
    /// OFB encryption and decryption are the same thing
    fn ofb_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        Self::ofb_encrypt(key, cypher_text, iv)
    }
}

impl<T, const B: usize, const K: usize> OFB<B, K> for T where T: BlockCypher<B, K> {}

pub trait CTR<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Counter<BLOCK_SIZE_BYTES>,
{
    fn ctr_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        IV: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut cypher_text: Vec<u8> = Vec::with_capacity(plain_text.len());

        let key_stream = Self::generate_stream(IV).flat_map(|x| Self::encrypt_block(key, &x));

        #[allow(clippy::useless_conversion)]
        let combination = plain_text
            .iter()
            .zip(key_stream.into_iter())
            .map(|(a, b)| a ^ b);

        cypher_text.extend(combination);
        cypher_text
    }
    // Hmm is decrypt the same as encrypt?
    fn ctr_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text: &[u8],
        IV: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        Self::ctr_encrypt(key, cypher_text, IV)
    }
}

impl<const B: usize, const K: usize, T> CTR<B, K> for T where T: BlockCypher<B, K> + Counter<B> {}

const fn gf128_poly_add(a: u128, b: u128) -> u128 {
    a ^ b
}

const fn gf128_poly_mul(a: u128, b: u128, modulo: u128) -> u128 {
    let mut acc: i32 = 0;
    let mut X: u128 = a;
    let mut Y: u128 = b;
    let mut p: u128 = 0;
    let mut carry: bool;
    while acc < 128 {
        if Y & 1 == 1 {
            p ^= X;
        }
        Y >>= 1;
        carry = X >> 127 == 1;
        X <<= 1;
        if carry {
            X ^= p
        }
        acc = acc.saturating_add(1i32);
    }
    p
}

const GCM_MODULO: u128 = 0x87;
