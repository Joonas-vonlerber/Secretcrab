use std::ops::BitXor;

use num_traits::ops::mul_add;

use crate::Integrity::Sponge::zip_with;

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

pub trait ECB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn ecb_encrypt(key: &[u8; KEY_SIZE_BYTES], plain_text: &[u8]) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let mut cypher_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES),
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
            plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES),
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