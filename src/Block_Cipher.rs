use std::{iter::once, ops::BitXor};

use crate::{zip_with, Authenticity::AuthenticationError};
use std::iter::successors;

pub trait BlockCipher<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize> {
    fn encrypt_block(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text_block: &[u8; BLOCK_SIZE_BYTES],
    ) -> [u8; BLOCK_SIZE_BYTES];
    fn decrypt_block(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext_block: &[u8; BLOCK_SIZE_BYTES],
    ) -> [u8; BLOCK_SIZE_BYTES];
}

pub trait Padding<const BLOCK_SIZE_BYTES: usize> {
    fn pad(data: &[u8]) -> impl Iterator<Item = [u8; BLOCK_SIZE_BYTES]>;
    fn unpad(data: &[[u8; BLOCK_SIZE_BYTES]]) -> Vec<u8>;
}

fn bytes_needed_to_fit(data_len: usize, block_size: usize) -> usize {
    block_size - (data_len % block_size)
}
fn fill_with_zeros<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    let need_to_fill = bytes_needed_to_fit(data.len(), N);
    if data.is_empty() {
        None
    } else {
        Some(
            [data, &[0x00].repeat(need_to_fill)]
                .concat()
                .try_into()
                .unwrap(),
        )
    }
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
    Self: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn ecb_encrypt(key: &[u8; KEY_SIZE_BYTES], plain_text: &[u8]) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let mut ciphertext: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            (plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES))
                .div_ceil(BLOCK_SIZE_BYTES),
        );
        ciphertext.extend(Self::pad(plain_text).map(|block| Self::encrypt_block(key, &block)));
        ciphertext
    }
    fn ecb_decrypt(key: &[u8; KEY_SIZE_BYTES], ciphertext: &[[u8; BLOCK_SIZE_BYTES]]) -> Vec<u8> {
        let mut plain_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(ciphertext.len());
        plain_text.extend(
            ciphertext
                .iter()
                .map(|block| Self::decrypt_block(key, block)),
        );
        Self::unpad(&plain_text)
    }
}

impl<T, const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
    ECB<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> for T
where
    T: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
}

pub trait CBC<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn cbc_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let padded_text = Self::pad(plain_text);
        let mut ciphertext: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            (plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES))
                .div_ceil(BLOCK_SIZE_BYTES),
        );
        let mut iv: [u8; BLOCK_SIZE_BYTES] = iv;
        let mut cipher_block: [u8; BLOCK_SIZE_BYTES];
        for block in padded_text {
            cipher_block = Self::encrypt_block(key, &zip_with(block, iv, BitXor::bitxor));
            ciphertext.push(cipher_block);
            iv = cipher_block;
        }
        ciphertext
    }
    fn cbc_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext: &[[u8; BLOCK_SIZE_BYTES]],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut plain_text: Vec<[u8; BLOCK_SIZE_BYTES]> =
            Vec::with_capacity(ciphertext.len() * BLOCK_SIZE_BYTES);
        let with_iv = [&[iv], ciphertext].concat();
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
    T: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
}

pub trait PCBC<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn pcbc_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let padded_text = Self::pad(plain_text);
        let mut ciphertext: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(
            (plain_text.len() + bytes_needed_to_fit(plain_text.len(), BLOCK_SIZE_BYTES))
                .div_ceil(BLOCK_SIZE_BYTES),
        );
        let mut iv = iv;
        let mut cipher_block: [u8; BLOCK_SIZE_BYTES];
        for block in padded_text {
            cipher_block = Self::encrypt_block(key, &zip_with(block, iv, BitXor::bitxor));
            iv = zip_with(cipher_block, block, BitXor::bitxor);
            ciphertext.push(cipher_block);
        }
        ciphertext
    }
    fn pcbc_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext: &[[u8; BLOCK_SIZE_BYTES]],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut plain_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(ciphertext.len());
        let mut iv = iv;
        let mut plain_block: [u8; BLOCK_SIZE_BYTES];
        for block in ciphertext {
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
    T: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
}

pub trait CFB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES>,
{
    fn cfb_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::with_capacity(plain_text.len());
        let block_iterator = plain_text.chunks_exact(BLOCK_SIZE_BYTES);
        let remainder = block_iterator.remainder();
        let mut key_block: [u8; BLOCK_SIZE_BYTES] = iv;
        let mut cipher_block: [u8; BLOCK_SIZE_BYTES] = [0x00; BLOCK_SIZE_BYTES];
        ciphertext.extend(block_iterator.flat_map(|block| {
            cipher_block = zip_with(
                Self::encrypt_block(key, &key_block),
                block.try_into().expect("chunks_exact"),
                BitXor::bitxor,
            );
            key_block = cipher_block;
            cipher_block
        }));
        ciphertext.extend(
            remainder
                .iter()
                .zip(Self::encrypt_block(key, &key_block))
                .map(|(a, b)| a ^ b),
        );
        ciphertext
    }

    fn cfb_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut plain_text: Vec<u8> = Vec::with_capacity(ciphertext.len());
        let block_iterator = ciphertext.chunks_exact(BLOCK_SIZE_BYTES);
        let remainder = block_iterator.remainder();
        let mut prev: [u8; BLOCK_SIZE_BYTES] = iv;
        plain_text.extend(block_iterator.clone().flat_map(|x| {
            let block: [u8; BLOCK_SIZE_BYTES] = x.try_into().expect("Exact chunks");
            let prev_temp = prev;
            prev = block;
            zip_with(Self::encrypt_block(key, &prev_temp), block, BitXor::bitxor)
        }));
        if let Some(last) = block_iterator.last() {
            plain_text.extend(
                Self::encrypt_block(key, last.try_into().expect("Exact chunks"))
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
    T: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES>,
{
}

pub trait OFB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES>,
{
    fn ofb_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::with_capacity(plain_text.len());
        let crypted_iv = Self::encrypt_block(key, &iv);
        let key_stream = successors(Some(crypted_iv), |a| Some(Self::encrypt_block(key, a)));
        let chunks = plain_text.chunks(BLOCK_SIZE_BYTES);
        ciphertext.extend(key_stream.zip(chunks).flat_map(|(key_stream, block)| {
            key_stream.into_iter().zip(block.iter()).map(|(a, b)| a ^ b)
        }));
        ciphertext
    }
    /// OFB encryption and decryption are the same thing
    fn ofb_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        Self::ofb_encrypt(key, ciphertext, iv)
    }
}

impl<T, const B: usize, const K: usize> OFB<B, K> for T where T: BlockCipher<B, K> {}

pub trait CTR<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCipher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Counter<BLOCK_SIZE_BYTES>,
{
    fn ctr_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        IV: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::with_capacity(plain_text.len());

        let key_stream = Self::generate_stream(IV).flat_map(|x| Self::encrypt_block(key, &x));

        #[allow(clippy::useless_conversion)]
        let combination = plain_text
            .iter()
            .zip(key_stream.into_iter())
            .map(|(a, b)| a ^ b);

        ciphertext.extend(combination);
        ciphertext
    }
    fn ctr_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext: &[u8],
        IV: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        Self::ctr_encrypt(key, ciphertext, IV)
    }
}

impl<const B: usize, const K: usize, T> CTR<B, K> for T where T: BlockCipher<B, K> + Counter<B> {}

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

pub(crate) fn ghash(h: u128, A: &[u8], C: &[u8]) -> [u8; 16] {
    let auth_chunks = A.chunks_exact(16);
    let auth_remainder = fill_with_zeros::<16>(auth_chunks.remainder());
    let cipher_chunks = C.chunks_exact(16);
    let cipher_remainder = fill_with_zeros::<16>(cipher_chunks.remainder());
    let len_concat: u128 = (((A.len() * 8) as u128) << 64) ^ ((C.len() * 8) as u128);
    dbg!(&cipher_chunks);
    // fucken chain them :DD
    auth_chunks
        .map(|x| x.try_into().expect("chunks exact"))
        .chain(once(&auth_remainder).flatten())
        .chain(cipher_chunks.map(|x| x.try_into().expect("Chunks excact")))
        .chain(once(&cipher_remainder).flatten())
        .map(|block| u128::from_be_bytes(*block))
        .chain(once(&len_concat).copied())
        .fold(0u128, |acc, x| gf128_poly_mul(acc ^ x, h, GCM_MODULO))
        .to_be_bytes()
}

pub trait GCM128<const KEY_SIZE_BYTES: usize>
where
    Self: CTR<16, KEY_SIZE_BYTES>,
{
    fn gcm_encrypt<const TAG_SIZE_BYTES: usize>(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: &[u8],
        auth_data: &[u8],
    ) -> (Vec<u8>, [u8; TAG_SIZE_BYTES]) {
        assert!(TAG_SIZE_BYTES <= 16);
        let h = Self::encrypt_block(key, &[0x0; 16]);
        let iv: [u8; 16] = if iv.len() == 12 {
            [iv, &[0x00, 0x00, 0x00, 0x01]]
                .concat()
                .try_into()
                .expect("IV was wrong length")
        } else {
            ghash(u128::from_be_bytes(h), &[], iv)
        };
        let ciphertext = Self::ctr_encrypt(key, plain_text, iv);
        let tag: [u8; TAG_SIZE_BYTES] = zip_with(
            ghash(u128::from_be_bytes(h), auth_data, &ciphertext),
            Self::encrypt_block(key, &iv),
            BitXor::bitxor,
        )[0..TAG_SIZE_BYTES]
            .try_into()
            .unwrap();

        (ciphertext, tag)
    }
    fn gcm_decrypt<const TAG_SIZE_BYTES: usize>(
        key: &[u8; KEY_SIZE_BYTES],
        ciphertext: &[u8],
        iv: &[u8],
        tag: [u8; TAG_SIZE_BYTES],
        auth_data: &[u8],
    ) -> Result<Vec<u8>, AuthenticationError> {
        assert!(TAG_SIZE_BYTES <= 16);
        let h = Self::encrypt_block(key, &[0x0; 16]);
        let iv: [u8; 16] = if iv.len() == 12 {
            [iv, &[0x00, 0x00, 0x00, 0x80]]
                .concat()
                .try_into()
                .expect("IV was wrong length")
        } else {
            ghash(u128::from_be_bytes(h), &[], iv)
        };
        let plain_text = Self::ctr_decrypt(key, ciphertext, iv);
        let generated_tag: [u8; TAG_SIZE_BYTES] = zip_with(
            ghash(u128::from_be_bytes(h), auth_data, ciphertext),
            Self::encrypt_block(key, &iv),
            BitXor::bitxor,
        )[0..TAG_SIZE_BYTES]
            .try_into()
            .unwrap();

        if tag != generated_tag {
            Err(AuthenticationError::SignatureNotMatchMessage)
        } else {
            Ok(plain_text)
        }
    }
}

impl<T, const KEY_SIZE_BYTES: usize> GCM128<KEY_SIZE_BYTES> for T where T: CTR<16, KEY_SIZE_BYTES> {}
