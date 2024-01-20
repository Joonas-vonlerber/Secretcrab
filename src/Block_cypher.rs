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

pub trait ECB<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn ecb_encrypt(key: &[u8; KEY_SIZE_BYTES], plain_text: &[u8]) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        let mut cypher_text: Vec<[u8; BLOCK_SIZE_BYTES]> = Vec::with_capacity(plain_text.len());
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

trait CBC<const BLOCK_SIZE_BYTES: usize, const KEY_SIZE_BYTES: usize>
where
    Self: BlockCypher<BLOCK_SIZE_BYTES, KEY_SIZE_BYTES> + Padding<BLOCK_SIZE_BYTES>,
{
    fn cbc_encrypt(
        key: &[u8; KEY_SIZE_BYTES],
        plain_text: &[u8],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
        todo!()
    }
    fn cbc_decrypt(
        key: &[u8; KEY_SIZE_BYTES],
        cypher_text: &[[u8; BLOCK_SIZE_BYTES]],
        iv: [u8; BLOCK_SIZE_BYTES],
    ) -> Vec<u8> {
        todo!()
    }
}
