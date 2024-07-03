use std::ops::BitXor;
use crate::Integrity::Sponge::zip_with;


fn classic_feistel_network_encrypt<const ROUND: usize, KEY, const N: usize, F>(left: [u8; N], right: [u8; N], keys: [KEY; ROUND], perm: F) -> ([u8; N], [u8; N])
where
    F: Fn([u8; N], KEY) -> [u8; N],
{
    let mut left = left;
    let mut right = right;
    for key in keys {
        (left, right) = (right, zip_with(left, perm(right, key), BitXor::bitxor));
    }
    (left, right)
}

fn classic_feistel_network_decrypt<const ROUND: usize, KEY, const N: usize, F>(right: [u8; N], left: [u8; N], keys: [KEY; ROUND], perm: F) -> ([u8; N], [u8; N]) 
where 
    F: Fn([u8; N], KEY) -> [u8; N],
{
    let mut left = left;
    let mut right = right;
    for key in keys.into_iter().rev() {
        (right, left) = (left, zip_with(right, perm(left, key), BitXor::bitxor))
    }
    (left, right)
}

