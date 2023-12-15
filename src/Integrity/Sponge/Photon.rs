use ndarray::{Array1, Array2, ArrayView1, ArrayViewMut1};
use std::{default, fmt::Display, ops::*};

use crate::Confidentiality::AES::sub_byte;
use PhotonConstants::*;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum PhotonCell {
    U4(u8),
    U8(u8),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
struct U4(u8);

impl Display for U4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl U4 {
    const MAX: U4 = U4(15);
    const MIN: U4 = U4(0);

    #[inline]
    const fn new(input: u8) -> Option<U4> {
        if U4::MAX.0 >= input {
            Some(U4(input))
        } else {
            None
        }
    }

    fn to_hex(self) -> String {
        String::from(match self.0 {
            0 => "0x0",
            1 => "0x1",
            2 => "0x2",
            3 => "0x3",
            4 => "0x4",
            5 => "0x5",
            6 => "0x6",
            7 => "0x7",
            8 => "0x8",
            9 => "0x9",
            10 => "0xa",
            11 => "0xb",
            12 => "0xc",
            13 => "0xd",
            14 => "0xe",
            15 => "0xf",
            _ => unreachable!(),
        })
    }
    #[inline]
    const fn wrapping_add(self, rhs: U4) -> U4 {
        U4(self.0.wrapping_add(rhs.0) & 0x0f)
    }
    #[inline]
    const fn saturating_add(self, rhs: U4) -> U4 {
        let result: u8 = self.0.saturating_add(rhs.0);
        if result > U4::MAX.0 {
            U4::MAX
        } else {
            U4(result)
        }
    }
    #[inline]
    const fn wrapping_mul(self, rhs: U4) -> U4 {
        U4(self.0.wrapping_mul(rhs.0) & 0x0f)
    }
    #[inline]
    const fn saturating_mul(self, rhs: U4) -> U4 {
        let result: u8 = self.0.saturating_mul(rhs.0);
        if result > U4::MAX.0 {
            U4::MAX
        } else {
            U4(result)
        }
    }
    #[inline]
    const fn wrapping_and(self, rhs: U4) -> U4 {
        U4(self.0 & rhs.0)
    }
    #[inline]
    const fn wrapping_not(self) -> U4 {
        U4((!self.0) & 0x0f)
    }
    #[inline]
    const fn wrapping_xor(self, rhs: U4) -> U4 {
        U4(self.0 ^ rhs.0)
    }
    #[inline]
    const fn wrapping_or(self, rhs: U4) -> U4 {
        U4(self.0 | rhs.0)
    }
    #[inline]
    const fn wrapping_shl(self, times: u8) -> U4 {
        U4((self.0 << times) & 0x0f)
    }
    #[inline]
    const fn wrapping_shr(self, times: u8) -> U4 {
        U4(self.0 >> times)
    }
    #[inline]
    fn add_photon(self, rhs: U4) -> U4 {
        self ^ rhs
    }
    #[inline]
    fn mul_photon(self, rhs: U4) -> U4 {
        let mut a: U4 = self;
        let mut b: U4 = rhs;
        let mut p: U4 = U4::MIN;
        let mut carry: bool;
        for _ in 0..4 {
            if b.0 & 1 == 1 {
                p ^= a
            }
            b >>= 1;
            carry = a.0 >> 3 == 1;
            a <<= 1;
            if carry {
                a ^= U4(0b0011)
            }
        }
        p
    }
}

fn aes_mul_photon(lhs: u8, rhs: u8) -> u8 {
    let mut a: u8 = lhs;
    let mut b: u8 = rhs;
    let mut p: u8 = 0;
    let mut carry: bool;
    for _ in 0..8 {
        if b & 1 == 1 {
            p ^= a
        }
        b >>= 1;
        carry = a >> 7 == 1;
        a <<= 1;
        if carry {
            a ^= 0x1b
        }
    }
    p
}

impl Add<U4> for U4 {
    type Output = U4;
    fn add(self, rhs: U4) -> Self::Output {
        U4::new(self.0 + rhs.0).expect("Attempted addition with overflow (U4)")
    }
}

impl Mul<U4> for U4 {
    type Output = U4;
    fn mul(self, rhs: U4) -> Self::Output {
        U4::new(self.0 * rhs.0).expect("Attempted multiplication with overflow (U4)")
    }
}

impl BitAnd<U4> for U4 {
    type Output = U4;
    fn bitand(self, rhs: U4) -> Self::Output {
        self.wrapping_and(rhs)
    }
}

impl BitAndAssign for U4 {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = self.wrapping_and(rhs)
    }
}

impl BitXor<U4> for U4 {
    type Output = U4;
    fn bitxor(self, rhs: U4) -> Self::Output {
        self.wrapping_xor(rhs)
    }
}

impl BitXorAssign for U4 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = self.wrapping_xor(rhs)
    }
}

impl Shl<u8> for U4 {
    type Output = U4;
    fn shl(self, rhs: u8) -> Self::Output {
        self.wrapping_shl(rhs)
    }
}

impl ShlAssign<u8> for U4 {
    fn shl_assign(&mut self, rhs: u8) {
        *self = self.wrapping_shl(rhs)
    }
}

impl Shr<u8> for U4 {
    type Output = U4;
    fn shr(self, rhs: u8) -> Self::Output {
        self.wrapping_shr(rhs)
    }
}

impl ShrAssign<u8> for U4 {
    fn shr_assign(&mut self, rhs: u8) {
        *self = self.wrapping_shr(rhs)
    }
}

fn sub_u4(input: U4) -> U4 {
    PRESET_SBOX[input.0 as usize]
}

fn add_constant_u4(state: &mut Array2<U4>, round: usize, block_size: PhotonBlockSize) {
    let internal_constants: &[U4] = block_size.internal_constants_u4();
    state
        .column_mut(0)
        .map_inplace(|a| *a = *a ^ ROUND_CONSTANTS[round] ^ internal_constants[a.0 as usize])
}

fn add_constant_u8(state: &mut Array2<u8>, round: usize) {
    state
        .column_mut(0)
        .map_inplace(|a| *a = *a ^ ROUND_CONSTANTS[round].0 ^ INTERNAL_CONSTANTS_288[*a as usize])
}

fn bytearray_rotate_left<T: Copy>(
    mut array: ArrayViewMut1<T>,
    mid: usize,
    block_size: PhotonBlockSize,
) {
    let mut temp;
    let d = block_size.array_size();
    for _ in 0..mid {
        temp = array[0];
        for i in 0..(d - 1) {
            array[i] = array[i + 1]
        }

        array[d - 1] = temp;
    }
}

fn shift_rows<T: Copy>(state: &mut Array2<T>, block_size: PhotonBlockSize) {
    for (rot, row) in state.rows_mut().into_iter().enumerate() {
        bytearray_rotate_left(row, rot, block_size);
    }
}

fn sub_cells_u4(state: &mut Array2<U4>) {
    state.map_inplace(|a| *a = sub_u4(*a))
}
fn sub_cells_u8(state: &mut Array2<u8>) {
    state.map_inplace(|a| *a = sub_byte(*a))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum PhotonBlockSize {
    P100,
    P144,
    P196,
    P256,
    P288,
}

impl PhotonBlockSize {
    fn array_size(&self) -> usize {
        match self {
            PhotonBlockSize::P100 => 5,
            PhotonBlockSize::P144 => 6,
            PhotonBlockSize::P196 => 7,
            PhotonBlockSize::P256 => 8,
            PhotonBlockSize::P288 => 6,
        }
    }
    fn internal_constants_u4(&self) -> &'static [U4] {
        match self {
            PhotonBlockSize::P100 => &INTERNAL_CONSTANTS_100[..],
            PhotonBlockSize::P144 => &INTERNAL_CONSTANTS_144[..],
            PhotonBlockSize::P196 => &INTERNAL_CONSTANTS_196[..],
            PhotonBlockSize::P256 => &INTERNAL_CONSTANTS_256[..],
            PhotonBlockSize::P288 => {
                unimplemented!("P288 uses u8 instead of U4, use internal_constants_u8 instead")
            }
        }
    }

    fn mixing_matrix_u4(&self) -> Array2<U4> {
        // Fuck do i have to do this :((
        let array_size: (usize, usize) = (self.array_size(), self.array_size());
        match *self {
            PhotonBlockSize::P100 => Array2::from_shape_vec(array_size, MIXING_ARRAY_100.to_vec())
                .expect("Mixing_array_100 was not the right size"),
            PhotonBlockSize::P144 => Array2::from_shape_vec(array_size, MIXING_ARRAY_144.to_vec())
                .expect("Mixing_array_144 was not the right size"),
            PhotonBlockSize::P196 => Array2::from_shape_vec(array_size, MIXING_ARRAY_196.to_vec())
                .expect("Mixing_array_196 was not the right size"),
            PhotonBlockSize::P256 => Array2::from_shape_vec(array_size, MIXING_ARRAY_256.to_vec())
                .expect("Mixing_array_256 was not the right size"),
            PhotonBlockSize::P288 => {
                unimplemented!("P288 uses matrix of u8 instead of U4. Use mixing_matrix_u8 instead")
            }
        }
    }

    fn mixing_matrix_u8(&self) -> Array2<u8> {
        let array_size: (usize, usize) = (self.array_size(), self.array_size());
        match *self {
            PhotonBlockSize::P288 => Array2::from_shape_vec(array_size, MIXING_ARRAY_288.to_vec())
                .expect("Mixing_array_288 was not the right size"),
            _ => unimplemented!(
                "P100, P144, P196 and P256 use U4 instead of u8. Use mixing_matrix_u4"
            ),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn U4_constructor_test() {
        assert_eq!(U4::new(0), Some(U4(0)));
        assert_eq!(U4::new(16), None);
        assert_eq!(U4::new(15), Some(U4(15)));
        assert_eq!(U4::new(u8::MAX), None);
    }
    #[test]
    fn U4_arith_test() {
        //sum
        assert_eq!(U4(1) + U4(6), U4(7));
        assert_eq!(U4(6) + U4(9), U4::MAX);
        assert_eq!(U4::MAX.wrapping_add(U4(1)), U4::MIN);
        assert_eq!(U4::MAX.saturating_add(U4(12)), U4::MAX);

        //times
        assert_eq!(U4(1) * U4(4), U4(4));
        assert_eq!(U4(3) * U4(5), U4::MAX);
        assert_eq!(U4(12).wrapping_mul(U4(4)), U4(0));
        assert_eq!(U4(12).saturating_mul(U4(4)), U4::MAX);

        // sum mod x^4 + x + 1
        assert_eq!(U4(2).add_photon(U4(4)), U4(6));
        assert_eq!(U4(12).add_photon(U4(10)), U4(6));

        // mul mod x^4 + x + 1
        assert_eq!(U4(0b1101).mul_photon(U4(0b1010)), U4(0b1011));
    }

    #[test]
    fn shift_rows_test() {
        let mut test_array: Array2<u8> =
            Array2::from_shape_vec((5, 5), (0u8..25).collect()).unwrap();
        let resulting_array: Array2<u8> = Array2::from_shape_vec(
            (5, 5),
            vec![
                0, 1, 2, 3, 4, 6, 7, 8, 9, 5, 12, 13, 14, 10, 11, 18, 19, 15, 16, 17, 24, 20, 21,
                22, 23,
            ],
        )
        .unwrap();
        shift_rows(&mut test_array, PhotonBlockSize::P100);
        assert_eq!(test_array, resulting_array);
    }
}

mod PhotonConstants {
    use super::*;
    pub(super) const PRESET_SBOX: [U4; 16] = [
        U4(0xc),
        U4(0x5),
        U4(0x6),
        U4(0xb),
        U4(0x9),
        U4(0x0),
        U4(0xa),
        U4(0xd),
        U4(0x3),
        U4(0xe),
        U4(0xf),
        U4(0x8),
        U4(0x4),
        U4(0x7),
        U4(0x1),
        U4(0x2),
    ];

    pub(super) const ROUND_CONSTANTS: [U4; 12] = [
        U4(1),
        U4(3),
        U4(7),
        U4(14),
        U4(13),
        U4(11),
        U4(6),
        U4(12),
        U4(9),
        U4(2),
        U4(5),
        U4(10),
    ];

    pub(super) const INTERNAL_CONSTANTS_100: [U4; 5] = [U4(0), U4(1), U4(3), U4(6), U4(4)];

    pub(super) const INTERNAL_CONSTANTS_144: [U4; 6] = [U4(0), U4(1), U4(3), U4(7), U4(6), U4(4)];

    pub(super) const INTERNAL_CONSTANTS_196: [U4; 7] =
        [U4(0), U4(1), U4(2), U4(5), U4(3), U4(6), U4(4)];

    pub(super) const INTERNAL_CONSTANTS_256: [U4; 8] =
        [U4(0), U4(1), U4(3), U4(7), U4(15), U4(14), U4(12), U4(8)];

    pub(super) const INTERNAL_CONSTANTS_288: [u8; 6] = [0, 1, 3, 7, 6, 4];

    pub(super) const NUMBER_OF_ROUNDS: usize = 12;

    pub(super) const MIXING_ARRAY_100: [U4; 25] = [
        U4(1),
        U4(2),
        U4(9),
        U4(9),
        U4(2),
        U4(2),
        U4(5),
        U4(3),
        U4(8),
        U4(13),
        U4(13),
        U4(11),
        U4(10),
        U4(12),
        U4(1),
        U4(1),
        U4(15),
        U4(2),
        U4(3),
        U4(14),
        U4(14),
        U4(14),
        U4(8),
        U4(5),
        U4(12),
    ];

    pub(super) const MIXING_ARRAY_144: [U4; 36] = [
        U4(1),
        U4(2),
        U4(8),
        U4(5),
        U4(8),
        U4(2),
        U4(2),
        U4(5),
        U4(1),
        U4(2),
        U4(6),
        U4(12),
        U4(12),
        U4(9),
        U4(15),
        U4(8),
        U4(8),
        U4(13),
        U4(13),
        U4(5),
        U4(11),
        U4(3),
        U4(10),
        U4(1),
        U4(1),
        U4(15),
        U4(13),
        U4(14),
        U4(11),
        U4(8),
        U4(8),
        U4(2),
        U4(3),
        U4(3),
        U4(2),
        U4(8),
    ];

    pub(super) const MIXING_ARRAY_196: [U4; 49] = [
        U4(1),
        U4(4),
        U4(6),
        U4(1),
        U4(1),
        U4(6),
        U4(4),
        U4(4),
        U4(2),
        U4(15),
        U4(2),
        U4(5),
        U4(10),
        U4(5),
        U4(5),
        U4(3),
        U4(15),
        U4(10),
        U4(7),
        U4(8),
        U4(13),
        U4(13),
        U4(4),
        U4(11),
        U4(2),
        U4(7),
        U4(15),
        U4(9),
        U4(9),
        U4(15),
        U4(7),
        U4(2),
        U4(11),
        U4(4),
        U4(13),
        U4(13),
        U4(8),
        U4(7),
        U4(10),
        U4(15),
        U4(3),
        U4(5),
        U4(5),
        U4(10),
        U4(5),
        U4(2),
        U4(15),
        U4(2),
        U4(4),
    ];

    pub(super) const MIXING_ARRAY_256: [U4; 64] = [
        U4(2),
        U4(4),
        U4(2),
        U4(11),
        U4(2),
        U4(8),
        U4(5),
        U4(6),
        U4(12),
        U4(9),
        U4(8),
        U4(13),
        U4(7),
        U4(7),
        U4(5),
        U4(2),
        U4(4),
        U4(4),
        U4(13),
        U4(13),
        U4(9),
        U4(4),
        U4(13),
        U4(9),
        U4(1),
        U4(6),
        U4(5),
        U4(1),
        U4(12),
        U4(13),
        U4(15),
        U4(14),
        U4(15),
        U4(12),
        U4(9),
        U4(13),
        U4(14),
        U4(5),
        U4(14),
        U4(13),
        U4(9),
        U4(14),
        U4(5),
        U4(15),
        U4(4),
        U4(12),
        U4(9),
        U4(6),
        U4(12),
        U4(2),
        U4(2),
        U4(10),
        U4(3),
        U4(1),
        U4(1),
        U4(14),
        U4(15),
        U4(1),
        U4(13),
        U4(10),
        U4(5),
        U4(10),
        U4(2),
        U4(3),
    ];

    pub(super) const MIXING_ARRAY_288: [u8; 36] = [
        2, 3, 1, 2, 1, 4, 8, 14, 7, 9, 6, 17, 34, 59, 31, 37, 24, 66, 132, 228, 121, 155, 103, 11,
        22, 153, 239, 111, 144, 75, 150, 203, 210, 121, 36, 167,
    ];
}
