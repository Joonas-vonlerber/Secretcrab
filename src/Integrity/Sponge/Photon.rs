use ndarray::{Array2, ArrayViewMut1};
use num_traits::{One, Zero};
use std::ops::*;

use crate::Confidentiality::AES::sub_byte;
use PhotonConstants::*;

use super::extended_sponge;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum PhotonCell {
    U4(u8),
    U8(u8),
}

impl PhotonCell {
    fn zero(&self) -> Self {
        match self {
            PhotonCell::U4(_) => PhotonCell::U4(0),
            PhotonCell::U8(_) => PhotonCell::U8(0),
        }
    }

    fn one(&self) -> Self {
        match self {
            PhotonCell::U4(_) => PhotonCell::U4(1),
            PhotonCell::U8(_) => PhotonCell::U8(1),
        }
    }

    fn value(&self) -> u8 {
        match self {
            PhotonCell::U4(a) => *a,
            PhotonCell::U8(a) => *a,
        }
    }

    fn modulo(&self) -> u8 {
        match self {
            PhotonCell::U4(_) => 0b0011,
            PhotonCell::U8(_) => 0x1b,
        }
    }

    fn bits(&self) -> usize {
        match self {
            PhotonCell::U4(_) => 4,
            PhotonCell::U8(_) => 8,
        }
    }

    fn powby254(self) -> Self {
        let x = self;
        let x2 = x * x;
        let x3 = x * x2;
        let x6 = x3 * x3;
        let x12 = x6 * x6;
        let x15 = x12 * x3;
        let x30 = x15 * x15;
        let x60 = x30 * x30;
        let x120 = x60 * x60;
        let x126 = x120 * x6;
        let x127 = x126 * x;
        x127 * x127
    }

    fn powby14(self) -> Self {
        let x = self;
        let x2 = x * x;
        let x3 = x2 * x;
        let x4 = x2 * x2;
        let x7 = x3 * x4;
        x7 * x7
    }

    fn inv(self) -> Option<Self> {
        if self.value() == 0 {
            return None;
        }
        let inverse = match self {
            PhotonCell::U4(_) => self.powby14(),
            PhotonCell::U8(_) => self.powby254(),
        };
        assert_eq!(self * inverse, self.one());
        Some(inverse)
    }

    // fn inv(self) -> Option<Self> {
    //     let mut t: u8 = 0;
    //     let mut r: u8 = self.modulo();
    //     let mut newt: u8 = 1;
    //     let mut newr: u8 = self.value();
    //     let mut quotient: u8;
    //     while newr != 0 {
    //         (quotient, _) = poly_div(r, newr);
    //         (r, newr) = (newr, r ^ (poly_mul(quotient, newr)) as u8);
    //         (t, newt) = (newt, t ^ (poly_mul(quotient, newt)) as u8);
    //     }
    //     if poly_deg(r) > 0 {
    //         return None;
    //     }
    //     let result = match self {
    //         PhotonCell::U4(_) => PhotonCell::U4(t),
    //         PhotonCell::U8(_) => PhotonCell::U8(t),
    //     };

    //     assert_eq!(self * result, self.one());
    //     Some(result)
    // }
}

impl BitXor for PhotonCell {
    type Output = PhotonCell;
    fn bitxor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (PhotonCell::U4(a), PhotonCell::U4(b)) => PhotonCell::U4(a ^ b),
            (PhotonCell::U8(a), PhotonCell::U8(b)) => PhotonCell::U8(a ^ b),
            (PhotonCell::U4(a), PhotonCell::U8(b)) => PhotonCell::U8(a ^ b),
            (PhotonCell::U8(a), PhotonCell::U4(b)) => PhotonCell::U8(a ^ b),
        }
    }
}

impl BitXorAssign for PhotonCell {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs
    }
}

impl Shl<u8> for PhotonCell {
    type Output = PhotonCell;
    fn shl(self, rhs: u8) -> Self::Output {
        match self {
            PhotonCell::U4(a) => PhotonCell::U4((a << rhs) & 0xf),
            PhotonCell::U8(a) => PhotonCell::U8(a << rhs),
        }
    }
}

fn poly_deg(p: u8) -> i8 {
    7i8 - (p.leading_zeros() as i8)
}

fn poly_div(lhs: u8, rhs: u8) -> (u8, u8) {
    assert_ne!(rhs, 0, "Cannot divide by 0");
    let mut q: u8 = 0;
    let mut r: u8 = lhs;
    while poly_deg(r) >= poly_deg(rhs) {
        let pos: u8 = (poly_deg(r) - poly_deg(rhs)).try_into().unwrap();
        q += 1 << pos;
        r ^= rhs << pos;
    }
    assert_eq!(u16::from(lhs), poly_mul(q, rhs) ^ r as u16);
    (q, r)
}

fn mul_char_2(lhs: u8, rhs: u8, bits: usize, modulo: u8) -> u8 {
    let mut a: u8 = lhs;
    let mut b: u8 = rhs;
    let mut p: u8 = 0;
    let mut carry: bool;
    let cutoff: u8 = if bits >= 8 {
        0xff
    } else {
        (1u8 << bits).saturating_sub(1)
    };
    for _ in 0..bits {
        if b & 1 == 1 {
            p ^= a;
        }
        b >>= 1;
        carry = a >> (bits - 1) == 1;
        a = (a << 1) & cutoff;
        if carry {
            a ^= modulo
        }
    }
    p
}

fn poly_mul(lhs: u8, rhs: u8) -> u16 {
    let mut a = u16::from(lhs);
    let mut b = u16::from(rhs);
    let mut p: u16 = 0;
    for _ in 0u8..8 {
        if b & 1 == 1 {
            p ^= a;
        }
        b >>= 1;
        a <<= 1;
    }
    p
}

impl Add for PhotonCell {
    type Output = PhotonCell;
    fn add(self, rhs: Self) -> Self::Output {
        self ^ rhs
    }
}

impl AddAssign for PhotonCell {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Mul for PhotonCell {
    type Output = PhotonCell;
    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (PhotonCell::U4(a), PhotonCell::U4(b)) => PhotonCell::U4(mul_char_2(a, b, 4, 0b0011)),
            (PhotonCell::U8(a), PhotonCell::U8(b)) => PhotonCell::U8(mul_char_2(a, b, 8, 0x1b)),
            (PhotonCell::U4(a), PhotonCell::U8(b)) => PhotonCell::U8(mul_char_2(a, b, 8, 0x1b)),
            (PhotonCell::U8(a), PhotonCell::U4(b)) => PhotonCell::U8(mul_char_2(a, b, 8, 0x1b)),
        }
    }
}

impl Sub for PhotonCell {
    type Output = PhotonCell;
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl Div for PhotonCell {
    type Output = PhotonCell;
    fn div(self, rhs: Self) -> Self::Output {
        self * (rhs.inv().expect("Division by 0"))
    }
}

impl Zero for PhotonCell {
    fn zero() -> Self {
        Self::U4(0)
    }
    fn is_zero(&self) -> bool {
        self.value() == 0
    }
}

impl One for PhotonCell {
    fn one() -> Self {
        Self::U4(1)
    }
}

fn add_constant(state: &mut Array2<PhotonCell>, round: usize, block_size: PhotonBlockSize) {
    let mut row_ind: usize = 0;
    let rows = state.shape()[0];
    let internal_constants: &[PhotonCell] = block_size.internal_constants();
    state.column_mut(0).map_inplace(|a| {
        *a = *a ^ ROUND_CONSTANTS[round] ^ internal_constants[row_ind % rows];
        row_ind += 1;
    })
}

fn bytearray_rotate_left(
    mut array: ArrayViewMut1<PhotonCell>,
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

fn shift_rows(state: &mut Array2<PhotonCell>, block_size: PhotonBlockSize) {
    for (rot, row) in state.rows_mut().into_iter().enumerate() {
        bytearray_rotate_left(row, rot, block_size);
    }
}

#[inline]
fn sub_cell(cell: PhotonCell) -> PhotonCell {
    match cell {
        PhotonCell::U4(a) => PRESET_SBOX[a as usize],
        PhotonCell::U8(a) => PhotonCell::U8(sub_byte(a)),
    }
}

fn sub_cells(state: &mut Array2<PhotonCell>) {
    state.map_inplace(|a| *a = sub_cell(*a))
}

fn mix_columns_serial(state: &mut Array2<PhotonCell>, block_size: PhotonBlockSize) {
    let matrix: Array2<PhotonCell> = block_size.mixing_matrix();
    for mut column in state.columns_mut() {
        let mixed = matrix.dot(&column);
        column.assign(&mixed);
    }
}

fn u8_to_photoncell(value: u8, block_size: PhotonBlockSize) -> Vec<PhotonCell> {
    match block_size {
        PhotonBlockSize::P288 => vec![PhotonCell::U8(value)],
        _ => vec![PhotonCell::U4(value >> 4), PhotonCell::U4(value & 0xf)],
    }
}

fn photoncell_to_u8(values: (PhotonCell, PhotonCell), block_size: PhotonBlockSize) -> Vec<u8> {
    match block_size {
        PhotonBlockSize::P288 => vec![values.0.value(), values.1.value()],
        _ => vec![(values.0.value() << 4) + (values.1.value())],
    }
}

fn state_to_array<const STATE_SIZE: usize>(
    state: &[u8; STATE_SIZE],
    block_size: PhotonBlockSize,
) -> Array2<PhotonCell> {
    let shape = (block_size.array_size(), block_size.array_size());
    let cellstate: Vec<PhotonCell> = state
        .iter()
        .flat_map(|a| u8_to_photoncell(*a, block_size))
        .collect();
    Array2::from_shape_vec(shape, cellstate)
        .expect("state_size and block_size do not work with eachother")
}

fn array_to_state<const STATE_SIZE: usize>(
    array: Array2<PhotonCell>,
    block_size: PhotonBlockSize,
) -> [u8; STATE_SIZE] {
    let cellstate = array.into_raw_vec();
    let state_vec: Vec<u8> = cellstate
        .chunks_exact(2)
        .flat_map(|xs| photoncell_to_u8((xs[0], xs[1]), block_size))
        .collect();
    state_vec
        .try_into()
        .expect("The array had an odd amount of elements. Implementing either P100 or P196")
}

fn photon_perm<const STATE_SIZE: usize>(state: &mut [u8; STATE_SIZE], block_size: PhotonBlockSize) {
    let mut array: Array2<PhotonCell> = state_to_array(&*state, block_size);
    for round in 0..12 {
        add_constant(&mut array, round, block_size);
        sub_cells(&mut array);
        shift_rows(&mut array, block_size);
        mix_columns_serial(&mut array, block_size);
    }
    *state = array_to_state(array, block_size);
}

fn photon_pad(input: &[u8], rate: usize) -> Vec<u8> {
    let padding_needed = rate - (input.len() % rate);
    let padding_bytes: Vec<u8> = match padding_needed {
        0 => [[0x80].to_vec(), [0x00].repeat(rate - 1)].concat(),
        1 => vec![0x80],
        x => [[0x80].to_vec(), [0x00].repeat(x - 1)].concat(),
    };
    [input, padding_bytes.as_slice()].concat()
}

fn photon_P144<const STATE_SIZE: usize>(state: &mut [u8; STATE_SIZE]) {
    photon_perm(state, PhotonBlockSize::P144)
}
fn photon_P256<const STATE_SIZE: usize>(state: &mut [u8; STATE_SIZE]) {
    photon_perm(state, PhotonBlockSize::P256)
}
fn photon_P288<const STATE_SIZE: usize>(state: &mut [u8; STATE_SIZE]) {
    photon_perm(state, PhotonBlockSize::P288)
}

fn photon<const HASH_LEN: usize, const STATE_SIZE: usize, F: Fn(&mut [u8; STATE_SIZE])>(
    input: &[u8],
    perm_fun: F,
    absorb_rate: u8,
    squeeze_rate: u8,
) -> [u8; HASH_LEN] {
    let initialization_state: [u8; STATE_SIZE] = [
        &[0x00].repeat(STATE_SIZE - 3)[..],
        &[(HASH_LEN / 4) as u8][..],
        &[absorb_rate][..],
        &[squeeze_rate][..],
    ]
    .concat()
    .try_into()
    .expect("The initialization rate should be the correct length");
    extended_sponge::<_, _, HASH_LEN, STATE_SIZE>(
        perm_fun,
        photon_pad,
        absorb_rate.into(),
        squeeze_rate.into(),
        initialization_state,
        input,
    )
}

fn photon128(input: &[u8]) -> [u8; 16] {
    photon::<16, 18, _>(input, photon_P144, 2, 2)
}

fn photon224(input: &[u8]) -> [u8; 28] {
    photon::<28, 32, _>(input, photon_P256, 4, 4)
}

fn photon256(input: &[u8]) -> [u8; 32] {
    photon::<32, 36, _>(input, photon_P288, 4, 4)
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
    fn internal_constants(&self) -> &'static [PhotonCell] {
        match self {
            PhotonBlockSize::P100 => &INTERNAL_CONSTANTS_100[..],
            PhotonBlockSize::P144 => &INTERNAL_CONSTANTS_144[..],
            PhotonBlockSize::P196 => &INTERNAL_CONSTANTS_196[..],
            PhotonBlockSize::P256 => &INTERNAL_CONSTANTS_256[..],
            PhotonBlockSize::P288 => &INTERNAL_CONSTANTS_288[..],
        }
    }

    fn mixing_matrix(&self) -> Array2<PhotonCell> {
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
            PhotonBlockSize::P288 => Array2::from_shape_vec(array_size, MIXING_ARRAY_288.to_vec())
                .expect("Mixing_array_288 was not the right size"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::ShapeBuilder;

    #[test]
    fn photoncell_arith_test() {
        //sum
        let a = PhotonCell::U4(0b1011);
        let b = PhotonCell::U4(0b1010);
        assert_eq!(a + b, PhotonCell::U4(0b0001));

        let c = PhotonCell::U4(0b1110);
        let d = PhotonCell::U4(0b1101);
        assert_eq!(c + d, PhotonCell::U4(0b0011));

        let e = PhotonCell::U4(0b1000);
        let f = PhotonCell::U8(0b00100110);
        assert_eq!(e + f, PhotonCell::U8(0b00101110));

        let g = PhotonCell::U8(0x7d);
        let h = PhotonCell::U4(0xf);
        assert_eq!(g + h, PhotonCell::U8(0x72));

        let i = PhotonCell::U8(0x42);
        let j = PhotonCell::U8(0x69);
        assert_eq!(i + j, PhotonCell::U8(0x2B));

        // leftshift
        let k = PhotonCell::U4(0b0101);
        assert_eq!(k << 1, PhotonCell::U4(0b1010));
        assert_eq!(k << 2, PhotonCell::U4(0b0100));
        assert_eq!(k << 3, PhotonCell::U4(0b1000));
        assert_eq!(k << 4, PhotonCell::U4(0b0000));

        // if this works then all of it should work, it was such a simple implementation
        let l = PhotonCell::U8(0b01010101);
        assert_eq!(l << 7, PhotonCell::U8(0b10000000));

        // product
        let m = PhotonCell::U4(0b1001);
        let n = PhotonCell::U4(0b0111);
        assert_eq!(m * n, PhotonCell::U4(0b1010));

        let o = PhotonCell::U4(0b0011);
        let p = PhotonCell::U4(0b1111);
        assert_eq!(o * p, PhotonCell::U4(0b0010));

        let q = PhotonCell::U4(0b1001);
        let r = PhotonCell::U4(0b0011);
        assert_eq!(q * r, PhotonCell::U4(0b1000));

        let s = PhotonCell::U8(0b01101001);
        let t = PhotonCell::U8(0b11101010);
        assert_eq!(s * t, PhotonCell::U8(0b00110111));

        let u = PhotonCell::U8(0b00100111);
        let v = PhotonCell::U8(0b11100110);
        assert_eq!(u * v, PhotonCell::U8(0b01011011));

        let w = PhotonCell::U8(0b10010011);
        let x = PhotonCell::U8(0b01001001);
        assert_eq!(w * x, PhotonCell::U8(0b10000110));

        // division and deg

        let y: u8 = 0b01110001;
        let z: u8 = 0b00001100;
        assert_eq!(poly_div(y, z), (0b00001011, 0b00000101));
        assert_eq!(poly_deg(y), 6);
        assert_eq!(poly_deg(z), 3);

        let a1: u8 = 0b11011001;
        let b1: u8 = 0b00001111;
        assert_eq!(poly_div(a1, b1), (0b00010111, 0b00000100));
        assert_eq!(poly_deg(a1), 7);
        assert_eq!(poly_deg(b1), 3);

        assert_eq!(poly_deg(0), -1);
        assert_eq!(poly_deg(1), 0);
        assert_eq!(poly_deg(2), 1);

        // polymul
        let c1: u8 = 0b11101001;
        let d1: u8 = 0b00010101;
        assert_eq!(poly_mul(c1, d1), 0b0000110111011101);

        let e1: u8 = 0b00110101;
        let f1: u8 = 0b11011010;
        assert_eq!(poly_mul(e1, f1), 0b0001010101010010);
    }

    #[test]
    fn shift_rows_test() {
        let mut test_array: Array2<PhotonCell> =
            Array2::from_shape_vec((5, 5), (0u8..25).map(PhotonCell::U8).collect()).unwrap();

        let resulting_array: Array2<PhotonCell> = Array2::from_shape_vec(
            (5, 5),
            vec![
                PhotonCell::U8(0),
                PhotonCell::U8(1),
                PhotonCell::U8(2),
                PhotonCell::U8(3),
                PhotonCell::U8(4),
                PhotonCell::U8(6),
                PhotonCell::U8(7),
                PhotonCell::U8(8),
                PhotonCell::U8(9),
                PhotonCell::U8(5),
                PhotonCell::U8(12),
                PhotonCell::U8(13),
                PhotonCell::U8(14),
                PhotonCell::U8(10),
                PhotonCell::U8(11),
                PhotonCell::U8(18),
                PhotonCell::U8(19),
                PhotonCell::U8(15),
                PhotonCell::U8(16),
                PhotonCell::U8(17),
                PhotonCell::U8(24),
                PhotonCell::U8(20),
                PhotonCell::U8(21),
                PhotonCell::U8(22),
                PhotonCell::U8(23),
            ],
        )
        .unwrap();
        shift_rows(&mut test_array, PhotonBlockSize::P100);
        assert_eq!(test_array, resulting_array);
    }

    #[test]
    fn inverse_test() {
        let a = PhotonCell::U8(0b01011011);
        assert_eq!(a.inv(), Some(PhotonCell::U8(0b11110000)));
    }

    #[test]
    fn add_constant_test() {
        let mut state: Array2<PhotonCell> = Array2::zeros((5, 5));
        let afterstate: Array2<PhotonCell> = Array2::from_shape_vec(
            (5, 5).f(),
            [
                vec![
                    PhotonCell::U4(1),
                    PhotonCell::U4(0),
                    PhotonCell::U4(2),
                    PhotonCell::U4(7),
                    PhotonCell::U4(5),
                ],
                [PhotonCell::U4(0)].repeat(20),
            ]
            .concat(),
        )
        .unwrap();
        add_constant(&mut state, 0, PhotonBlockSize::P100);
        assert_eq!(state, afterstate);
    }
}

mod PhotonConstants {
    use super::*;
    pub(super) const PRESET_SBOX: [PhotonCell; 16] = [
        PhotonCell::U4(0xc),
        PhotonCell::U4(0x5),
        PhotonCell::U4(0x6),
        PhotonCell::U4(0xb),
        PhotonCell::U4(0x9),
        PhotonCell::U4(0x0),
        PhotonCell::U4(0xa),
        PhotonCell::U4(0xd),
        PhotonCell::U4(0x3),
        PhotonCell::U4(0xe),
        PhotonCell::U4(0xf),
        PhotonCell::U4(0x8),
        PhotonCell::U4(0x4),
        PhotonCell::U4(0x7),
        PhotonCell::U4(0x1),
        PhotonCell::U4(0x2),
    ];

    pub(super) const ROUND_CONSTANTS: [PhotonCell; 12] = [
        PhotonCell::U4(1),
        PhotonCell::U4(3),
        PhotonCell::U4(7),
        PhotonCell::U4(14),
        PhotonCell::U4(13),
        PhotonCell::U4(11),
        PhotonCell::U4(6),
        PhotonCell::U4(12),
        PhotonCell::U4(9),
        PhotonCell::U4(2),
        PhotonCell::U4(5),
        PhotonCell::U4(10),
    ];

    pub(super) const INTERNAL_CONSTANTS_100: [PhotonCell; 5] = [
        PhotonCell::U4(0),
        PhotonCell::U4(1),
        PhotonCell::U4(3),
        PhotonCell::U4(6),
        PhotonCell::U4(4),
    ];

    pub(super) const INTERNAL_CONSTANTS_144: [PhotonCell; 6] = [
        PhotonCell::U4(0),
        PhotonCell::U4(1),
        PhotonCell::U4(3),
        PhotonCell::U4(7),
        PhotonCell::U4(6),
        PhotonCell::U4(4),
    ];

    pub(super) const INTERNAL_CONSTANTS_196: [PhotonCell; 7] = [
        PhotonCell::U4(0),
        PhotonCell::U4(1),
        PhotonCell::U4(2),
        PhotonCell::U4(5),
        PhotonCell::U4(3),
        PhotonCell::U4(6),
        PhotonCell::U4(4),
    ];

    pub(super) const INTERNAL_CONSTANTS_256: [PhotonCell; 8] = [
        PhotonCell::U4(0),
        PhotonCell::U4(1),
        PhotonCell::U4(3),
        PhotonCell::U4(7),
        PhotonCell::U4(15),
        PhotonCell::U4(14),
        PhotonCell::U4(12),
        PhotonCell::U4(8),
    ];

    pub(super) const INTERNAL_CONSTANTS_288: [PhotonCell; 6] = [
        PhotonCell::U8(0),
        PhotonCell::U8(1),
        PhotonCell::U8(3),
        PhotonCell::U8(7),
        PhotonCell::U8(6),
        PhotonCell::U8(4),
    ];

    pub(super) const NUMBER_OF_ROUNDS: usize = 12;

    pub(super) const MIXING_ARRAY_100: [PhotonCell; 25] = [
        PhotonCell::U4(1),
        PhotonCell::U4(2),
        PhotonCell::U4(9),
        PhotonCell::U4(9),
        PhotonCell::U4(2),
        PhotonCell::U4(2),
        PhotonCell::U4(5),
        PhotonCell::U4(3),
        PhotonCell::U4(8),
        PhotonCell::U4(13),
        PhotonCell::U4(13),
        PhotonCell::U4(11),
        PhotonCell::U4(10),
        PhotonCell::U4(12),
        PhotonCell::U4(1),
        PhotonCell::U4(1),
        PhotonCell::U4(15),
        PhotonCell::U4(2),
        PhotonCell::U4(3),
        PhotonCell::U4(14),
        PhotonCell::U4(14),
        PhotonCell::U4(14),
        PhotonCell::U4(8),
        PhotonCell::U4(5),
        PhotonCell::U4(12),
    ];

    pub(super) const MIXING_ARRAY_144: [PhotonCell; 36] = [
        PhotonCell::U4(1),
        PhotonCell::U4(2),
        PhotonCell::U4(8),
        PhotonCell::U4(5),
        PhotonCell::U4(8),
        PhotonCell::U4(2),
        PhotonCell::U4(2),
        PhotonCell::U4(5),
        PhotonCell::U4(1),
        PhotonCell::U4(2),
        PhotonCell::U4(6),
        PhotonCell::U4(12),
        PhotonCell::U4(12),
        PhotonCell::U4(9),
        PhotonCell::U4(15),
        PhotonCell::U4(8),
        PhotonCell::U4(8),
        PhotonCell::U4(13),
        PhotonCell::U4(13),
        PhotonCell::U4(5),
        PhotonCell::U4(11),
        PhotonCell::U4(3),
        PhotonCell::U4(10),
        PhotonCell::U4(1),
        PhotonCell::U4(1),
        PhotonCell::U4(15),
        PhotonCell::U4(13),
        PhotonCell::U4(14),
        PhotonCell::U4(11),
        PhotonCell::U4(8),
        PhotonCell::U4(8),
        PhotonCell::U4(2),
        PhotonCell::U4(3),
        PhotonCell::U4(3),
        PhotonCell::U4(2),
        PhotonCell::U4(8),
    ];

    pub(super) const MIXING_ARRAY_196: [PhotonCell; 49] = [
        PhotonCell::U4(1),
        PhotonCell::U4(4),
        PhotonCell::U4(6),
        PhotonCell::U4(1),
        PhotonCell::U4(1),
        PhotonCell::U4(6),
        PhotonCell::U4(4),
        PhotonCell::U4(4),
        PhotonCell::U4(2),
        PhotonCell::U4(15),
        PhotonCell::U4(2),
        PhotonCell::U4(5),
        PhotonCell::U4(10),
        PhotonCell::U4(5),
        PhotonCell::U4(5),
        PhotonCell::U4(3),
        PhotonCell::U4(15),
        PhotonCell::U4(10),
        PhotonCell::U4(7),
        PhotonCell::U4(8),
        PhotonCell::U4(13),
        PhotonCell::U4(13),
        PhotonCell::U4(4),
        PhotonCell::U4(11),
        PhotonCell::U4(2),
        PhotonCell::U4(7),
        PhotonCell::U4(15),
        PhotonCell::U4(9),
        PhotonCell::U4(9),
        PhotonCell::U4(15),
        PhotonCell::U4(7),
        PhotonCell::U4(2),
        PhotonCell::U4(11),
        PhotonCell::U4(4),
        PhotonCell::U4(13),
        PhotonCell::U4(13),
        PhotonCell::U4(8),
        PhotonCell::U4(7),
        PhotonCell::U4(10),
        PhotonCell::U4(15),
        PhotonCell::U4(3),
        PhotonCell::U4(5),
        PhotonCell::U4(5),
        PhotonCell::U4(10),
        PhotonCell::U4(5),
        PhotonCell::U4(2),
        PhotonCell::U4(15),
        PhotonCell::U4(2),
        PhotonCell::U4(4),
    ];

    pub(super) const MIXING_ARRAY_256: [PhotonCell; 64] = [
        PhotonCell::U4(2),
        PhotonCell::U4(4),
        PhotonCell::U4(2),
        PhotonCell::U4(11),
        PhotonCell::U4(2),
        PhotonCell::U4(8),
        PhotonCell::U4(5),
        PhotonCell::U4(6),
        PhotonCell::U4(12),
        PhotonCell::U4(9),
        PhotonCell::U4(8),
        PhotonCell::U4(13),
        PhotonCell::U4(7),
        PhotonCell::U4(7),
        PhotonCell::U4(5),
        PhotonCell::U4(2),
        PhotonCell::U4(4),
        PhotonCell::U4(4),
        PhotonCell::U4(13),
        PhotonCell::U4(13),
        PhotonCell::U4(9),
        PhotonCell::U4(4),
        PhotonCell::U4(13),
        PhotonCell::U4(9),
        PhotonCell::U4(1),
        PhotonCell::U4(6),
        PhotonCell::U4(5),
        PhotonCell::U4(1),
        PhotonCell::U4(12),
        PhotonCell::U4(13),
        PhotonCell::U4(15),
        PhotonCell::U4(14),
        PhotonCell::U4(15),
        PhotonCell::U4(12),
        PhotonCell::U4(9),
        PhotonCell::U4(13),
        PhotonCell::U4(14),
        PhotonCell::U4(5),
        PhotonCell::U4(14),
        PhotonCell::U4(13),
        PhotonCell::U4(9),
        PhotonCell::U4(14),
        PhotonCell::U4(5),
        PhotonCell::U4(15),
        PhotonCell::U4(4),
        PhotonCell::U4(12),
        PhotonCell::U4(9),
        PhotonCell::U4(6),
        PhotonCell::U4(12),
        PhotonCell::U4(2),
        PhotonCell::U4(2),
        PhotonCell::U4(10),
        PhotonCell::U4(3),
        PhotonCell::U4(1),
        PhotonCell::U4(1),
        PhotonCell::U4(14),
        PhotonCell::U4(15),
        PhotonCell::U4(1),
        PhotonCell::U4(13),
        PhotonCell::U4(10),
        PhotonCell::U4(5),
        PhotonCell::U4(10),
        PhotonCell::U4(2),
        PhotonCell::U4(3),
    ];

    pub(super) const MIXING_ARRAY_288: [PhotonCell; 36] = [
        PhotonCell::U8(2),
        PhotonCell::U8(3),
        PhotonCell::U8(1),
        PhotonCell::U8(2),
        PhotonCell::U8(1),
        PhotonCell::U8(4),
        PhotonCell::U8(8),
        PhotonCell::U8(14),
        PhotonCell::U8(7),
        PhotonCell::U8(9),
        PhotonCell::U8(6),
        PhotonCell::U8(17),
        PhotonCell::U8(34),
        PhotonCell::U8(59),
        PhotonCell::U8(31),
        PhotonCell::U8(37),
        PhotonCell::U8(24),
        PhotonCell::U8(66),
        PhotonCell::U8(132),
        PhotonCell::U8(228),
        PhotonCell::U8(121),
        PhotonCell::U8(155),
        PhotonCell::U8(103),
        PhotonCell::U8(11),
        PhotonCell::U8(22),
        PhotonCell::U8(153),
        PhotonCell::U8(239),
        PhotonCell::U8(111),
        PhotonCell::U8(144),
        PhotonCell::U8(75),
        PhotonCell::U8(150),
        PhotonCell::U8(203),
        PhotonCell::U8(210),
        PhotonCell::U8(121),
        PhotonCell::U8(36),
        PhotonCell::U8(167),
    ];
}
