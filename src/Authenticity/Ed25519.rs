use crypto_bigint::{
    impl_modulus, modular::constant_mod::Residue, modular::constant_mod::ResidueParams, Encoding,
    Limb, NonZero, Random, Uint, U256, U512,
};

use crate::Integrity::SHA::sha_512;
use const_hex::const_decode_to_array;
use rand::{prelude::*, rngs::OsRng};

const fn ct_eq(lhs_res: &GF25519, rhs_res: &GF25519) -> bool {
    let mut acc = 0;
    let mut i = 0;

    let lhs = lhs_res.retrieve();
    let rhs = rhs_res.retrieve();

    while i < 4 {
        acc |= lhs.as_limbs()[i].0 ^ rhs.as_limbs()[i].0;
        i += 1;
    }

    // acc == 0 if and only if self == rhs
    acc == 0
}

const fn ct_gt(lhs: &U256, rhs: &U256) -> bool {
    let (_res, borrow) = rhs.sbb(lhs, Limb::ZERO);
    borrow.0 == u64::MAX
}

impl_modulus!(
    GF25519Modulo,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

type GF25519 = Residue<GF25519Modulo, 4>;

macro_rules! residue {
    ($value: expr) => {
        GF25519::new(&U256::from_u32($value))
    };
}

const fn div(num: &GF25519, dem: &GF25519) -> GF25519 {
    num.mul(&dem.pow(&GF25519Modulo::MODULUS.wrapping_sub(&U256::from_u8(2))))
}

const fn invert(res: &GF25519) -> GF25519 {
    res.pow(&GF25519Modulo::MODULUS.wrapping_sub(&U256::from_u8(2)))
}

fn sqrt(quad_residue: &GF25519) -> Option<(GF25519, GF25519)> {
    if !is_quadratic_residue(quad_residue) && quad_residue.as_montgomery() != &U256::ZERO {
        return None;
    }
    // Factor modulo-1 into Q*2^S, where Q is odd
    let mut Q: U256 = GF25519Modulo::MODULUS.wrapping_sub(&U256::ONE);
    let mut S: u32 = 0;
    while Q.rem2k(1) == U256::ZERO {
        Q >>= 1usize;
        S += 1;
    }
    assert_eq!(
        Q.wrapping_mul(&(U256::from_u8(1) << S as usize)),
        GF25519Modulo::MODULUS.wrapping_sub(&U256::ONE)
    );

    // Find a non quadratic residue
    let mut rng = OsRng;
    let mut non_residue: GF25519 = GF25519::random(&mut rng);
    while is_quadratic_residue(&non_residue) || non_residue.as_montgomery() == &U256::ZERO {
        non_residue = GF25519::random(&mut rng);
    }
    let mut M: U256 = U256::from_u32(S);
    let mut c: GF25519 = non_residue.pow(&Q);
    let mut t: GF25519 = quad_residue.pow(&Q);
    let mut R: GF25519 = quad_residue.pow(
        // quadresidue^((Q+1)/2)
        &Q.wrapping_add(&U256::ONE).wrapping_div(&U256::from_u8(2)),
    );
    let mut i: U256 = U256::ZERO;
    let mut b: GF25519;
    let mut repeated_squared_t: GF25519 = t;

    loop {
        // Do we return?
        if t.as_montgomery() == &U256::ZERO {
            return Some((GF25519::ZERO, GF25519::ZERO));
        } else if t.as_montgomery() == &GF25519Modulo::R {
            return Some((R, R.neg()));
        }

        // Find i
        while repeated_squared_t.as_montgomery() != &GF25519Modulo::R {
            i = i.wrapping_add(&U256::ONE);
            repeated_squared_t = repeated_squared_t.square();
        }
        if i == M {
            return None;
        }
        b = c.pow(
            &residue!(2)
                .pow(&(M.wrapping_sub(&i).wrapping_sub(&U256::ONE)))
                .retrieve(),
        ); // c^(2^(M-i-1)), tän 2^fasfd vois tehä ainaki shiftauksella mut ku moduloooo :DDDD
        M = i;
        c = b.square();
        t = t.mul(&b.square());
        R = R.mul(&b);

        i = U256::ZERO;
        repeated_squared_t = t;
    }
}

fn is_quadratic_residue(candidate: &GF25519) -> bool {
    let legrende: U256 = candidate
        .pow(
            &GF25519Modulo::MODULUS
                .wrapping_sub(&U256::ONE)
                .wrapping_div(&U256::from_u8(2)),
        )
        .retrieve();
    legrende == U256::ONE
}

#[derive(Debug, Clone, Copy)]
/// Point on the curve Ed25519 represented in extended twisted edwards coordinates e.g four coordinates X,Y,T,Z, where for an affine point (x,y)
/// X = x/Z, Y = y/Z, T = x*y/Z  
struct Ed25519 {
    x: GF25519,
    y: GF25519,
    t: GF25519,
    z: GF25519,
}

impl Ed25519 {
    /// the order of the finite field used for the curve eg. 2^255 - 19
    const PRIME: U256 = GF25519Modulo::MODULUS;

    const ORDER: U256 =
        U256::from_be_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

    /// the d coefficient of the curve eg. -121665/121666
    const COEFF: GF25519 = div(&residue!(121665).neg(), &residue!(121666));
    /// returns the element one in the finite field of the curve
    const ONE: GF25519 = GF25519::ONE;

    /// the neutral element for addition for the curve eg. the point (0,1)
    const NEUTRAL: Ed25519 = Ed25519 {
        x: GF25519::ZERO,
        y: GF25519::ONE,
        t: GF25519::ZERO,
        z: GF25519::ONE,
    };

    const TURNTOSQRT: GF25519 = residue!(2).pow(
        &Ed25519::PRIME
            .wrapping_sub(&U256::ONE)
            .wrapping_div(&U256::from_u8(4)),
    );

    const CANDSQRT: U256 = Ed25519::PRIME
        .wrapping_sub(&U256::from_u8(5))
        .wrapping_div(&U256::from_u8(8));

    const BASE: Ed25519 = Ed25519::from_y(div(&residue!(4), &residue!(5)), true).unwrap();

    #[inline]
    /// Check if the coordinate is "positive" or not. In this context positive is defined to be a coordinate, which is even.
    const fn is_positive(coord: &GF25519) -> bool {
        !coord.retrieve().bit_vartime(0)
    }

    #[inline]
    /// Auxillary function for `from_y`
    const fn return_positive(coord1: GF25519, coord2: GF25519) -> GF25519 {
        if Ed25519::is_positive(&coord1) {
            coord1
        } else {
            coord2
        }
    }

    #[inline]
    /// Auxillary function for `from_y`
    const fn return_negative(coord1: GF25519, coord2: GF25519) -> GF25519 {
        if Ed25519::is_positive(&coord1) {
            coord2
        } else {
            coord1
        }
    }

    #[inline]
    /// Make a curve point on Ed25519 using the Y-coordinate of the point and whether is it positive or not
    const fn from_y(y: GF25519, pos: bool) -> Option<Ed25519> {
        let u: GF25519 = y.square().sub(&Ed25519::ONE);
        let v: GF25519 = (Ed25519::COEFF.mul(&y.square())).add(&Ed25519::ONE);
        let cand_x: GF25519 = u
            .mul(&v.pow(&U256::from_u8(3)))
            .mul(&(u.mul(&v.pow(&U256::from_u8(7)))).pow(&Ed25519::CANDSQRT));
        let x = match cand_x {
            real_sqrt if ct_eq(&v.mul(&real_sqrt.square()), &u) => real_sqrt,
            false_root if ct_eq(&v.mul(&false_root.square()), &u.neg()) => {
                false_root.mul(&Ed25519::TURNTOSQRT)
            }
            _ => return None,
        };
        match x {
            r if pos && ct_eq(&r, &GF25519::ZERO) => None,
            r if pos => Ed25519::from_affine(Ed25519::return_positive(r, r.neg()), y),
            r if !pos => Ed25519::from_affine(Ed25519::return_negative(r, r.neg()), y),
            _ => None,
        }
    }

    #[inline]
    /// Checks whether the given point is on the Ed25519 curve
    const fn is_point_on_curve(x: &GF25519, y: &GF25519) -> bool {
        let x_square: GF25519 = x.square();
        let y_square: GF25519 = y.square();
        ct_eq(
            &(x_square).neg().add(&y_square),
            &(x_square.mul(&y_square).mul(&Ed25519::COEFF)).add(&Ed25519::ONE),
        )
    }

    #[inline]
    /// Constructs a point on the elliptic curve
    const fn from_affine(x: GF25519, y: GF25519) -> Option<Ed25519> {
        match Ed25519::is_point_on_curve(&x, &y) {
            false => None,
            true => Some(Ed25519 {
                x,
                y,
                t: x.mul(&y),
                z: GF25519::ONE,
            }),
        }
    }

    #[inline]
    const fn as_affine(&self) -> (GF25519, GF25519) {
        (self.x.mul(&invert(&self.z)), self.y.mul(&invert(&self.z)))
    }

    const fn from_hex(input_hex: &str) -> Option<Ed25519> {
        Ed25519::from_byte_array(match const_decode_to_array(input_hex.as_bytes()) {
            Ok(yaas) => yaas,
            Err(_) => panic!("expected hex digits but got something else"),
        })
    }

    fn to_hex(self) -> String {
        const_hex::const_encode::<32, false>(&self.to_byte_array())
            .as_str()
            .to_owned()
    }

    fn to_int_le(self) -> U256 {
        U256::from_le_bytes(self.to_byte_array())
    }

    fn from_int_le(num: U256) -> Option<Ed25519> {
        Ed25519::from_byte_array(num.to_le_bytes())
    }

    #[inline]
    fn to_byte_array(self) -> [u8; 32] {
        let (x, y) = self.as_affine();
        let mut y_bytes: [u8; 32] = y.retrieve().to_le_bytes();
        let x_least: u8 = u8::from(x.retrieve().bit_vartime(0));
        y_bytes[31] |= x_least.reverse_bits();
        y_bytes
    }

    #[inline]
    const fn from_byte_array(bytes: [u8; 32]) -> Option<Ed25519> {
        let mut y = U256::from_le_slice(&bytes);
        let pos = !y.bit_vartime(255);
        y = y.wrapping_and(&(U256::ONE.shl(255)).not());
        if ct_gt(&y, &Ed25519::PRIME) {
            None
        } else {
            Ed25519::from_y(GF25519::new(&y), pos)
        }
    }

    #[inline]
    const fn double(&self) -> Ed25519 {
        let Ed25519 { x, y, t: _t, z } = self;

        let A: GF25519 = x.square(); // A = X1^2,
        let B: GF25519 = y.square(); // B = Y1^2
        let C: GF25519 = residue!(2).mul(&z.square()); // C = 2*Z1^2
        let D: GF25519 = A.neg(); // D = a*A
        let E: GF25519 = ((x.add(y)).square()).sub(&A).sub(&B); // E = (X1+Y1)^2-A-B
        let G: GF25519 = D.add(&B); // G = D+B
        let F: GF25519 = G.sub(&C); // F = G-C
        let H: GF25519 = D.sub(&B); // H = D-B

        let x3 = E.mul(&F);
        let y3 = G.mul(&H);
        let t3 = E.mul(&H);
        let z3 = F.mul(&G);
        Ed25519 {
            x: x3,
            y: y3,
            t: t3,
            z: z3,
        }
    }

    #[inline]
    const fn neg(&self) -> Self {
        Ed25519 {
            x: self.x.neg(),
            y: self.y,
            t: self.t.neg(),
            z: self.z,
        }
    }

    #[inline]
    const fn add(&self, rhs: &Self) -> Self {
        let Ed25519 {
            x: x1,
            y: y1,
            t: t1,
            z: z1,
        } = self;

        let Ed25519 {
            x: x2,
            y: y2,
            t: t2,
            z: z2,
        } = rhs;

        let k: GF25519 = residue!(2).mul(&Ed25519::COEFF);

        let A: GF25519 = (y1.sub(x1)).mul(&y2.sub(x2));
        let B: GF25519 = (y1.add(x1)).mul(&y2.add(x2));
        let C: GF25519 = k.mul(t1).mul(t2);
        let D: GF25519 = residue!(2).mul(z1).mul(z2);
        let E: GF25519 = B.sub(&A);
        let F: GF25519 = D.sub(&C);
        let G: GF25519 = D.add(&C);
        let H: GF25519 = B.add(&A);

        Ed25519 {
            x: E.mul(&F),
            y: G.mul(&H),
            t: E.mul(&H),
            z: F.mul(&G),
        }
    }

    #[inline]
    /// Montgomery ladder multiplication for curve points
    const fn mul<const ULIMBS: usize>(&self, s: Uint<ULIMBS>) -> Ed25519 {
        let mut r0 = Ed25519::NEUTRAL;
        let mut r1 = *self;
        let mut i = 64 * ULIMBS - 1;
        let mut is_zero: bool = false;
        while i > 0 || is_zero {
            if s.bit_vartime(i) {
                r0 = r0.add(&r1);
                r1 = r1.double();
            } else {
                r1 = r0.add(&r1);
                r0 = r0.double();
            }

            if i == 1 {
                is_zero = true;
                i = 0;
            } else if is_zero {
                is_zero = false;
            } else {
                i -= 1;
            }
        }
        r0 // r0 = P * s
    }
}

impl PartialEq for Ed25519 {
    fn eq(&self, other: &Self) -> bool {
        self.as_affine() == other.as_affine()
    }
}
/// Generate a private key for Ed25519
#[inline]
pub fn generate_private_key() -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut key);
    key
}

/// Auxillary function for signing and verifying when converting between U512 and U256
fn le_int_from_byte_mod_order(input: [u8; 64]) -> U256 {
    U512::from_le_bytes(input)
        .rem(&NonZero::new(Ed25519::ORDER.mul(&U256::ONE)).unwrap())
        .split()
        .1
}

/// Sign a message using the Ed25519 digital signature algorithm and generate a public key with the given private key.
pub fn Ed25519_sign_gen_pub_key(message: &[u8], private_key: [u8; 32]) -> ([u8; 64], [u8; 32]) {
    // Generate keys
    let private_hash = sha_512(&private_key);
    let mut s_bytes: Vec<u8> = private_hash.into_iter().take(32).collect();
    s_bytes[0] &= 0b11111000;
    s_bytes[31] &= 0b01111111;
    s_bytes[31] |= 0b01000000;
    let s: U256 = U256::from_le_bytes(s_bytes.try_into().unwrap());
    let base = Ed25519::BASE;
    let public_key: [u8; 32] = base.mul(s).to_byte_array();

    // Sign message
    let prefix: Vec<u8> = private_hash.into_iter().skip(32).collect();
    let r: U256 = le_int_from_byte_mod_order(sha_512(&[&prefix, message].concat()));
    let R: [u8; 32] = base.mul(r).to_byte_array();
    let k: U256 = le_int_from_byte_mod_order(sha_512(&[&R, &public_key, message].concat()));
    let S = le_int_from_byte_mod_order((k.mul(&s)).to_le_bytes()).add_mod(&r, &Ed25519::ORDER);

    (
        [R, S.to_le_bytes()].concat().try_into().unwrap(),
        public_key,
    )
}

pub fn Ed25519_sign_with_keys(
    message: &[u8],
    private_key: [u8; 32],
    public_key: [u8; 32],
) -> [u8; 64] {
    let private_hash = sha_512(&private_key);
    let mut s_bytes: Vec<u8> = private_hash.into_iter().take(32).collect();
    s_bytes[0] &= 0b11111000;
    s_bytes[31] &= 0b01111111;
    s_bytes[31] |= 0b01000000;
    let s: U256 = U256::from_le_bytes(s_bytes.try_into().unwrap());
    let base = Ed25519::BASE;

    // Sign message
    let prefix: Vec<u8> = private_hash.into_iter().skip(32).collect();
    let r: U256 = le_int_from_byte_mod_order(sha_512(&[&prefix, message].concat()));
    let R: [u8; 32] = base.mul(r).to_byte_array();
    let k: U256 = le_int_from_byte_mod_order(sha_512(&[&R, &public_key, message].concat()));
    let S = le_int_from_byte_mod_order((k.mul(&s)).to_le_bytes()).add_mod(&r, &Ed25519::ORDER);
    [R, S.to_le_bytes()].concat().try_into().unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationError {
    BadSignature,
    BadPublicKey,
    SignatureNotMatchMessage,
}

pub fn Ed25519_verify_sign(
    message: &[u8],
    signature: [u8; 64],
    public_key: [u8; 32],
) -> Result<(), VerificationError> {
    let (r_bytes, s_bytes) = signature.split_at(32);
    let R: Ed25519 = match Ed25519::from_byte_array(r_bytes.try_into().unwrap()) {
        // Will always be [u8; 32]
        Some(a) => a,
        None => return Err(VerificationError::BadSignature),
    };
    let S: U256 = U256::from_le_bytes(s_bytes.try_into().unwrap()); // Will always be [u8; 32]

    let A = match Ed25519::from_byte_array(public_key) {
        Some(a) => a,
        None => return Err(VerificationError::BadPublicKey),
    };

    let k = U512::from_le_bytes(sha_512(
        &[&R.to_byte_array(), &A.to_byte_array(), message].concat(),
    ));

    let base = Ed25519::BASE;
    match base.mul(S) == R.add(&A.mul(k)) {
        true => Ok(()),
        false => Err(VerificationError::SignatureNotMatchMessage),
    }
}

/*




                UNIT TESTS





*/
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sqrt_test() {
        let qr1: GF25519 = residue!(4);
        let expected_roots: [Option<(GF25519, GF25519)>; 2] = [
            Some((residue!(2), residue!(2).neg())),
            Some((residue!(2).neg(), residue!(2))),
        ];
        assert!(expected_roots.contains(&sqrt(&qr1)));

        let qr2: GF25519 = residue!(9);
        let expected_roots: [Option<(GF25519, GF25519)>; 2] = [
            Some((residue!(3), residue!(3).neg())),
            Some((residue!(3).neg(), residue!(3))),
        ];
        assert!(expected_roots.contains(&sqrt(&qr2)));

        let qr3: GF25519 = residue!(16);
        let expected_roots: [Option<(GF25519, GF25519)>; 2] = [
            Some((residue!(4), residue!(4).neg())),
            Some((residue!(4).neg(), residue!(4))),
        ];
        assert!(expected_roots.contains(&sqrt(&qr3)));

        let qr4: GF25519 = residue!(13);

        assert_eq!(sqrt(&qr4), None);
    }

    #[test]
    fn ed25519_base_point_test() {
        std::env::set_var("RUST_BACKTRACE", "1");
        let base = Ed25519::BASE;
        let expected_x =
            U256::from_be_hex("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A");
        let expected_y =
            U256::from_be_hex("6666666666666666666666666666666666666666666666666666666666666658");

        let hex_point =
            Ed25519::from_hex("5866666666666666666666666666666666666666666666666666666666666666")
                .unwrap();

        assert_eq!(base.x.retrieve(), expected_x);
        assert_eq!(base.y.retrieve(), expected_y);
        assert_eq!(hex_point, base);
        assert_eq!(base, Ed25519::from_hex(&base.to_hex()).unwrap());
    }

    #[test]
    fn ed25519_multiplication_test() {
        let base: Ed25519 = Ed25519::BASE;
        let neutral: Ed25519 = Ed25519::NEUTRAL;

        assert_eq!(neutral.double(), neutral);

        let base2 = base.mul(U256::from_u8(2));
        let base_double = base.double();
        assert_eq!(base2.as_affine(), base_double.as_affine());
        assert_eq!(base2.as_affine(), base.add(&base).as_affine());
        let expected2_x =
            U256::from_be_hex("36AB384C9F5A046C3D043B7D1833E7AC080D8E4515D7A45F83C5A14E2843CE0E");
        let expected2_y =
            U256::from_be_hex("2260CDF3092329C21DA25EE8C9A21F5697390F51643851560E5F46AE6AF8A3C9");
        assert_eq!(base2.as_affine().0.retrieve(), expected2_x);
        assert_eq!(base2.as_affine().1.retrieve(), expected2_y);

        let base3 = base.mul(U256::from_u8(3));
        let expected3_x =
            U256::from_be_hex("67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25c");
        let expected3_y =
            U256::from_be_hex("1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4");

        assert_eq!(base3.as_affine().0.retrieve(), expected3_x);
        assert_eq!(base3.as_affine().1.retrieve(), expected3_y);

        let base5 = base.mul(U256::from_u8(5));
        let expected5_x =
            U256::from_be_hex("49FDA73EADE3587BFCEF7CF7D12DA5DE5C2819F93E1BE1A591409CC0322EF233");
        let expected5_y =
            U256::from_be_hex("5F4825B298FEAE6FE02C6E148992466631282ECA89430B5D10D21F83D676C8ED");
        assert_eq!(base5.as_affine().0.retrieve(), expected5_x);
        assert_eq!(base5.as_affine().1.retrieve(), expected5_y);

        let a =
            U256::from_le_hex("12581e70a192aeb9ac1411b36d11fc06393db55998190491c063807a6b4d730d");
        let basea = base.mul(a);
        let expecteda_x =
            U256::from_be_hex("67CEBF8191EECC2A58EA37EB2BC3242685BCDED15E5A510389B769E7BB8020C3");
        let expecteda_y =
            U256::from_be_hex("608105B6F38F15A032D1B2B1C090A3F3A687185BA5A3E41097E56D930952E314");
        assert_eq!(basea.as_affine().0.retrieve(), expecteda_x);
        assert_eq!(basea.as_affine().1.retrieve(), expecteda_y);

        let b =
            U256::from_le_hex("0c2340b974bebfb9cb3f14e991bca432b57fb33f7c4d79e15f64209076afcd00");
        let baseb = base.mul(b);
        let expectedb_x =
            U256::from_be_hex("6A5C71962B9904C8DAC0CC1040FDFC0674C6F46E27A2B199DBC90A1171FF37EA");
        let expectedb_y =
            U256::from_be_hex("1D3F41A4374F8151F27B19F7C995EB7FD37292758BAD347805B95E5D57CCA4CC");
        assert_eq!(baseb.as_affine().0.retrieve(), expectedb_x);
        assert_eq!(baseb.as_affine().1.retrieve(), expectedb_y);
    }

    #[test]
    fn Ed25519_test() {
        let private_key1: [u8; 32] = const_decode_to_array(
            b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap();

        let expected_pub_key1: [u8; 32] = const_decode_to_array(
            b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();

        let message1 = b"";
        let (signature1, public_key1) = Ed25519_sign_gen_pub_key(message1, private_key1);

        let expected_sign1: [u8; 64] = const_decode_to_array(b"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();

        assert_eq!(public_key1, expected_pub_key1);
        assert_eq!(signature1, expected_sign1);
        assert_eq!(
            Ed25519_verify_sign(message1, signature1, public_key1),
            Ok(())
        );

        let private_key2: [u8; 32] = const_decode_to_array(
            b"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        )
        .unwrap();
        let expected_pub_key2: [u8; 32] = const_decode_to_array(
            b"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        )
        .unwrap();

        let message2 = b"r";
        let expected_sign2: [u8; 64] = const_decode_to_array(
        b"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    )
    .unwrap();
        let (signature2, public_key2) = Ed25519_sign_gen_pub_key(message2, private_key2);
        assert_eq!(public_key2, expected_pub_key2);
        assert_eq!(signature2, expected_sign2);
        assert_eq!(
            Ed25519_verify_sign(message2, signature2, public_key2),
            Ok(())
        );

        let private_key3: [u8; 32] = const_decode_to_array(
            b"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        )
        .unwrap();
        let expected_pub_key3: [u8; 32] = const_decode_to_array(
            b"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        )
        .unwrap();
        let expected_sign3: [u8; 64] = const_decode_to_array(b"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a").unwrap();
        let message3: [u8; 2] = [0xaf, 0x82];
        let (signature3, public_key3) = Ed25519_sign_gen_pub_key(&message3, private_key3);
        assert_eq!(expected_pub_key3, public_key3);
        assert_eq!(expected_sign3, signature3);
        assert_eq!(
            Ed25519_verify_sign(&message3, signature3, public_key3),
            Ok(())
        );
    }
}
