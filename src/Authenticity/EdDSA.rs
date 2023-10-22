use crate::Confidentiality::RSA::miller_rabin_test;
use num::{
    bigint::{RandBigInt, ToBigInt},
    integer::ExtendedGcd,
    BigInt, BigUint, Integer, Zero,
};
use rand::prelude::*;
use std::ops::*;

macro_rules! implement_arith {
    ($arith_trait: tt, $fun: tt, $alias: tt, $tyyppi: ty) => {
        impl $arith_trait<&$tyyppi> for $tyyppi {
            type Output = $tyyppi;
            fn $fun(self, rhs: &$tyyppi) -> Self::Output {
                self $alias rhs.clone()
            }
        }

        impl $arith_trait<$tyyppi> for &$tyyppi {
            type Output = $tyyppi;
            fn $fun(self, rhs: $tyyppi) -> Self::Output {
                self.clone() $alias rhs
            }
        }

        impl $arith_trait<&$tyyppi> for &$tyyppi {
            type Output = $tyyppi;
            fn $fun(self, rhs: &$tyyppi) -> Self::Output {
                self.clone() $alias rhs.clone()
            }
        }
    };
}

fn modulos_same(modulo1: &BigUint, modulo2: &BigUint) {
    assert_eq!(
        modulo1, modulo2,
        "Finite fields must have the same order {} != {}",
        modulo1, modulo2
    )
}

#[derive(Debug, PartialEq, Clone)]
struct FiniteField {
    // Could transform to montgomery form to make multiplication faster??
    val: BigUint,
    order: BigUint,
}

impl FiniteField {
    fn zero(modulo: &BigUint) -> Self {
        FiniteField {
            val: BigUint::zero(),
            order: modulo.clone(),
        }
    }

    fn one(modulo: &BigUint) -> Self {
        FiniteField {
            val: BigUint::from(1u32),
            order: modulo.clone(),
        }
    }

    fn maybe_mod(&mut self) {
        //    FOR FUTURE OPTIMIZATION:      pseudo-mersenne prime reduction
        match self.val >= self.order {
            true => self.val %= &self.order,
            false => (),
        }
    }

    fn new(value: BigUint, order: BigUint) -> FiniteField {
        FiniteField { val: value, order }
    }

    fn new_u32(value: u32, modulo: u32) -> FiniteField {
        FiniteField {
            val: BigUint::from(value),
            order: BigUint::from(modulo),
        }
    }
    fn pow(&self, exponent: &BigUint) -> FiniteField {
        FiniteField {
            val: self.val.modpow(exponent, &self.order), // thankfully modpow exists
            order: self.order.clone(),
        }
    }
    /// Calculation the legrende symbol for a prime field and **DOES NOT WORK FOR COMPOSITE FIELDS**<br>
    /// Output may be interpreted as true => 1 and false => -1
    fn legrende_symbol(&self) -> bool {
        match self.is_prime_field() {
            true => {
                let legrende =
                    self.pow(&((&self.order - BigUint::from(1u32)) / BigUint::from(2u32)));
                legrende.val == BigUint::from(1u32)
            }
            false => unimplemented!("For composite fields the legrende symbol/sqrt is very difficult :D have not implemented it yet, launch a git issue"),
        }
    }
    fn is_prime_field(&self) -> bool {
        is_prime(&self.order)
    }

    fn is_quadratic_residue(&self) -> bool {
        self.legrende_symbol()
    }

    fn sqrt(&self) -> Option<(Self, Self)> {
        match self.is_quadratic_residue() {
            true if &self.order % &BigUint::from(4u32) == BigUint::from(3u32) => {
                let root = self.pow(&((&self.order + BigUint::from(1u32)) / BigUint::from(4u32)));
                Some((root.clone(), -&root))
            }
            true => tonelli_Shanks(self), // slower algo than just exponenting
            false => None,
        }
    }
}

fn tonelli_Shanks(quad_residue: &FiniteField) -> Option<(FiniteField, FiniteField)> {
    assert!(quad_residue.is_prime_field() && quad_residue.is_quadratic_residue());
    let order = quad_residue.order.clone();
    // Factor modulo-1 into Q*2^S, where Q is odd
    let mut Q = &order - 1u32;
    let mut S: BigUint = BigUint::zero();
    while &Q % 2u32 == BigUint::zero() {
        Q >>= 1u32;
        S += 1u32;
    }
    // Find a non quadratic residue
    let mut rng = thread_rng();
    let mut non_residue: FiniteField = FiniteField {
        val: rng.gen_biguint_below(&order),
        order: order.clone(),
    };
    while non_residue.is_quadratic_residue() || non_residue.val == BigUint::zero() {
        non_residue.val = rng.gen_biguint_below(&order);
    }

    let mut M = S;
    let mut c = non_residue.pow(&Q);
    let mut t = quad_residue.pow(&Q);
    let mut R = quad_residue.pow(&((Q + 1u32) / 2u32));
    let mut i: BigUint = BigUint::zero();
    let mut b: FiniteField;
    let mut repeated_squared_t: FiniteField = t.clone();
    loop {
        // Do we return?
        if t.val == BigUint::zero() {
            return Some((
                FiniteField {
                    val: BigUint::zero(),
                    order: order.clone(),
                },
                FiniteField {
                    val: BigUint::zero(),
                    order,
                },
            ));
        } else if t.val == BigUint::from(1u32) {
            return Some((R.clone(), -R));
        }

        // Find i
        while repeated_squared_t.val != BigUint::from(1u32) {
            i += 1u32;
            repeated_squared_t = &repeated_squared_t * &repeated_squared_t;
        }
        if i == M {
            return None;
        }
        b = c.pow(&BigUint::from(2u32).modpow(&(&M - &i - 1u32), &order)); // c^(2^(M-i-1)), tän 2^fasfd vois tehä ainaki shiftauksella mut ku moduloooo :DDDD
        M = i.clone();
        c = b.pow(&BigUint::from(2u32));
        t = &t * &b.pow(&BigUint::from(2u32));
        R = &R * &b;

        i = BigUint::zero();
        repeated_squared_t = t.clone();
    }
}

impl Add<FiniteField> for FiniteField {
    type Output = FiniteField;
    fn add(self, rhs: FiniteField) -> Self::Output {
        modulos_same(&self.order, &rhs.order);
        let mut output = FiniteField {
            val: &self.val + &rhs.val,
            order: self.order,
        };
        output.maybe_mod();
        output
    }
}

implement_arith!(Add, add, +, FiniteField);

impl Sub<FiniteField> for FiniteField {
    type Output = FiniteField;
    fn sub(self, rhs: FiniteField) -> Self::Output {
        modulos_same(&self.order, &rhs.order);
        let difference: BigInt = self.val.to_bigint().unwrap() - rhs.val.to_bigint().unwrap();
        match difference {
            result if result < BigInt::zero() => FiniteField {
                val: (result + BigInt::from(self.order.clone()))
                    .try_into()
                    .unwrap(),
                order: self.order,
            },
            result => FiniteField {
                val: result.try_into().unwrap(),
                order: self.order,
            },
        }
    }
}

implement_arith!(Sub, sub, -, FiniteField);

impl Mul<FiniteField> for FiniteField {
    // This is super slowwww montgomery mult and other stuff?
    type Output = FiniteField;
    fn mul(self, rhs: FiniteField) -> Self::Output {
        modulos_same(&self.order, &rhs.order);
        let mut output = FiniteField {
            val: &self.val * &rhs.val,
            order: self.order,
        };
        output.maybe_mod();
        output
    }
}

implement_arith!(Mul, mul, *, FiniteField);

impl Div<FiniteField> for FiniteField {
    type Output = FiniteField;
    fn div(self, rhs: FiniteField) -> Self::Output {
        modulos_same(&self.order, &rhs.order);
        let rhs_modular_inverse = rhs
            .val
            .to_bigint()
            .unwrap()
            .extended_gcd(&rhs.order.to_bigint().unwrap())
            .x;
        let mut result = match rhs_modular_inverse > BigInt::zero() {
            true => FiniteField {
                val: &self.val * rhs_modular_inverse.to_biguint().unwrap(),
                order: self.order,
            },
            false => FiniteField {
                val: &self.val
                    * (rhs_modular_inverse + rhs.order.to_bigint().unwrap())
                        .to_biguint()
                        .unwrap(),
                order: self.order,
            },
        };
        result.maybe_mod();
        result
    }
}

implement_arith!(Div, div, /, FiniteField);

impl Neg for FiniteField {
    type Output = FiniteField;
    fn neg(self) -> Self::Output {
        FiniteField {
            val: &self.order - &self.val,
            order: self.order,
        }
    }
}

impl Neg for &FiniteField {
    type Output = FiniteField;
    fn neg(self) -> Self::Output {
        FiniteField {
            val: &self.order - &self.val,
            order: self.order.clone(),
        }
    }
}

/// First checks the divisibility for the first 70 primes after which we use the Miller Rabin. Should be very accurate :DD
/// but in the nature of heuristic methods false positives and false negatives are possible
fn is_prime(candidate: &BigUint) -> bool {
    let low_level_primes: [BigUint; 70] = [
        2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
        89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277,
        281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    ]
    .map(BigUint::from);
    let is_low_level = low_level_primes.contains(candidate);
    let check_low_level_divisibility = low_level_primes
        .iter()
        .any(|divisor| &(divisor * divisor) <= candidate && candidate % divisor == BigUint::zero());

    if !check_low_level_divisibility {
        is_low_level || miller_rabin_test(candidate) // somehow the miller rabin test cound'nt get some of the low level primes so this fixes the problem for now?? lets hope this doesn't backfire (forshadowing)
    } else {
        false
    }
}

#[derive(Debug, PartialEq, Clone)]
struct Ed25519 {
    // FOR FUTURE OPTIMIZATION:    Extended twisted edwards coordinates?? well defined in here https://eprint.iacr.org/2008/522.pdf
    x: FiniteField,
    y: FiniteField,
}

impl Ed25519 {
    /// Returns the order of the finite field used for the curve eg. 2^255 - 19
    fn prime() -> BigUint {
        BigUint::from(2u32).pow(255) - BigUint::from(19u32)
    }

    fn order() -> BigUint {
        BigUint::from(2u32).pow(252)
            + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap()
    }
    // returns the d coefficient of the curve eg. -121665/121666
    fn coeff() -> FiniteField {
        -(&FiniteField {
            val: BigUint::from(121665u32),
            order: Ed25519::prime(),
        } / &FiniteField {
            val: BigUint::from(121666u32),
            order: Ed25519::prime(),
        })
    }

    /// returns the element one in the finite field of the curve
    fn one() -> FiniteField {
        FiniteField::one(&Self::prime())
    }

    /// returns the neutral element for addition for the curve eg. the point (0,1)
    fn neutral() -> Self {
        Ed25519 {
            x: FiniteField::zero(&Self::prime()),
            y: FiniteField::one(&Self::prime()),
        }
    }

    /// Check if the coordinate is "positive" or not. In this context positive is defined to be a coordinate, which is even.
    fn is_positive(coord: &FiniteField) -> bool {
        coord.val.is_even()
    }

    /// Auxillary function for `from_y`
    fn return_positive(coord1: FiniteField, coord2: FiniteField) -> FiniteField {
        if Ed25519::is_positive(&coord1) {
            coord1
        } else {
            coord2
        }
    }

    /// Auxillary function for `from_y`
    fn return_negative(coord1: FiniteField, coord2: FiniteField) -> FiniteField {
        if Ed25519::is_positive(&coord1) {
            coord2
        } else {
            coord1
        }
    }

    /// Make a curve point on Ed25519 using the Y-coordinate of a point. Y coordinates modulo must be the Ed25519 fields order or 2^255 - 19
    /// or `Ed25519::prime()`
    ///
    /// ## Panics
    /// Will panic when the order of the finite field of y is incorrect: should be 2^255 - 19. You can create the value using `Ed25519::prime()`
    fn from_y(y: FiniteField, pos: bool) -> Option<Ed25519> {
        assert_eq!(y.order, Ed25519::prime(), "Cannot convert y-coordinate to Ed25519 due to y-coordinates field-order being different. It should be 2^255 - 19 but is {}", y.order);
        let x = ((&y * &y - Ed25519::one()) / (Ed25519::coeff() * &y * &y + Ed25519::one()))
            .sqrt()
            .map(|(root1, root2)| match pos {
                true => Ed25519::return_positive(root1, root2),
                false => Ed25519::return_negative(root1, root2),
            });
        x.map(|x| Ed25519 { x, y })
    }

    /// Checks whether the given point is on the Ed25519 curve
    ///
    /// ## Panics
    ///
    /// If the order of the fields used in the coordinates is incorrect: should be 2"255 - 19. You can create the value using `Ed25519::prime()`
    fn is_point_on_curve(x: &FiniteField, y: &FiniteField) -> bool {
        assert_eq!(
            x.order,
            Ed25519::prime(),
            "The order of x-coordinates field is incorrect: should be 2^255 - 19 but is {}",
            x.order
        );
        assert_eq!(
            y.order,
            Ed25519::prime(),
            "The order of y-coordinates field is incorrect: should be 2^255 - 19 but is {}",
            y.order
        );
        -(x * x) + (y * y) == Ed25519::one() + Ed25519::coeff() * (x * x) * (y * y)
    }

    /// Constructs a point on the elliptic curve
    fn new(x: FiniteField, y: FiniteField) -> Option<Ed25519> {
        assert_eq!(x.order, Ed25519::prime(), "Cannot construct an Ed22519 instance because the order of x-coordinates field is incorrect: should be 2^255 - 19 but is {}", x.order);
        assert_eq!(y.order, Ed25519::prime(), "Cannot construct an Ed22519 instance because the order of y-coordinates field is incorrect: should be 2^255 - 19 but is {}", y.order);
        match Ed25519::is_point_on_curve(&x, &y) {
            false => None,
            true => Some(Ed25519 { x, y }),
        }
    }

    fn double(self) -> Ed25519 {
        let Ed25519 { x, y } = self;
        let x_squared = &x * &x;
        let y_squared = &y * &y;
        Ed25519 {
            x: (&x * &y + &x * &y) / (&y_squared - &x_squared),
            y: (&y_squared + &x_squared)
                / ((Ed25519::one() + Ed25519::one()) - &y_squared + &x_squared),
        }
    }
}

impl Neg for &Ed25519 {
    type Output = Ed25519;
    fn neg(self) -> Self::Output {
        Ed25519 {
            x: -&self.x,
            y: self.y.clone(),
        }
    }
}

impl Neg for Ed25519 {
    type Output = Ed25519;
    fn neg(self) -> Self::Output {
        Ed25519 {
            x: -self.x,
            y: self.y,
        }
    }
}

impl Add<Ed25519> for Ed25519 {
    type Output = Ed25519;
    fn add(self, rhs: Ed25519) -> Self::Output {
        Ed25519 {
            x: (&self.x * &rhs.y + &rhs.x * &self.y)
                / (Ed25519::one() + Ed25519::coeff() * &self.x * &rhs.x * &self.y * &rhs.y),
            y: (&self.y * &rhs.y + &self.x * &rhs.x)
                / (Ed25519::one() - Ed25519::coeff() * self.x * rhs.x * self.y * rhs.y),
        }
    }
}

implement_arith!(Add, add, +, Ed25519);

impl Mul<Ed25519> for BigUint {
    type Output = Ed25519;
    fn mul(self, rhs: Ed25519) -> Self::Output {
        // shitty implementations could be better
        let mut acc = rhs.clone();
        let mut yaas = BigUint::zero();
        let yees = self - 1u32;
        while yaas < yees {
            acc = acc + &rhs;
            yaas += 1u32;
        }
        acc
    }
}

impl Mul<&Ed25519> for BigUint {
    type Output = Ed25519;
    fn mul(self, rhs: &Ed25519) -> Self::Output {
        self * rhs.clone()
    }
}

/*




                UNIT TESTS





*/

#[test]
fn FiniteField_test_small_number() {
    let Ff1: FiniteField = FiniteField::new_u32(12, 27);
    let Ff2: FiniteField = FiniteField::new_u32(22, 27);
    assert_eq!(&Ff1 - &Ff2, FiniteField::new_u32(17, 27));
    assert_eq!(&Ff1 * &Ff2, FiniteField::new_u32(21, 27));
    assert_eq!(&Ff1 / &Ff2, FiniteField::new_u32(3, 27));
    assert_eq!(&Ff1 + &Ff2, FiniteField::new_u32(7, 27));
}

#[test]
fn FiniteField_test_large_number() {
    let Ff1: FiniteField = FiniteField {
        val: BigUint::from(2u32).pow(255) + BigUint::from(1u32),
        order: Ed25519::prime(),
    };
    let Ff2: FiniteField = FiniteField {
        val: BigUint::from(2u32).pow(255),
        order: Ed25519::prime(),
    };
    assert_eq!(
        &Ff1 + &Ff2,
        FiniteField {
            val: BigUint::from(39u32),
            order: Ed25519::prime()
        }
    );
    assert_eq!(
        &Ff1 - &Ff2,
        FiniteField {
            val: BigUint::from(1u32),
            order: Ed25519::prime()
        }
    );
    assert_eq!(
        &Ff1 * &Ff2,
        FiniteField {
            val: BigUint::from(380u32),
            order: Ed25519::prime()
        }
    );
}

#[test]
fn is_prime_test() {
    let p1 = BigUint::from(4u32);
    assert!(!is_prime(&p1));
    let p2: BigUint = BigUint::from(65537u32);
    assert!(is_prime(&p2));
    let p3: BigUint = BigUint::from(53u32);
    assert!(is_prime(&p3));
    let n: BigUint = BigUint::from(51u32);
    assert!(!is_prime(&n));
}

#[test]
fn legrende_symbol_test() {
    let ff1: FiniteField = FiniteField::new_u32(3, 11);
    assert!(ff1.legrende_symbol());
    let ff2: FiniteField = FiniteField::new_u32(3, 13);
    assert!(ff2.legrende_symbol());
    let ff3: FiniteField = FiniteField::new_u32(6, 43);
    assert!(ff3.legrende_symbol());
    let ff4: FiniteField = FiniteField::new_u32(5, 53);
    assert!(!ff4.legrende_symbol());
    let minus_one_mod_four: FiniteField = -&FiniteField::new_u32(1u32, 17u32);
    assert!(minus_one_mod_four.legrende_symbol());
    let minus_three_mod_four: FiniteField = -&FiniteField::new_u32(1, 11);
    assert!(!minus_three_mod_four.legrende_symbol())
}

#[test]
fn sqrt_test() {
    let ff1: FiniteField = FiniteField::new_u32(15, 17);
    let expected1: [FiniteField; 2] = [FiniteField::new_u32(10, 17), FiniteField::new_u32(7, 17)];
    let sqrt1 = ff1.sqrt().expect("Hmm didn't find a square root for ff1");
    assert!(expected1.contains(&sqrt1.0) && expected1.contains(&sqrt1.1));

    let ff2: FiniteField = FiniteField::new_u32(38, 53);
    let expected2: [FiniteField; 2] = [FiniteField::new_u32(12, 53), FiniteField::new_u32(41, 53)];
    let sqrt2 = ff2.sqrt().expect("Hmm didn't find a square root for ff2");
    assert!(expected2.contains(&sqrt2.0) && expected2.contains(&sqrt2.1));

    let ff3: FiniteField = FiniteField::new_u32(12, 23);
    let expected3: [FiniteField; 2] = [FiniteField::new_u32(9, 23), FiniteField::new_u32(14, 23)];
    let sqrt3 = ff3.sqrt().expect("Hmm didn't find a square root for ff3");
    assert!(expected3.contains(&sqrt3.0) && expected3.contains(&sqrt3.1));

    let ff4: FiniteField = FiniteField::new_u32(5, 13);
    assert_eq!(ff4.sqrt(), None);
}

fn times(times: u32, val: u32) -> u32 {
    let mut acc = val;
    let mut yaas = 0;
    while yaas < times - 1 {
        acc += val;
        yaas += 1;
    }
    acc
}

#[test]
fn yaas() {
    assert_eq!(times(4, 15), 60);
}
