#![allow(dead_code)]

pub mod RSA {
    use num::{bigint::RandBigInt, BigInt, BigUint, Integer, One, Zero};
    use rand::prelude::*;
    pub struct RSAkeypair {
        pub public_key: BigUint,
        pub private_key: BigUint,
        pub modulo: BigUint,
    }

    pub fn encrypt(msg: &str, key: &BigUint, modulo: &BigUint) -> BigUint {
        let bytes = msg.as_bytes();
        let text_int = BigUint::from_bytes_be(bytes);
        text_int.modpow(key, modulo)
    }

    pub fn decrypt(
        encrypted_msg: &BigUint,
        key: &BigUint,
        modulo: &BigUint,
    ) -> Result<String, std::string::FromUtf8Error> {
        let text_int = encrypted_msg.modpow(key, modulo);
        let bytes = text_int.to_bytes_be();
        String::from_utf8(bytes)
    }

    pub fn generate_keys_modulo(bits: u64) -> RSAkeypair {
        let p = get_large_prime(bits);
        let q = get_large_prime(bits);
        let modulo = &p * &q;
        let lambdan = (p - 1u32).lcm(&(&q - 1u32));
        let public_key = BigUint::from(65537u32);
        assert_ne!(&lambdan % &public_key, BigUint::zero());
        let private_key = BigInt::from(public_key.clone())
            .extended_gcd(&BigInt::from(lambdan.clone()))
            .x;

        RSAkeypair {
            public_key,
            private_key: match private_key > BigInt::zero() {
                true => BigUint::try_from(private_key).unwrap(), // this shouldn't fail
                false => BigUint::try_from(private_key + BigInt::from(lambdan)).unwrap(),
            },
            modulo,
        }
    }

    fn create_low_level_prime(n: u64) -> BigUint {
        let mut rng = thread_rng();
        let mut random_number: BigUint;
        let low_level_primes: [BigUint; 70] = [
            2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
            83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
            179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
            271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
        ]
        .map(BigUint::from);
        loop {
            random_number = rng.gen_biguint(n);
            random_number.set_bit(random_number.bits(), true);
            if low_level_primes.iter().any(|divisor| {
                &random_number % divisor == BigUint::zero() && divisor * divisor <= random_number
            }) {
                continue;
            }
            break;
        }
        random_number
    }

    fn miller_rabin_test(candidate: &BigUint) -> bool {
        let mut rng = thread_rng();
        const NUMBER_OF_TRIALS: i32 = 20;
        let mut max_divisions_by_two: u32 = 0;
        let mut even_component: BigUint = candidate - 1u32;
        while &even_component % 2u32 == BigUint::zero() {
            even_component >>= 1;
            max_divisions_by_two += 1;
        }
        assert_eq!(
            2u32.pow(max_divisions_by_two) * &even_component,
            candidate - 1u32
        );
        !((0..NUMBER_OF_TRIALS)
            .map(|_| rng.gen_biguint_range(&(BigUint::one() + BigUint::one()), &(candidate + 1u32)))
            .any(|round_tester| {
                is_composite(
                    &round_tester,
                    &even_component,
                    candidate,
                    &max_divisions_by_two,
                )
            }))
    }
    fn is_composite(
        round_tester: &BigUint,
        even_component: &BigUint,
        candidate: &BigUint,
        max_divisions_by_two: &u32,
    ) -> bool {
        if round_tester.modpow(even_component, candidate) == BigUint::one() {
            false
        } else {
            !((0..*max_divisions_by_two).any(|i| {
                round_tester.modpow(&(even_component * (1u32 << i)), candidate) == candidate - 1u32
            }))
        }
    }

    fn get_large_prime(bits: u64) -> BigUint {
        let mut candidate = create_low_level_prime(bits);
        while !miller_rabin_test(&candidate) {
            candidate = create_low_level_prime(bits);
        }
        candidate
    }
}
