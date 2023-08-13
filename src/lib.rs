#![allow(dead_code, non_snake_case)]

pub mod Hash {
    fn sha_1_constants(i: usize, b: u32, c: u32, d: u32) -> (u32, u32) {
        match i {
            i if (0..=19).contains(&i) => (((b & c) | ((!b) & d)), 0x5A827999u32), // (b and c) or ((not b) and d)
            i if (20..=39).contains(&i) => ((b ^ c ^ d), 0x6ED9EBA1u32),           // b xor c xor d
            i if (40..=59).contains(&i) => (((b & c) | (b & d) | (c & d)), 0x8F1BBCDCu32), // (b and c) or (b and d) or (c and d)
            i if (60..=79).contains(&i) => ((b ^ c ^ d), 0xCA62C1D6u32), // b xor c xor d
            _ => unreachable!("shouldn't go that high"),
        }
    }

    pub fn sha_1(input: &[u8]) -> [u8; 20] {
        let mut h0: u32 = 0x67452301u32;
        let mut h1: u32 = 0xEFCDAB89u32;
        let mut h2: u32 = 0x98BADCFEu32;
        let mut h3: u32 = 0x10325476u32;
        let mut h4: u32 = 0xC3D2E1F0u32;
        let mut a: u32;
        let mut b: u32;
        let mut c: u32;
        let mut d: u32;
        let mut e: u32;
        let lenght = input.len();
        const USIZE_LEN: usize = (usize::BITS as usize) / 8; // will not fail, USIZE_LEN is value 64 or 32, which fit inside of usize
        let padding_needed = match lenght % 64 {
            x if x > 64 - USIZE_LEN => 128 - x - USIZE_LEN - 1,
            x => 64 - USIZE_LEN - x - 1,
        };
        let padding_bits = [0x00u8].repeat(padding_needed);
        let message = [
            input,
            [0x80u8].as_slice(),
            padding_bits.as_slice(),
            (lenght * 8).to_be_bytes().as_slice(),
        ]
        .concat();
        assert_eq!(message.len() % 64, 0);

        for chunk in message.chunks(64) {
            // chunks are always size of 64
            a = h0;
            b = h1;
            c = h2;
            d = h3;
            e = h4;
            let mut words: Vec<u32> = chunk
                .chunks(4)
                .map(|word| u32::from_be_bytes(word.try_into().unwrap())) // will not fail because chunk_size == 4
                .collect();
            assert_eq!(words.len(), 16);
            words.reserve_exact(64);
            (16..80).for_each(|i| {
                words.push(
                    (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1),
                )
            });
            assert_eq!(words.len(), 80);
            for (i, w) in words.iter().enumerate() {
                let (f, k) = sha_1_constants(i, b, c, d);
                (a, b, c, d, e) = (
                    a.rotate_left(5)
                        .wrapping_add(f)
                        .wrapping_add(e)
                        .wrapping_add(k)
                        .wrapping_add(*w),
                    a,
                    b.rotate_left(30),
                    c,
                    d,
                );
            }
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }
        [
            h0.to_be_bytes(),
            h1.to_be_bytes(),
            h2.to_be_bytes(),
            h3.to_be_bytes(),
            h4.to_be_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap()
    }
}
pub mod RSA {

    use num::{bigint::RandBigInt, BigInt, BigUint, Integer, One, Zero};
    use rand::prelude::*;
    #[derive(Debug, PartialEq)]
    pub struct RSAkeypair {
        pub public_key: Vec<u8>,
        pub private_key: Vec<u8>,
        pub modulo: Vec<u8>,
    }

    // pub fn write_to_file(keypair: &RSAkeypair) -> io::Result<()> {
    //     // I could create a ssh rsa key in the correct format but don't want to be responsible for errors :DD
    //     let RSAkeypair {
    //         public_key,
    //         private_key,
    //         modulo,
    //     } = keypair;
    //     let modulo_bytes = modulo.to_bytes_be();
    //     let public_bytes = public_key.to_bytes_be();
    // TODO if i wanna even do it :D
    // }

    pub fn use_key(msg: &[u8], key: &[u8], modulo: &[u8]) -> Vec<u8> {
        let msg_int = BigUint::from_bytes_be(msg);
        let key_int = BigUint::from_bytes_be(key);
        let modulo_int = BigUint::from_bytes_be(modulo);
        msg_int.modpow(&key_int, &modulo_int).to_bytes_be()
    }

    pub fn generate_keys_modulo(bits: u64) -> RSAkeypair {
        let p = get_large_prime(bits);
        let q = get_large_prime(bits);
        let modulo = (&p * &q).to_bytes_be();
        let lambdan = (p - 1u32).lcm(&(&q - 1u32));
        let public_key = BigUint::from(65537u32);
        assert_ne!(&lambdan % &public_key, BigUint::zero());
        let private_key = BigInt::from(public_key.clone())
            .extended_gcd(&BigInt::from(lambdan.clone()))
            .x;

        RSAkeypair {
            public_key: public_key.to_bytes_be(),
            private_key: match private_key > BigInt::zero() {
                true => BigUint::try_from(private_key).unwrap().to_bytes_be(), // this shouldn't fail
                false => BigUint::try_from(private_key + BigInt::from(lambdan))
                    .unwrap()
                    .to_bytes_be(),
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
        random_number = rng.gen_biguint(n);
        random_number.set_bit(n - 1, true);
        while low_level_primes.iter().any(|divisor| {
            &random_number % divisor == BigUint::zero() && divisor * divisor <= random_number
        }) {
            random_number = rng.gen_biguint(n);
            random_number.set_bit(n - 1, true);
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

#[cfg(test)]
mod tests {
    extern crate rustc_serialize as rustc_ser;
    use crate::Hash::sha_1;
    use rustc_ser::hex::ToHex;
    use std::env;
    #[test]
    fn hash_test() {
        env::set_var("RUST_BACKTRACE", "1");
        let empty = sha_1(b"lol").as_slice().to_hex();
        assert_eq!(empty, "403926033d001b5279df37cbbe5287b7c7c267fa".to_owned());
        let lazy_dog = sha_1(b"The quick brown fox jumps over the lazy dog")
            .as_slice()
            .to_hex();
        assert_eq!(
            lazy_dog,
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_owned()
        );
        let lazy_cog = sha_1(b"The quick brown fox jumps over the lazy cog")
            .as_slice()
            .to_hex();
        assert_eq!(
            lazy_cog,
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3".to_owned()
        );
    }
}
