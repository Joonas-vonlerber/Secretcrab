#![allow(dead_code, non_snake_case)]
#![feature(slice_as_chunks, array_zip, slice_flatten, iter_collect_into)]

pub mod Hash;
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
    use crate::Hash::SHA::{sha_1, sha_256, sha_3_244, sha_512, sha_512_to_244, sha_512_to_256};
    use crate::RSA::*;
    use rustc_ser::hex::ToHex;
    use std::env;
    #[test]
    fn RSA_test() {
        env::set_var("RUST_BACKTRACE", "1");
        let RSAkeypair {
            public_key,
            private_key,
            modulo,
        } = generate_keys_modulo(256);

        let msg = "Hello, World!";
        let encrypted_message = use_key(msg.as_bytes(), &public_key, &modulo);
        let decrypted_message = use_key(&encrypted_message, &private_key, &modulo);
        assert_eq!(String::from_utf8(decrypted_message).unwrap(), msg);
    }
    #[test]
    fn sha1_test() {
        env::set_var("RUST_BACKTRACE", "1");
        let lol_hash = sha_1(b"lol").as_slice().to_hex();
        assert_eq!(
            lol_hash,
            "403926033d001b5279df37cbbe5287b7c7c267fa".to_owned()
        );
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
    #[test]
    fn sha_256_test() {
        let Hello_hash = sha_256(b"Hello").as_slice().to_hex();
        assert_eq!(
            Hello_hash,
            "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969".to_owned()
        );
        let lazy_dog = sha_256(b"The quick brown fox jumps over the lazy dog")
            .as_slice()
            .to_hex();
        assert_eq!(
            lazy_dog,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_owned()
        );
        let lazy_cog = sha_256(b"The quick brown fox jumps over the lazy cog")
            .as_slice()
            .to_hex();
        assert_eq!(
            lazy_cog,
            "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be".to_owned()
        );
    }
    #[test]
    fn sha_512_test() {
        let hello_hash = sha_512(b"Hello").as_slice().to_hex();
        assert_eq!(hello_hash, "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315".to_owned());
        let lazy_dog = sha_512(b"The quick brown fox jumps over the lazy dog")
            .as_slice()
            .to_hex();
        assert_eq!(
            lazy_dog,
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6".to_owned()
        );
        let lazy_cog = sha_512(b"The quick brown fox jumps over the lazy cog")
            .as_slice()
            .to_hex();
        assert_eq!(
            lazy_cog,
            "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045".to_owned()
        );
    }
    #[test]
    fn sha_512_to_t_test() {
        let hello_hash_244 = sha_512_to_244(b"Hello").as_slice().to_hex();
        assert_eq!(
            hello_hash_244,
            "0d075258abfd1f8b81fc0a5207a1aa5cc82eb287720b1f849b862235".to_owned()
        );
        let hello_hash_256 = sha_512_to_256(b"Hello").as_slice().to_hex();
        assert_eq!(
            hello_hash_256,
            "7e75b18b88d2cb8be95b05ec611e54e2460408a2dcf858f945686446c9d07aac".to_owned()
        );
    }

    #[test]
    fn sha_3_224_test() {
        let hello_hash_224 = sha_3_244(b"Hello").to_hex();
        assert_eq!(
            hello_hash_224,
            "4cf679344af02c2b89e4a902f939f4608bcac0fbf81511da13d7d9b9".to_owned()
        );
    }
}
