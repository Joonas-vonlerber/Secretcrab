use super::SHA3::*;
use super::SHA2::*;
use super::SHA1::*;
use const_hex::encode;
use std::env;

#[test]
fn sha1_merkel_test() {
    env::set_var("RUST_BACKTRACE", "1");
    let lol_hash = encode(sha1(b"lol"));
    assert_eq!(
        lol_hash,
        "403926033d001b5279df37cbbe5287b7c7c267fa".to_owned()
    );
    let lazy_dog = encode(sha1(b"The quick brown fox jumps over the lazy dog").as_slice());
    assert_eq!(
        lazy_dog,
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_owned()
    );
    let lazy_cog = encode(sha1(b"The quick brown fox jumps over the lazy cog").as_slice());
    assert_eq!(
        lazy_cog,
        "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3".to_owned()
    );
}
#[test]
fn sha256_merkle_test() {
    let Hello_hash = encode(sha256(b"Hello").as_slice());
    assert_eq!(
        Hello_hash,
        "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969".to_owned()
    );
    let lazy_dog = encode(sha256(b"The quick brown fox jumps over the lazy dog").as_slice());
    assert_eq!(
        lazy_dog,
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_owned()
    );
    let lazy_cog = encode(sha256(b"The quick brown fox jumps over the lazy cog").as_slice());
    assert_eq!(
        lazy_cog,
        "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be".to_owned()
    );
}
#[test]
fn sha224_merkle_test() {
    let Hello_hash = encode(sha224(b"Hello").as_slice());
    assert_eq!(
        Hello_hash,
        "4149da18aa8bfc2b1e382c6c26556d01a92c261b6436dad5e3be3fcc".to_owned()
    );
    let lazy_dog = encode(sha224(b"The quick brown fox jumps over the lazy dog").as_slice());
    assert_eq!(
        lazy_dog,
        "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525".to_owned()
    );
    let lazy_cog = encode(sha224(b"The quick brown fox jumps over the lazy cog").as_slice());
    assert_eq!(
        lazy_cog,
        "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b".to_owned()
    );
}

#[test]
fn sha512_merkel_test() {
    let hello_hash = encode(sha512(b"Hello").as_slice());
    assert_eq!(hello_hash, "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315".to_owned());
    let lazy_dog = encode(sha512(b"The quick brown fox jumps over the lazy dog").as_slice());
    assert_eq!(
            lazy_dog,
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6".to_owned()
        );
    let lazy_cog = encode(sha512(b"The quick brown fox jumps over the lazy cog").as_slice());
    assert_eq!(
            lazy_cog,
            "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045".to_owned()
        );
}

#[test]
fn sha384_merkle_test() {
    let hello_hash = encode(sha384(b"Hello").as_slice());
    assert_eq!(hello_hash, "3519fe5ad2c596efe3e276a6f351b8fc0b03db861782490d45f7598ebd0ab5fd5520ed102f38c4a5ec834e98668035fc".to_owned());
    let lazy_dog = encode(sha384(b"The quick brown fox jumps over the lazy dog").as_slice());
    assert_eq!(
            lazy_dog,
            "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1".to_owned()
        );
    let lazy_cog = encode(sha384(b"The quick brown fox jumps over the lazy cog").as_slice());
    assert_eq!(
            lazy_cog,
            "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b".to_owned()
        );
}

#[test]
fn sha_512_to_t_merkle_test() {
    let hello_hash_244 = encode(sha512_to_224(b"Hello").as_slice());
    assert_eq!(
        hello_hash_244,
        "0d075258abfd1f8b81fc0a5207a1aa5cc82eb287720b1f849b862235".to_owned()
    );
    let hello_hash_256 = encode(sha512_to_256(b"Hello").as_slice());
    assert_eq!(
        hello_hash_256,
        "7e75b18b88d2cb8be95b05ec611e54e2460408a2dcf858f945686446c9d07aac".to_owned()
    );
}

#[test]
fn sha_3_224_test() {
    let hello_hash_224 = encode(sha_3_244(b"Hello"));
    assert_eq!(
        hello_hash_224,
        "4cf679344af02c2b89e4a902f939f4608bcac0fbf81511da13d7d9b9".to_owned()
    );
}

#[test]
fn sha_3_256_test() {
    let hello_hash_256 = encode(sha_3_256(b"Hello"));
    assert_eq!(
        hello_hash_256,
        "8ca66ee6b2fe4bb928a8e3cd2f508de4119c0895f22e011117e22cf9b13de7ef"
    )
}

#[test]
fn sha_3_384_test() {
    let hello_hash_384 = encode(sha_3_384(b"Hello"));
    assert_eq!(
        hello_hash_384,
        "df7e26e3d067579481501057c43aea61035c8ffdf12d9ae427ef4038ad7c13266a11c0a3896adef37ad1bc85a2b5bdac"
    )
}

#[test]
fn sha_3_512_test() {
    let hello_hash_512 = encode(sha_3_512(b"Hello"));
    assert_eq!(
        hello_hash_512,
        "0b8a44ac991e2b263e8623cfbeefc1cffe8c1c0de57b3e2bf1673b4f35e660e89abd18afb7ac93cf215eba36dd1af67698d6c9ca3fdaaf734ffc4bd5a8e34627"
    )
}
