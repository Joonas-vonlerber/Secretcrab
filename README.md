# Secretcrab

A cryptographic suite made in pure Rust. Includes implementations for the SHA-family of hash functions.
Also includes encryption algorithms like RSA or AES.

## Implementation security

I cannot verify the security of my own implementations. For secure purposes I recommend using trusted implementations whenever possible.

The random number generator used in generating keys might not be totally secure. Check [implementation](https://docs.rs/rand/0.8.5/rand/rngs/struct.OsRng.html)

## Features

- XOR encryption & decryption
- RSA encryption & decryption
- AES encryption & decryption
- SHA1
- SHA224, SHA256, SHA384, SHA512, SHA512/244, SHA512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256
- Ed25519 signing & verifying
- BLAKE2B, BLAKE2S, BLAKE2-224, BLAKE2-256, BLAKE2-384, BLAKE2-512
- Block Cypher trait with different modes such as
  - ECB
  - CBC
  - PCBC
  - CFB

## Future

I am planning on implementing

- Photon
- Argon2
- Diffie-Heilman

I am doing this on the side of my studying so new updates and implementations might take a while

Pull requests open :D
