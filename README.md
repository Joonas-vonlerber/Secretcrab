# Secretcrab

A cryptographic suite made in pure Rust. Includes implementations for the SHA-family of hash functions.
Also includes encryption algorithms like RSA or AES.

## Implementation security

I cannot verify the security of the implentations :DD For secure purposes i recommend using the official implenetations whenever possible.

The random number generator used in generating keys might not be totally secure.

## Features

- XOR encryption & decryption
- RSA encryption & decryption
- AES encryption & decryption
- SHA1
- SHA244, SHA256, SHA384, SHA512, SHA512/244, SHA512/256
- SHA3-244, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256

## Future

I am planning on implementing

- EdDSA (currently working on this one. Should be done this year (2023)?? Doubt :DD)
- Diffie-Heilman
- Argon2

I am also studying so new updates and implentations might take a while

Pull requests open :D
