# Concat KDF

A [Go](https://go.dev) (Golang for search engines) standalone implementation of NIST's [SP 800-56C](https://csrc.nist.gov/pubs/sp/800/56/c/r1/final) single-step Key Derivation Function, also known as Concatenation KDF.

## How to use it?

This library implements the same general format of Go's standard library [hkdf](https://pkg.go.dev/crypto/hkdf) and [pbkdf2](https://pkg.go.dev/crypto/pbkdf2) functions.

To use it, simply provide a hash returning function, along with the secret keying material and other info:

```go
key, err := concatkdf.Key(sha256.New, secretMaterial, info, keyLen)
if err != nil {
  // ...
}
```

For HMAC variations, provide an anonymous function pre-initializing the HMAC block with the desired algorithm and salt:
```go
key, err := concatkdf.Key(func() hash.Hash { return hmac.New(sha256.New, salt) }, secretMaterial, info, keyLen)
if err != nil {
  // ...
}
```


## Supported algorithms

  > ⚠️ Beware using untested algorithms ⚠️
  >
  > There may be edge cases still not properly treated or tested, specially when entering KMAC territory.

This implementation should theoretically work with any algorithm that implements Go's standard hash.Hash interface. However, only the following algorithms have been tested (shout out to @patrickfav for sharing the test vectors for these with the community):

- SHA-1
- SHA-256
- SHA-512
- HMAC with SHA-256
- HMAC with SHA-512

## Special Thanks

Special thanks go to the people below:

- @patrickfav for sharing with the community test vectors for some of the covered algorithms, as well as for their [Java implementation](https://github.com/patrickfav/singlestep-kdf), which served as reference for some of this Go implementation
- the Python's [cryptography library](https://github.com/pyca/cryptography) team, whose work also served as reference for this implementation

## Contributing

Contributions are welcome! Feel free to submit a Pull Request with new features and/or bugfixes.