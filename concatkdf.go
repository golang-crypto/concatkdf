// Package concatkdf implements the Single-Step Key Derivation
// Function (Concatenation KDF) as specified in NIST SP 800-56C.
//
// ConcatKDF is a cryptographic key derivation function (KDF) with
// the goal of deriving a strong secret key from the secret keying
// material obtained through a key agreement process.
package concatkdf

import (
	"encoding/binary"
	"hash"
)

// Key derives a key from the given hash, secret and context info, returning a []byte
// of length keyLength that can be used as cryptographic key.
//
// A salt may be provided through a function pre-initializing the hash block:
//
//	key, err := concatkdf.Key(func() hash.Hash { return hmac.New(sha256.New, salt) }, secretMaterial, info, keyLen)
//	if err != nil {
//		// ...
//	}
func Key[Hash hash.Hash](h func() Hash, secret []byte, info string, keyLength int) ([]byte, error) {
	out := make([]byte, 0, keyLength)
	hasher := h()

	for counter := uint32(1); len(out) < keyLength; counter++ {
		hasher.Reset()
		binary.Write(hasher, binary.BigEndian, counter)
		hasher.Write(secret)
		hasher.Write([]byte(info))

		out = hasher.Sum(out)
	}

	return out[:keyLength], nil
}
