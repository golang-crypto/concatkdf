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
