package ssh

import (
	"bytes"
	"fmt"
	"io"
)

var opensshPrivateKeyPrefix = bytes.Join([][]byte{
	[]byte("openssh-key-v1"), []byte{0},
	// cipher "none", kdf "none"
	SerializeString("none"), SerializeString("none"),
	SerializeUint32(0), SerializeUint32(1), // empty kdf, and #keys = 1
}, nil)

var opensshPrivateKeyPadding = []byte{1, 2, 3, 4, 5, 6, 7}

// Reads the inner private key data, i.e., the section that is
// potentially encrypted (although we currently handle only
// unencrypted key files). On success returns the concatenation of the
// private key and the public key, which is compatible with
// crypto.ed25519.PrivateKey.
func readEd25519PrivateKeyInner(r io.Reader, publicKeyBlob []byte) ([]byte, error) {
	pub, err := parseBytes(publicKeyBlob, nil, ReadEd25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, pubkey invalid: %w", err)
	}

	n1, err := ReadUint32(r)
	if err != nil {
		return nil, err
	}
	n2, err := ReadUint32(r)
	if err != nil {
		return nil, err
	}

	if n1 != n2 {
		return nil, fmt.Errorf("invalid private key, bad nonce")
	}

	if err := readSkip(r, publicKeyBlob); err != nil {
		return nil, fmt.Errorf("invalid private key, inconsistent public key: %v", err)
	}
	keys, err := ReadString(r, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, private key missing: %v", err)
	}
	// The keys blob consists of the 32-byte private key +
	// 32 byte public key.
	if len(keys) != 64 {
		return nil, fmt.Errorf("unexpected private key size: %d", len(keys))
	}
	if !bytes.Equal(pub[:], keys[32:]) {
		return nil, fmt.Errorf("inconsistent public key")
	}
	_, err = ReadString(r, 100)
	if err != nil {
		return nil, fmt.Errorf("comment string missing")
	}
	return keys, nil
}

// Reads a binary private key file, i.e., after PEM decapsulation. On
// success returns the concatenation of the private key and the public
// key, which is compatible with crypto.ed25519.PrivateKey.
func readEd25519PrivateKey(r io.Reader) ([]byte, error) {
	if err := readSkip(r, opensshPrivateKeyPrefix); err != nil {
		return nil, fmt.Errorf("invalid or encrypted private key: %v", err)
	}
	publicKeyBlob, err := ReadString(r, 100)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, pubkey missing: %v", err)
	}
	privBlob, err := ReadString(r, 1000)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}
	if length := len(privBlob); length%8 != 0 {
		return nil, fmt.Errorf("invalid private key length: %d", length)
	}

	return parseBytes(privBlob, opensshPrivateKeyPadding,
		func(r io.Reader) ([]byte, error) {
			return readEd25519PrivateKeyInner(r, publicKeyBlob)
		})
}

// Deterministic variant with nonce input, for unit testing.
func serializeEd25519PrivateKey(priv, pub []byte, nonce [4]byte) []byte {
	if len(priv) != 32 {
		panic(fmt.Sprintf("Bad size %d for ed25519 private key", len(priv)))
	}
	pubBlob := SerializeEd25519PublicKey(pub)

	return bytes.Join([][]byte{
		// Prefix + first copy of public key
		opensshPrivateKeyPrefix, SerializeString(pubBlob),

		// Followed by the data that could be encrypted, but isn't in our case.
		// Length of below data.
		SerializeUint32(136),

		// Size of above is
		//   8 (nonce)
		//  51 (public part)
		//  68 (private part)
		//   4 (comment)
		//   5 (padding)
		// ----
		// 136 (sum)

		// Add nonce twice, presumably to check for correct decryption
		nonce[:], nonce[:],

		// Private key is public key + additional private parameters.
		pubBlob,

		// Finally, the ssh secret key, which includes the raw public
		// key once more.
		SerializeUint32(64), // Length of private + public key
		priv[:],
		pub[:],
		// Empty comment.
		SerializeUint32(0),
		// Padding
		[]byte{1, 2, 3, 4, 5},
	}, nil)
}
