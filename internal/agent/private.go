package agent

// Based on sigsum-go/internal/ssh/private.go

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// For documentation of the openssh private key format, see
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
// https://coolaj86.com/articles/the-openssh-private-key-format
//
// This implementation supports only unencrypted ed25519 keys.

const pemPrivateKeyTag = "OPENSSH PRIVATE KEY"

var NoPEMError = errors.New("not a PEM file")

var opensshPrivateKeyPrefix = bytes.Join([][]byte{
	[]byte("openssh-key-v1"), []byte{0},
	// cipher "none", kdf "none"
	serializeString("none"), serializeString("none"),
	serializeUint32(0), serializeUint32(1), // empty kdf, and #keys = 1
}, nil)

var opensshPrivateKeyPadding = []byte{1, 2, 3, 4, 5, 6, 7}

func readPublicEd25519(r io.Reader) ([]byte, error) {
	if err := readSkip(r, bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeUint32(ed25519.PublicKeySize),
	}, nil)); err != nil {
		return nil, fmt.Errorf("invalid public key blob prefix: %v", err)
	}
	return readBytes(r, ed25519.PublicKeySize)
}

// Reads the inner private key data, i.e., the section that is
// potentially encrypted (although we handle only unencrypted key
// files).
func readPrivateKeyInner(r io.Reader, publicKeyBlob []byte) (crypto.Signer, error) {
	pub, err := parseBytes(publicKeyBlob, nil, readPublicEd25519)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, pubkey invalid: %w", err)
	}

	n1, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	n2, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	if n1 != n2 {
		return nil, fmt.Errorf("invalid private key, bad nonce")
	}

	if err := readSkip(r, publicKeyBlob); err != nil {
		return nil, fmt.Errorf("invalid private key, inconsistent public key: %v", err)
	}
	keys, err := readString(r, 64)
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
	_, err = readString(r, 100)
	if err != nil {
		return nil, fmt.Errorf("comment string missing")
	}
	return ed25519.PrivateKey(keys), nil
}

// Reads a binary private key file, i.e., after PEM decapsulation.
func readPrivateKey(r io.Reader) (crypto.Signer, error) {
	if err := readSkip(r, opensshPrivateKeyPrefix); err != nil {
		return nil, fmt.Errorf("invalid or encrypted private key: %v", err)
	}
	publicKeyBlob, err := readString(r, 100)
	if err != nil {
		return nil, fmt.Errorf("invalid private key, pubkey missing: %v", err)
	}
	privBlob, err := readString(r, 1000)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}
	if length := len(privBlob); length%8 != 0 {
		return nil, fmt.Errorf("invalid private key length: %d", length)
	}

	return parseBytes(privBlob, opensshPrivateKeyPadding,
		func(r io.Reader) (crypto.Signer, error) {
			return readPrivateKeyInner(r, publicKeyBlob)
		})
}

// Reads an ASCII format private key. Supports only the case of a
// single unencrypted key.
func ReadPrivateKeyFile(fileName string) (crypto.Signer, error) {
	ascii, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, NoPEMError
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	signer, err := parseBytes(block.Bytes, nil, readPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key file %q failed: %v",
			fileName, err)
	}

	return signer, nil
}
