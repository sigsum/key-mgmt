package agent

// Based on sigsum-go/internal/ssh/private.go

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
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

// Skips prefix, if present, otherwise return nil.
func skipPrefix(buffer []byte, prefix []byte) []byte {
	if !bytes.HasPrefix(buffer, prefix) {
		return nil
	}
	return buffer[len(prefix):]
}

func parseUint32(buffer []byte) (uint32, []byte) {
	if buffer == nil || len(buffer) < 4 {
		return 0, nil
	}
	return binary.BigEndian.Uint32(buffer[:4]), buffer[4:]
}

func parseString(buffer []byte) ([]byte, []byte) {
	length, buffer := parseUint32(buffer)
	if buffer == nil {
		return nil, nil
	}
	if int64(len(buffer)) < int64(length) {
		return nil, nil
	}
	return buffer[:int(length)], buffer[int(length):]
}

func parsePublicEd25519(blob []byte) ([]byte, error) {
	pub := skipPrefix(blob, bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeUint32(ed25519.PublicKeySize),
	}, nil))

	if pub == nil {
		return nil, fmt.Errorf("invalid public key blob prefix")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %v", len(blob))
	}
	return pub, nil
}

func ParsePrivateKey(ascii []byte) (crypto.Signer, error) {
	parseBlob := func(blob []byte) (crypto.Signer, error) {
		blob = skipPrefix(blob, opensshPrivateKeyPrefix)
		if blob == nil {
			return nil, fmt.Errorf("invalid or encrypted private key")
		}
		publicKeyBlob, blob := parseString(blob)
		if blob == nil {
			return nil, fmt.Errorf("invalid private key, pubkey missing")
		}
		pub, err := parsePublicEd25519(publicKeyBlob)
		if err != nil {
			return nil, fmt.Errorf("invalid private key, pubkey invalid: %w", err)
		}
		length, blob := parseUint32(blob)
		if blob == nil || int64(length) != int64(len(blob)) ||
			length%8 != 0 {
			return nil, fmt.Errorf("invalid private key")
		}
		n1, blob := parseUint32(blob)
		n2, blob := parseUint32(blob)
		if blob == nil || n1 != n2 {
			return nil, fmt.Errorf("invalid private key, bad nonce")
		}
		blob = skipPrefix(blob, publicKeyBlob)
		if blob == nil {
			return nil, fmt.Errorf("invalid private key, inconsistent public key")
		}
		keys, blob := parseString(blob)
		if blob == nil {
			return nil, fmt.Errorf("invalid private key, private key missing")
		}
		// The keys blob consists of the 32-byte private key +
		// 32 byte public key.
		if len(keys) != 64 {
			return nil, fmt.Errorf("unexpected private key size: %d", len(keys))
		}
		if !bytes.Equal(pub[:], keys[32:]) {
			return nil, fmt.Errorf("inconsistent public key")
		}
		return ed25519.PrivateKey(keys), nil
	}
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, NoPEMError
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return parseBlob(block.Bytes)
}

func ReadPrivateKeyFile(fileName string) (crypto.Signer, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	signer, err := ParsePrivateKey(contents)
	if err != nil {
		return nil, fmt.Errorf("parsing private key file %q failed: %v",
			fileName, err)
	}
	return signer, nil
}
