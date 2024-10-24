package ssh

import (
	// "bytes"
	// "crypto/rand"
	// "encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	// "io"
)

// Ascii key formats

const pemPrivateKeyTag = "OPENSSH PRIVATE KEY"

var NoPEMError = errors.New("not a PEM file")

// Parses an openssh PEM-formatted private key.
func ParseAsciiEd25519PrivateKey(ascii []byte) ([]byte, error) {
	block, _ := pem.Decode(ascii)
	if block == nil {
		return nil, NoPEMError
	}
	if block.Type != pemPrivateKeyTag {
		return nil, fmt.Errorf("unexpected PEM tag: %q", block.Type)
	}
	return parseBytes(block.Bytes, nil, readEd25519PrivateKey)
}
