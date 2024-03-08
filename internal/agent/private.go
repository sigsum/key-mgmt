package agent

// Based on sigsum-go/internal/ssh/private.go

import (
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"sigsum.org/key-mgmt/pkg/ssh"
)

// For documentation of the openssh private key format, see
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
// https://coolaj86.com/articles/the-openssh-private-key-format
//
// This implementation supports only unencrypted ed25519 keys.

const pemPrivateKeyTag = "OPENSSH PRIVATE KEY"

var NoPEMError = errors.New("not a PEM file")

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
	keys, err := ssh.ParseBytes(block.Bytes, nil, ssh.ReadEd25519PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key file %q failed: %v",
			fileName, err)
	}

	return ed25519.PrivateKey(keys), nil
}
